//! `fz import supabase users` (issue #659, step 2 of ADR 0026): moves a
//! Supabase project's `auth.users` into a running venture's `auth-core`
//! over the same admin import `fz auth import` uses (its `send_batch`, so
//! there is one HTTP path), then records the source-to-account mapping the
//! data step rewrites references through. `cratefield-import-supabase`'s
//! `read_users` is the engine; the CLI flags are documented in `lib.rs`.
//!
//! Without `--apply` nothing is written: the server validates every user
//! and reports a verdict, and no mapping row is recorded. `--apply` writes
//! both and needs `--map-db-url-env`. Progress and the summary go to
//! stderr; the JSON report (stdout, or `--report`) holds the counts, the
//! skipped and unmapped ids and the server's verdict — never an email, a
//! hash, a token or a credentialed URL.
//!
//! Exit code: non-zero only when the run cannot finish — a refused input, a
//! failed read, batch or mapping write, or drift in the mapping table. A
//! run that completes reporting `conflict` or `invalid` exits zero, like
//! `fz auth import`: those are the server having answered, and the counts
//! print either way.

use std::path::PathBuf;

/// Everything `fz import supabase users` was given. The field docs are the
/// clap help, in `lib.rs`.
pub struct UsersArgs {
    pub db_url: Option<String>,
    pub target: String,
    pub admin_token_env: String,
    /// Required with `--apply`.
    pub map_db_url_env: Option<String>,
    pub oidc_providers: Vec<String>,
    pub batch_size: usize,
    pub merge_by_email: bool,
    /// `--apply`: write. Absent, the run is a dry run.
    pub apply: bool,
    /// Where the JSON report goes. Defaults to stdout.
    pub report: Option<PathBuf>,
}

#[cfg(feature = "import-supabase")]
mod imp {
    use std::collections::{BTreeMap, BTreeSet};

    use serde::Serialize;
    use serde_json::Value;

    use crate::EnvVars;
    use crate::auth_import::{self, ResultRow};
    use crate::import::source_db_url;
    use cratefield_core::Config as _;
    use cratefield_import_supabase as engine;

    use super::UsersArgs;

    /// The statuses the summary prints, in order.
    const STATUSES: [&str; 5] = ["created", "unchanged", "merged", "conflict", "invalid"];

    /// The statuses whose row names the account the import created for the
    /// user, so a mapping row is recorded for them.
    const MAPPED_STATUSES: [&str; 3] = ["created", "unchanged", "merged"];

    /// The JSON report. `skipped`, `unmapped`, `mapping` and `results` are
    /// the engine's and the server's own shapes, so they are not restated;
    /// none of them names an email or a hash.
    #[derive(Debug, Serialize)]
    struct Report {
        dry_run: bool,
        counts: BTreeMap<String, usize>,
        mapping: engine::MappingCounts,
        skipped: Vec<engine::SkippedUser>,
        unmapped: Vec<engine::UnmappedProvider>,
        results: Vec<ResultRow>,
    }

    /// `fz import supabase users`: read, send, map, report.
    ///
    /// # Errors
    ///
    /// A refused input (a URL, a token, an out-of-range `--batch-size`, a
    /// missing variable), any read or batch that fails, a mapping write
    /// that drifts, or a report that cannot be written.
    pub fn run(args: &UsersArgs) -> Result<(), String> {
        if args.batch_size == 0 || args.batch_size > auth_import::MAX_BATCH_SIZE {
            return Err(format!(
                "--batch-size must be between 1 and {}, got {}",
                auth_import::MAX_BATCH_SIZE,
                args.batch_size
            ));
        }
        let (db_url, note) = source_db_url(args.db_url.as_deref(), &EnvVars)?;
        if let Some(note) = note {
            eprintln!("{note}");
        }
        let admin_token = EnvVars.get(&args.admin_token_env).ok_or_else(|| {
            format!(
                "the environment variable `{}` is not set or is empty (it must hold the \
                 auth-core admin token — the value the venture has as `ADMIN_TOKEN`)",
                args.admin_token_env
            )
        })?;
        let map_url = if args.apply {
            let name = args.map_db_url_env.as_deref().ok_or_else(|| {
                "--apply needs --map-db-url-env naming the environment variable that holds the \
                 *target* database URL (the harness Postgres, where `import_supabase_users` \
                 lives)"
                    .to_owned()
            })?;
            let url = EnvVars.get(name).ok_or_else(|| {
                format!(
                    "the environment variable `{name}` is not set or is empty (it must hold the \
                     *target* database URL — the harness Postgres, where `import_supabase_users` \
                     lives)"
                )
            })?;
            Some(engine::Secret::new(url))
        } else {
            None
        };

        let options = engine::UsersOptions {
            db_url: engine::Secret::new(db_url.expose()),
            batch_size: args.batch_size,
            oidc_providers: args.oidc_providers.iter().cloned().collect::<BTreeSet<_>>(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("cannot start the async runtime this import needs: {err}"))?;
        runtime.block_on(transfer(args, &options, &admin_token, map_url.as_ref()))
    }

    /// Reads the plan, sends every batch, records the mapping and writes
    /// the report.
    async fn transfer(
        args: &UsersArgs,
        options: &engine::UsersOptions,
        admin_token: &str,
        map_url: Option<&engine::Secret>,
    ) -> Result<(), String> {
        let (http, _clock) = auth_import::native_stack();
        let plan = engine::read_users(options)
            .await
            .map_err(|error| error.to_string())?;
        // Each record rides with the metadata read alongside it, both in id
        // order, so a result row pairs with its user by position: the server
        // answers one verdict per user in request order.
        let users: Vec<(&engine::ImportRecord, &engine::UserMetadata)> = plan.users().collect();
        let url = auth_import::import_url(&args.target);
        let dry_run = !args.apply;
        let total = users.len();
        let mut results: Vec<ResultRow> = Vec::with_capacity(total);
        let mut mapped: Vec<engine::MappedUser> = Vec::new();
        for chunk in users.chunks(args.batch_size) {
            let body: Vec<Value> = chunk
                .iter()
                .map(|(record, _)| serde_json::to_value(record))
                .collect::<Result<_, _>>()
                .map_err(|error| format!("cannot encode a user record: {error}"))?;
            let rows = auth_import::send_batch(
                &http,
                &url,
                admin_token,
                args.merge_by_email,
                dry_run,
                &body,
            )
            .await?;
            for (row, (_, metadata)) in rows.iter().zip(chunk) {
                if MAPPED_STATUSES.contains(&row.status.as_str())
                    && let Some(sub) = row.sub.as_deref()
                {
                    mapped.push(metadata.mapping(sub));
                }
            }
            results.extend(rows);
            print_progress(results.len(), total, &results);
        }

        let mapping = match map_url {
            Some(url) if !mapped.is_empty() => {
                let mut conn = engine::connect_mapping(url)
                    .await
                    .map_err(|error| error.to_string())?;
                engine::record_mapping(&mut conn, url, &mapped)
                    .await
                    .map_err(|error| error.to_string())?
            }
            _ => engine::MappingCounts::default(),
        };

        let report = Report {
            dry_run,
            counts: counts_by_status(&results),
            mapping,
            skipped: plan.skipped,
            unmapped: plan.unmapped,
            results,
        };
        let json = serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot encode the report: {error}"))?;
        match &args.report {
            Some(path) => std::fs::write(path, json)
                .map_err(|error| format!("cannot write {}: {error}", path.display()))?,
            None => println!("{json}"),
        }
        print_summary(&report, total, args.apply);
        Ok(())
    }

    /// How many results carry each status. Every status is present, zero
    /// included, so a status that never appeared is visibly a zero.
    fn counts_by_status(results: &[ResultRow]) -> BTreeMap<String, usize> {
        let mut counts: BTreeMap<String, usize> =
            STATUSES.iter().map(|s| ((*s).to_owned(), 0)).collect();
        for row in results {
            *counts.entry(row.status.clone()).or_default() += 1;
        }
        counts
    }

    fn count(counts: &BTreeMap<String, usize>, status: &str) -> usize {
        counts.get(status).copied().unwrap_or(0)
    }

    /// One line per batch, on stderr: `users: 500/1234 sent (created 480,
    /// unchanged 20, merged 0, conflict 0, invalid 0)`. Counts are
    /// cumulative, so the last line is the run.
    fn print_progress(sent: usize, total: usize, results: &[ResultRow]) {
        let counts = counts_by_status(results);
        eprintln!(
            "users: {sent}/{total} sent (created {}, unchanged {}, merged {}, conflict {}, invalid \
             {})",
            count(&counts, "created"),
            count(&counts, "unchanged"),
            count(&counts, "merged"),
            count(&counts, "conflict"),
            count(&counts, "invalid"),
        );
    }

    /// The human summary, on stderr (stdout is the JSON report).
    fn print_summary(report: &Report, total: usize, apply: bool) {
        if report.dry_run {
            eprintln!(
                "fz import supabase users: dry run — the server validated {total} user(s) and \
                 wrote nothing; pass --apply to import"
            );
        } else {
            eprintln!("fz import supabase users: imported {total} user(s)");
        }
        for status in STATUSES {
            eprintln!("  {status}: {}", count(&report.counts, status));
        }
        if apply {
            eprintln!(
                "  mapping inserted: {}, unchanged: {}",
                report.mapping.inserted, report.mapping.unchanged
            );
        }
        if !report.skipped.is_empty() {
            let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
            for user in &report.skipped {
                *reasons.entry(user.reason.as_str()).or_default() += 1;
            }
            let reasons: Vec<String> = reasons.iter().map(|(r, n)| format!("{r} {n}")).collect();
            eprintln!(
                "  skipped: {} ({})",
                report.skipped.len(),
                reasons.join(", ")
            );
        }
        if !report.unmapped.is_empty() {
            let providers: Vec<String> = report
                .unmapped
                .iter()
                .map(|p| format!("{} ({})", p.provider, p.supabase_ids.len()))
                .collect();
            eprintln!(
                "  unmapped: {} — these users can sign in with a magic link",
                providers.join(", ")
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_report_carries_counts_skips_and_unmapped_but_no_email_or_hash() {
            let email = "ada@example.test";
            let hash = "$2b$12$abcdefghijklmnopqrstuuOJ4f0Zf1rSYx2Zl8pQ1fSl8sQf2aZ1u";
            let plan = engine::ImportPlan {
                records: vec![engine::ImportRecord {
                    external_provider: engine::EXTERNAL_PROVIDER,
                    external_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                    email: email.to_owned(),
                    email_verified: true,
                    password_hash: Some(engine::Secret::new(hash)),
                    created_at: None,
                    identities: vec![engine::ImportIdentity {
                        provider: "google".to_owned(),
                        subject: "sub-1".to_owned(),
                    }],
                }],
                metadata: Vec::new(),
                skipped: vec![engine::SkippedUser {
                    supabase_id: "00000000-0000-4000-8000-000000000002".to_owned(),
                    reason: engine::SkipReason::NoEmail,
                }],
                unmapped: vec![engine::UnmappedProvider {
                    provider: "github".to_owned(),
                    supabase_ids: vec!["00000000-0000-4000-8000-000000000003".to_owned()],
                }],
            };
            let results = vec![ResultRow {
                external_provider: "supabase".to_owned(),
                external_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                status: "created".to_owned(),
                sub: Some("sub-1".to_owned()),
                reason: None,
            }];
            let report = Report {
                dry_run: false,
                counts: counts_by_status(&results),
                mapping: engine::MappingCounts::default(),
                skipped: plan.skipped,
                unmapped: plan.unmapped,
                results,
            };
            let json = serde_json::to_string(&report).expect("serializes");

            assert!(!json.contains(email), "the report carries no email: {json}");
            assert!(!json.contains(hash), "the report carries no hash: {json}");
            assert!(!json.contains("password_hash"), "{json}");
            // The skipped id and its reason, and the unmapped provider, are
            // exactly what the operator acts on.
            assert!(json.contains("no-email"), "{json}");
            assert!(json.contains("github"), "{json}");
            assert_eq!(count(&report.counts, "created"), 1);
            assert_eq!(count(&report.counts, "conflict"), 0);
        }
    }
}

#[cfg(feature = "import-supabase")]
pub use imp::run;

/// The refusal an `fz` without the feature prints: one line naming the
/// install, mirroring `import::inspect`'s.
///
/// # Errors
///
/// Always: this build has no `import-supabase` feature, so it cannot reach
/// Postgres or the network.
#[cfg(not(feature = "import-supabase"))]
pub fn run(_args: &UsersArgs) -> Result<(), String> {
    Err(
        "this `fz` was built without the `import-supabase` feature, so it cannot move auth \
         users. Install one that has it — `cargo install cratefield-cli --features \
         import-supabase` — and run that binary (it needs no compiled-in harness)."
            .to_owned(),
    )
}
