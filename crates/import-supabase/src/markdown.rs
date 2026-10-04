//! The human rendering of a [`Report`]. The JSON is the source of truth
//! (ADR 0026, Decision 6); this is rendered from it and carries nothing it
//! does not.

use std::fmt::Write as _;

use crate::report::{Classification, Finding, Report, SourceStatus};

/// `1.5 MiB`, `812 B`.
#[must_use]
pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024 * 10 && unit < UNITS.len() - 1 {
        value /= 1024;
        unit += 1;
    }
    if unit == 0 && bytes >= 1024 {
        // One decimal for small KiB values.
        #[allow(clippy::cast_precision_loss)]
        return format!("{:.1} KiB", bytes as f64 / 1024.0);
    }
    format!("{value} {}", UNITS[unit])
}

fn duration(seconds: u64) -> String {
    match seconds {
        0..60 => format!("{seconds} s"),
        60..3600 => format!("{} min", seconds.div_ceil(60)),
        _ => format!("{:.1} h", seconds_to_hours(seconds)),
    }
}

#[allow(clippy::cast_precision_loss)]
fn seconds_to_hours(seconds: u64) -> f64 {
    seconds as f64 / 3600.0
}

/// One table cell: no pipes, no newlines.
fn cell(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
}

fn code(text: &str) -> String {
    let text = cell(text);
    if text.contains('`') {
        format!("`` {text} ``")
    } else {
        format!("`{text}`")
    }
}

fn status(status: SourceStatus) -> &'static str {
    match status {
        SourceStatus::Inspected => "inspected",
        SourceStatus::NotInspected => "not inspected",
        SourceStatus::Failed => "failed (see warnings)",
    }
}

fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn findings_table(out: &mut String, findings: &[&Finding], with_equivalent: bool) {
    if with_equivalent {
        out.push_str(
            "| Kind | Object | Phase | Why | Cratefield equivalent |\n|---|---|---|---|---|\n",
        );
    } else {
        out.push_str("| Kind | Object | Phase | Why |\n|---|---|---|---|\n");
    }
    for finding in findings {
        let _ = write!(
            out,
            "| {} | {} | {} | {}",
            finding.kind,
            code(&finding.object),
            finding.phase,
            cell(&finding.reason)
        );
        if with_equivalent {
            let _ = write!(out, " | {}", cell(&finding.cratefield_equivalent));
        }
        out.push_str(" |\n");
    }
    out.push('\n');
}

impl Report {
    /// The report as Markdown.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one block per section, in order
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let s = &self.summary;
        let _ = writeln!(
            out,
            "# Supabase migration report: `{}`\n\nSource `{}:{}/{}`, PostgreSQL {}. Report \
             version {}, written by {} {}. Read-only: nothing was written to the project.\n",
            self.project.project_ref,
            self.project.host,
            self.project.port,
            self.project.database,
            self.project.server_version,
            self.report_version,
            self.tool.name,
            self.tool.version,
        );

        out.push_str("## Summary\n\n");
        let _ = writeln!(
            out,
            "| | |\n|---|---|\n| Ready (no blockers) | **{}** |\n| Automatic | {} |\n| Needs \
             work | {} |\n| Blockers | {} |\n| Decided | {} |\n| Undecided | {} |\n| Tables | {} \
             (~{} rows) |\n| Data | {} (plus {} of \
             indexes, rebuilt on the target) |\n| Storage | {} objects, {} |\n| Estimated \
             transfer | about {} at {} Mbit/s (data and storage only; index builds and \
             verification are extra) |\n",
            yes(s.ready),
            s.automatic,
            s.needs_work,
            s.blockers,
            s.decided,
            s.undecided,
            s.tables,
            s.estimated_rows,
            human_bytes(s.data_bytes),
            human_bytes(s.index_bytes),
            s.storage_objects,
            human_bytes(s.storage_bytes),
            duration(s.estimated_transfer_seconds),
            s.transfer_assumed_mbps,
        );

        let r = &self.read_only;
        let _ = writeln!(
            out,
            "**Read-only evidence:** read-only transaction {}, read-only session {}, no \
             transaction id assigned {}; role `{}` (superuser {}, holds write privileges {}).\n",
            yes(r.transaction_read_only),
            yes(r.session_read_only),
            yes(r.no_transaction_id_assigned),
            r.role,
            yes(r.role_is_superuser),
            yes(r.role_can_write),
        );
        let _ = writeln!(
            out,
            "**Coverage:** database {}, Management API {}, policy classifier {}.\n",
            status(self.coverage.database),
            status(self.coverage.management_api),
            status(self.coverage.policy_classifier),
        );

        for (class, title, blurb, with_equivalent) in [
            (
                Classification::Blocker,
                "Blockers",
                "Each stops a later step until it is resolved.",
                true,
            ),
            (
                Classification::NeedsWork,
                "Needs work",
                "Moved or reported, but the venture writes or decides something. Each needs a \
                 `covered` or `waived` disposition before cutover.",
                true,
            ),
            (
                Classification::Automatic,
                "Automatic",
                "Moved by the importer with nothing to decide.",
                true,
            ),
        ] {
            let findings: Vec<&Finding> = self
                .findings
                .iter()
                .filter(|finding| finding.classification == class)
                .collect();
            let _ = writeln!(out, "## {title} ({})\n", findings.len());
            if findings.is_empty() {
                out.push_str("None.\n\n");
                continue;
            }
            let _ = writeln!(out, "{blurb}\n");
            findings_table(&mut out, &findings, with_equivalent);
        }

        let d = &self.dispositions;
        out.push_str("## Dispositions\n\n");
        if d.by_kind.is_empty() {
            out.push_str("Nothing needs a disposition.\n\n");
        } else {
            out.push_str(
                "Every needs-work item needs its own `covered` or `waived` entry (ADR 0026, \
                 Decision 5): `fz import supabase inspect --dispositions <FILE>`. Cutover \
                 refuses while `Undecided` is non-zero.\n\n| Kind | Covered | Waived | Undecided \
                 |\n|---|---|---|---|\n",
            );
            for kind in &d.by_kind {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} |",
                    kind.kind, kind.covered, kind.waived, kind.undecided
                );
            }
            out.push('\n');
            if !d.stale.is_empty() {
                out.push_str("**Stale entries** (they match no item that needs work):\n\n");
                for id in &d.stale {
                    let _ = writeln!(out, "- {}", code(id));
                }
                out.push('\n');
            }
        }

        let _ = writeln!(
            out,
            "## Row-level security ({} policies)\n",
            self.policies.len()
        );
        if self.policies.is_empty() {
            out.push_str("None.\n\n");
        } else {
            out.push_str(
                "RLS is neither copied nor translated (ADR 0026). The pattern and the suggested \
                 check are advice: a person writes the check, turns the policy's test stub (in \
                 the JSON report) into a passing test, and records the policy as covered or \
                 waived.\n\n| Table | Policy | Command | Roles | USING | WITH CHECK | Pattern \
                 | Confidence | Source | Suggested check |\n|---|---|---|---|---|---|---|---|---|---|\n",
            );
            for policy in &self.policies {
                let pattern = serde_json::to_value(policy.pattern)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default();
                let source = serde_json::to_value(policy.source)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "| `{}.{}` | {} | {} | {} | {} | {} | {}{} | {:.2} | {} | {} |",
                    policy.schema,
                    policy.table,
                    cell(&policy.name),
                    policy.command,
                    policy.roles.join(", "),
                    policy.using.as_deref().map_or_else(|| "—".to_owned(), code),
                    policy
                        .with_check
                        .as_deref()
                        .map_or_else(|| "—".to_owned(), code),
                    pattern,
                    policy
                        .classifier_label
                        .as_deref()
                        .map_or_else(String::new, |label| format!(" (classifier said {label})")),
                    policy.confidence,
                    source,
                    cell(&policy.suggested_equivalent),
                );
            }
            out.push('\n');
        }

        let _ = writeln!(out, "## Tables ({})\n", self.tables.len());
        if !self.tables.is_empty() {
            out.push_str(
                "| Table | Rows (est.) | Data | Indexes | RLS | Primary key |\n|---|---|---|---|---|---|\n",
            );
            for table in &self.tables {
                let _ = writeln!(
                    out,
                    "| `{}.{}` | {} | {} | {} | {} | {} |",
                    table.schema,
                    table.name,
                    table
                        .estimated_rows
                        .map_or_else(|| "not analyzed".to_owned(), |rows| rows.to_string()),
                    human_bytes(table.data_bytes),
                    human_bytes(table.index_bytes),
                    yes(table.rls_enabled),
                    if table.primary_key.is_empty() {
                        "none".to_owned()
                    } else {
                        table.primary_key.join(", ")
                    },
                );
            }
            out.push('\n');
        }

        let a = &self.auth;
        out.push_str("## Auth\n\n");
        if a.present {
            let _ = writeln!(
                out,
                "{} users ({} without a password, {} unconfirmed, {} anonymous); {} MFA factors; \
                 {} SSO providers.\n",
                a.users,
                a.users_without_password,
                a.users_unconfirmed,
                a.anonymous_users,
                a.mfa_factors,
                a.sso_providers
            );
            if !a.identities_by_provider.is_empty() {
                let providers: Vec<String> = a
                    .identities_by_provider
                    .iter()
                    .map(|count| format!("{} ({})", count.provider, count.identities))
                    .collect();
                let _ = writeln!(out, "Identities by provider: {}.\n", providers.join(", "));
            }
            match &a.enabled_providers {
                Some(enabled) => {
                    let _ = writeln!(
                        out,
                        "Enabled in the auth configuration: {}; MFA: {}.\n",
                        if enabled.is_empty() {
                            "none".to_owned()
                        } else {
                            enabled.join(", ")
                        },
                        a.enabled_mfa
                            .as_ref()
                            .filter(|mfa| !mfa.is_empty())
                            .map_or_else(|| "none".to_owned(), |mfa| mfa.join(", "))
                    );
                }
                None => out
                    .push_str("The auth configuration was not read (no Management API token).\n\n"),
            }
        } else {
            out.push_str("No `auth` schema.\n\n");
        }

        out.push_str("## Storage\n\n");
        if self.storage.buckets.is_empty() {
            out.push_str("No buckets.\n\n");
        } else {
            out.push_str(
                "| Bucket | Public | Objects | Size | Over 10 MiB |\n|---|---|---|---|---|\n",
            );
            for bucket in &self.storage.buckets {
                let _ = writeln!(
                    out,
                    "| `{}` | {} | {} | {} | {} |",
                    bucket.id,
                    yes(bucket.public),
                    bucket.objects,
                    human_bytes(bucket.bytes),
                    bucket.objects_over_blob_cap
                );
            }
            out.push('\n');
        }

        out.push_str("## Edge Functions\n\n");
        match self.edge_functions.status {
            SourceStatus::Inspected if self.edge_functions.functions.is_empty() => {
                out.push_str("None.\n\n");
            }
            SourceStatus::Inspected => {
                for function in &self.edge_functions.functions {
                    let _ = writeln!(out, "- `{}` ({})", function.slug, function.status);
                }
                out.push('\n');
            }
            _ => out.push_str(
                "Not inspected: unknown, not none. Pass a Management API token to list them.\n\n",
            ),
        }

        out.push_str("## Realtime and cron\n\n");
        if self.realtime.publications.is_empty() {
            out.push_str("No publications.\n");
        }
        for publication in &self.realtime.publications {
            let tables = if publication.all_tables {
                "all tables".to_owned()
            } else if publication.tables.is_empty() {
                "no tables".to_owned()
            } else {
                publication.tables.join(", ")
            };
            let _ = writeln!(out, "- Publication `{}`: {tables}.", publication.name);
        }
        for job in &self.cron_jobs {
            let _ = writeln!(out, "- Cron job `{}` on `{}`.", job.name, job.schedule);
        }
        out.push('\n');

        if !self.warnings.is_empty() {
            out.push_str("## Warnings\n\n");
            for warning in &self.warnings {
                let _ = writeln!(out, "- {warning}");
            }
            out.push('\n');
        }

        out.push_str(
            "## Next\n\nResolve the blockers, decide each needs-work item, then run the later \
             steps (docs/import/supabase.md): auth users, schema and data into `app`, storage \
             into R2, verify, cut over.\n",
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(human_bytes(812), "812 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(12 * 1024 * 1024), "12 MiB");
    }

    #[test]
    fn cells_cannot_break_the_table() {
        assert_eq!(cell("a | b\nc"), "a \\| b c");
    }
}
