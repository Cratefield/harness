//! `fz migrations apply` (issue #18): applies the harness's module
//! migrations directly to a Postgres database — the native counterpart of
//! `wrangler d1 migrations apply`. Requires building `fz` with
//! factory0-cli's `postgres` feature so sqlx and tokio stay out of the
//! default (wasm-safe) dependency graph.

use factory0_core::Harness;

/// Applies the harness's migrations to the database at `url`.
///
/// # Errors
///
/// A human-readable message when the dialect is unsupported, the binary
/// lacks the `postgres` feature, the server is unreachable, or a
/// migration fails.
pub fn apply(harness: &Harness, dialect: &str, url: &str) -> Result<(), String> {
    if dialect != "postgres" {
        return Err(format!(
            "dialect {dialect:?} is not supported for apply (only postgres, issue #18)"
        ));
    }
    #[cfg(not(feature = "postgres"))]
    {
        let _ = (harness, url);
        Err(
            "this fz binary was built without factory0-cli's `postgres` feature — \
             rebuild the fz bin with `--features factory0-cli/postgres` to apply \
             migrations to Postgres (sqlite/D1 migrations run through \
             `wrangler d1 migrations apply`)"
                .to_owned(),
        )
    }
    #[cfg(feature = "postgres")]
    apply_postgres(harness, url)
}

#[cfg(feature = "postgres")]
fn apply_postgres(harness: &Harness, url: &str) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the async runtime: {err}"))?;
    // The URL is never echoed: connection strings carry credentials.
    runtime.block_on(async {
        let db = factory0_adapter_postgres::Postgres::connect(url)
            .await
            .map_err(|err| format!("cannot connect (check --url): {err}"))?;
        db.apply_harness_migrations(harness)
            .await
            .map_err(|err| format!("migrations failed: {err}"))
    })
}
