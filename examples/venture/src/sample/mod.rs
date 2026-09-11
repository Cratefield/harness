//! Sample module for the venture example: one table, one write endpoint,
//! one read endpoint — the sea-query/D1 round-trip canary (issue #5).

use axum::extract::State;
use axum::routing::{get, post};
use cratefield::{
    Action, Audience, Clock, Config, ConfigError, DataKind, Disposition, IdGen, Json, Migrations,
    Module, ModuleContext, Outcome, PersonalDataSet, Port, Problem, Scope, SqlMigration, Statement,
    Surface, SystemClock, UlidIdGen, View,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub struct SampleRowModule;

const MIGRATION: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("migrations/sqlite/0001_init.sql"),
    transactional: true,
};

impl Module for SampleRowModule {
    fn name(&self) -> &'static str {
        "sample"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::HttpClient]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["sample_rows"]
    }

    /// The sample table holds an address, so it says so. A module that owns
    /// a table and declares nothing about it is outside export and erasure
    /// however plainly the schema reads (issue #244).
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[PersonalDataSet {
            table: "sample_rows",
            subject: "email",
            kind: DataKind::Contact,
            disposition: Disposition::Erase,
            description: "The address you typed into the sample form, with the date.",
            redacted: &[],
        }];
        SETS
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ctx);
        axum::Router::new()
            .route("/rows", post(insert_row).with_state(Arc::clone(&state)))
            .route(
                "/rows/latest",
                get(latest_row).with_state(Arc::clone(&state)),
            )
            .route(
                "/transport-probe",
                get(transport_probe).with_state(Arc::clone(&state)),
            )
    }

    /// The UI surface (ADR 0010): the insert as a public form, the read as
    /// a JSON action. `GET /__surface` lists both; the CI wrangler smoke
    /// asserts the document on a real Workers request.
    fn surface(&self) -> Surface {
        Surface::new()
            .action(
                Action::post("insert", "/rows")
                    .input::<InsertBody>()
                    .accepted("Row stored."),
            )
            .action(
                Action::get("latest", "/rows/latest")
                    .audience(Audience::Public)
                    .outcome(Outcome::Json),
            )
            .view(View::form("insert"))
            .view(View::status("latest"))
    }
}

#[derive(Deserialize, JsonSchema)]
struct InsertBody {
    #[schemars(extend("x-cf-label" = "Email", "x-cf-widget" = "email"))]
    email: String,
}

fn now_iso() -> String {
    SystemClock
        .now()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

async fn insert_row(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    Json(body): Json<InsertBody>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(db) = ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let id = match ctx.ports.id_gen.as_ref() {
        Some(id_gen) => id_gen.ulid(),
        None => UlidIdGen.ulid(),
    };
    let query = sea_query::Query::insert()
        .into_table(sea_query::Alias::new("sample_rows"))
        .columns([
            sea_query::Alias::new("id"),
            sea_query::Alias::new("email"),
            sea_query::Alias::new("created_at"),
        ])
        .values_panic([
            id.clone().into(),
            body.email.clone().into(),
            now_iso().into(),
        ])
        .to_owned();
    db.execute(&Statement::render(&query))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "sample insert failed");
            internal(&scope)
        })?;
    Ok(Json(json!({ "id": id })))
}

/// Two deliberately unreachable destinations, both carrying the same
/// credential-shaped path: APNs addresses a device *by* its request path,
/// so `/3/device/<token>` **is** the token.
///
/// Two, because workerd's failure messages are not one shape, and this
/// probe exists to prove the port does not depend on which it gets:
///
/// - `.invalid` is reserved by RFC 2606 and resolves nowhere. Under
///   `wrangler dev --local` that comes back as an opaque `internal error;
///   reference = …`, with no URL in it at all.
/// - The same target under a scheme `fetch` does not implement is refused
///   with `TypeError: Fetch API cannot load: <the whole URL>` — path and
///   query included. That is the message that actually carries the
///   credential, and so the one the CI assertion is written against.
const PROBE_TARGETS: [&str; 2] = [
    "https://unreachable.invalid/3/device/PROBEDEVICETOKEN0a1b2c3d4e5f",
    "ftp://unreachable.invalid/3/device/PROBEDEVICETOKEN0a1b2c3d4e5f",
];

/// The one place CI can watch a **real** `worker::Error` (issue #229).
///
/// The Cloudflare `HttpClient` port has to report a transport failure
/// without quoting the request URL, because on this harness that URL is
/// often the recipient's credential — and workerd is the only thing that
/// produces the error it has to do that to. A unit test can construct the
/// error type; it cannot produce workerd's own message. So the `wrangler
/// dev` smoke drives this route and asserts the answer names the origin
/// and never the path, which is the assertion that would have failed
/// before the port stopped stringifying `worker::Error` whole.
///
/// It takes no input at all: the destinations are constants, so this is
/// not a fetch anybody can point anywhere.
///
/// On the native runtime the same route answers with that runtime's own
/// refusal (it vets the destination before opening a socket), which is a
/// different sentence about the same rule.
async fn transport_probe(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(client) = ctx.ports.http.clone() else {
        return Err(internal(&scope));
    };
    let mut errors = Vec::with_capacity(PROBE_TARGETS.len());
    for target in PROBE_TARGETS {
        let Ok(request) = http::Request::get(target).body(bytes::Bytes::new()) else {
            return Err(internal(&scope));
        };
        errors.push(match client.send(request).await {
            // Nothing answers at `.invalid`. If something ever does, say
            // so rather than let a success read as the redaction working.
            Ok(response) => format!("unexpectedly answered: {}", response.status()),
            Err(err) => {
                // Logged for the native runtime, and answered for the
                // Worker one: a module's `tracing::error!` is dropped on
                // wasm32 (issue #107), so the response body is where CI
                // reads the message the port produced.
                tracing::error!(error = %err, "transport probe failed, as designed");
                err.to_string()
            }
        });
    }
    Ok(Json(json!({ "errors": errors })))
}

async fn latest_row(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(db) = ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let query = sea_query::Query::select()
        .columns([
            sea_query::Alias::new("id"),
            sea_query::Alias::new("email"),
            sea_query::Alias::new("created_at"),
        ])
        .from(sea_query::Alias::new("sample_rows"))
        .order_by(sea_query::Alias::new("created_at"), sea_query::Order::Desc)
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await.map_err(|err| {
        tracing::error!(error = %err, "sample select failed");
        internal(&scope)
    })?;
    match rows.first() {
        Some(row) => Ok(Json(json!({
            "id": row.get::<String>("id"),
            "email": row.get::<String>("email"),
            "created_at": row.get::<String>("created_at"),
        }))),
        None => Ok(Json(json!(null))),
    }
}
