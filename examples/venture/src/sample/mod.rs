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

const MIGRATION: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("migrations/sqlite/0001_init.sql"),
);

impl Module for SampleRowModule {
    fn name(&self) -> &'static str {
        "sample"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // The harness hands a module only the ports it declares, so the
        // blob-probe route is unreachable without `Port::Blob` here.
        &[Port::Db, Port::HttpClient, Port::Blob]
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
            subject_via: None,
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

    /// `sample.probe` is the emission the CI sidecar-forward check drives
    /// (issue #258). Declared here so `/__surface` and `fz doctor` can name
    /// it; nothing inside this venture subscribes to it, which is the
    /// point — its only audience is a sidecar mounted in configuration.
    fn emits(&self) -> &'static [&'static str] {
        &["sample.probe"]
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
            .route("/fetch-probe", get(fetch_probe).with_state(Arc::clone(&state)))
            .route("/blob-probe", get(blob_probe).with_state(Arc::clone(&state)))
            .route(
                "/sidecar-probe",
                get(sidecar_probe).with_state(Arc::clone(&state)),
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

/// The outbound half of the `HttpClient` port that `transport-probe`'s
/// failures deliberately leave unproven (issues #132, #229): a fetch that
/// **succeeds**, against a public destination whose body is stable text —
/// Cloudflare's `cdn-cgi/trace`, a few hundred bytes of `key=value` lines
/// including `h=<host>` and `colo=<airport>`. The route parses those two
/// lines out, so the wrangler smoke asserts the Worker actually received
/// and read the upstream body, not merely that some status came back.
///
/// A constant, like the failing probe's targets: this is not a fetch
/// anybody can point anywhere, and the answer is what the Worker observed.
async fn fetch_probe(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    const TARGET: &str = "https://www.cloudflare.com/cdn-cgi/trace";
    let Some(client) = ctx.ports.http.clone() else {
        return Err(internal(&scope));
    };
    let Ok(request) = http::Request::get(TARGET).body(bytes::Bytes::new()) else {
        return Err(internal(&scope));
    };
    let response = match client.send(request).await {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(error = %err, "fetch probe could not reach its target");
            return Err(internal(&scope));
        }
    };
    let status = response.status().as_u16();
    let body = String::from_utf8_lossy(response.body());
    let field = |name: &str| {
        body.lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap_or_default()
            .to_owned()
    };
    Ok(Json(json!({
        "status": status,
        "h": field("h="),
        "colo": field("colo="),
    })))
}

/// The Blob port against a real bucket: put, read back, verify, delete
/// (issues #105 acceptance, #132). The `wrangler dev` smoke is the only
/// place this adapter is exercised at all — `cargo test` never touches R2
/// — so this route is the whole of the proof that the configured binding
/// round-trips. The key carries the request id, so concurrent smoke runs
/// cannot collide; the harness scopes it under `sample/` ([`ScopedBlob`]
/// via the module port view), which is itself part of what this proves.
///
/// Like the other probes it requires nothing on the wire: the payload is
/// the route's own.
async fn blob_probe(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(blob) = ctx.ports.blob.clone() else {
        return Err(internal(&scope));
    };
    const PAYLOAD: &[u8] = b"venture-example blob round trip";
    const CONTENT_TYPE: &str = "text/plain; charset=utf-8";
    let key = format!("probe/{}", scope.request_id);

    blob.put(&key, PAYLOAD, CONTENT_TYPE).await.map_err(|err| {
        tracing::error!(error = %err, "blob probe put failed");
        internal(&scope)
    })?;
    let round_trip = async {
        let object = blob.get(&key).await.map_err(|err| err.to_string())?;
        let object = object.ok_or_else(|| "put then get found nothing".to_owned())?;
        if object.bytes != PAYLOAD {
            return Err("read-back bytes differ from what was put".to_owned());
        }
        if object.content_type != CONTENT_TYPE {
            return Err("read-back content type differs from what was put".to_owned());
        }
        blob.delete(&key)
            .await
            .map_err(|err| format!("delete failed: {err}"))?;
        Ok(())
    };
    if let Err(what) = round_trip.await {
        tracing::error!(what, "blob probe round trip failed");
        return Err(internal(&scope));
    }
    Ok(Json(json!({
        "round_trip": "ok",
        "key": key,
        "bytes": PAYLOAD.len(),
    })))
}

/// Emits `sample.probe` for the sidecar-forward check (issue #258). The
/// emission must answer immediately: the forward happens in this request's
/// `wait_until`, and the CI job asserts on the wall clock that a slow
/// subscriber behind the service binding does not drag this answer with it.
/// The request id rides in the payload so the sidecar's evidence endpoint
/// can prove *this* delivery arrived, not just any.
async fn sidecar_probe(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
) -> Json<serde_json::Value> {
    ctx.events.emit_in(
        &scope,
        "sample.probe",
        json!({ "request_id": scope.request_id.clone(), "at": now_iso() }),
    );
    Json(json!({ "emitted": "sample.probe", "request_id": scope.request_id }))
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
