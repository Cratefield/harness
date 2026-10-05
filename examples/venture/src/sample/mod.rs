//! Sample module for the venture example: one table, one write endpoint,
//! one read endpoint — the sea-query/D1 round-trip canary (issue #5).

use axum::extract::{Path, Query, State};
use axum::routing::{get, post, put};
use cratefield::{
    Action, Audience, Clock, Config, ConfigError, DataKind, Disposition, IdGen, Json, Migrations,
    Module, ModuleContext, Outcome, PartReceipt, PersonalDataSet, Port, Problem, RequestStream,
    ResponseStream, Scope, SqlMigration, Statement, StreamRoute, Surface, SystemClock, UlidIdGen,
    UploadId, View,
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
            .route(
                "/fetch-probe",
                get(fetch_probe).with_state(Arc::clone(&state)),
            )
            .route(
                "/blob-probe",
                get(blob_probe).with_state(Arc::clone(&state)),
            )
            .route(
                "/sidecar-probe",
                get(sidecar_probe).with_state(Arc::clone(&state)),
            )
            // The streaming half (issue #585): `/upload` reads its body in
            // chunks and never buffers it, `/download` answers with a
            // generated stream, and `/big-buffered` is the buffered
            // counter-example CI watches fail.
            .route("/upload", post(upload))
            .route("/download", get(download))
            .route("/big-buffered", get(big_buffered))
            // The large-object half (issue #586): a multipart upload in
            // three legs — create, upload each 40 MB part, complete — then a
            // streamed read back, and a delete. The 120 MB object is far
            // past the isolate's 128 MB memory, so the parts (not the whole
            // object) are what is ever resident.
            .route(
                "/blob-large/{key}/uploads",
                post(create_large_upload).with_state(Arc::clone(&state)),
            )
            .route(
                "/blob-large/{key}/uploads/{id}/parts/{n}",
                put(upload_large_part).with_state(Arc::clone(&state)),
            )
            .route(
                "/blob-large/{key}/uploads/{id}/complete",
                post(complete_large_upload).with_state(Arc::clone(&state)),
            )
            .route(
                "/blob-large/{key}",
                get(download_large)
                    .delete(delete_large)
                    .with_state(Arc::clone(&state)),
            )
    }

    /// `POST /upload` and `GET /download` are served in streaming mode
    /// (issue #585): the runtime hands each body in as a
    /// [`RequestStream`] and bridges a [`ResponseStream`] straight to the
    /// wire, so neither direction holds the whole body resident. The
    /// ceilings (64 MiB each) are this route's own — `content-length` over
    /// one is refused `413` before a byte is read.
    fn streaming_routes(&self) -> &'static [StreamRoute] {
        const ROUTES: &[StreamRoute] = &[
            StreamRoute::post("/upload", STREAM_CEILING),
            StreamRoute::get("/download", STREAM_CEILING),
            // The multipart part's body streams in (issue #586): 40 MB parts
            // need a route ceiling above that, and 64 MiB keeps the example
            // under Cloudflare's 100 MB request cap. The large GET streams
            // the object back out.
            StreamRoute::put(
                "/blob-large/{key}/uploads/{id}/parts/{n}",
                LARGE_PART_CEILING,
            ),
            StreamRoute::get("/blob-large/{key}", LARGE_PART_CEILING),
        ];
        ROUTES
    }

    /// The large-object ceiling the sample declares (issue #586): 256 MiB,
    /// so CI's 120 MB multipart upload passes and the harness's `ScopedBlob`
    /// enforces the bound on the streamed and multipart writes. Far below
    /// the harness-wide [`MAX_LARGE_BLOB_BYTES`](cratefield::MAX_LARGE_BLOB_BYTES).
    fn max_blob_object_bytes(&self) -> u64 {
        LARGE_BLOB_OBJECT_BYTES
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
    const PAYLOAD: &[u8] = b"venture-example blob round trip";
    const CONTENT_TYPE: &str = "text/plain; charset=utf-8";
    let Some(blob) = ctx.ports.blob.clone() else {
        return Err(internal(&scope));
    };
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

/// The streaming routes' own ceiling (issue #585): 64 MiB, far past the
/// 64 KiB buffered default, and the number CI's oversized-chunked test
/// crosses.
const STREAM_CEILING: usize = 64 * 1024 * 1024;

/// The `/download` chunk size: an isolate holds one of these at a time, so a
/// response many times the isolate's memory still streams.
const DOWNLOAD_CHUNK: usize = 64 * 1024;

/// Streams a `POST /upload` body through SHA-256 without buffering it (issue
/// #585): [`RequestStream::next_chunk`] hands over the route's chunks, the
/// hasher folds each as it arrives, and only the 32-byte digest is ever held
/// whole. The answer is what the caller can check against `sha256sum` of the
/// file it sent, so a dropped, reordered or short body cannot pass the CI
/// assertion.
///
/// A body over the route ceiling ends the stream with
/// [`StreamError::TooLarge`](cratefield::StreamError::TooLarge), which maps
/// to the same `413 request-too-large` every other route gives — and because
/// the handler returns there, nothing it would have done on success happens
/// after the refusal point. That no side effect can run after a mid-stream
/// refusal is proved directly in `cratefield_core::stream`'s own tests (the
/// stream fuses and its source is dropped), so this route carries no extra
/// state to make the point twice.
async fn upload(mut body: RequestStream) -> Result<Json<serde_json::Value>, Problem> {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    let mut bytes: u64 = 0;
    while let Some(chunk) = body.next_chunk().await {
        match chunk {
            Ok(chunk) => {
                hasher.update(&chunk);
                bytes += chunk.len() as u64;
            }
            // `TooLarge` becomes the route's `413`, `Transport` the generic
            // `500` — the core mapping, applied here so the client sees the
            // problem JSON rather than a bare isolate error.
            Err(err) => return Err(Problem::from(err)),
        }
    }
    let mut sha256 = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(sha256, "{byte:02x}");
    }
    Ok(Json(json!({ "bytes": bytes, "sha256": sha256 })))
}

#[derive(Deserialize)]
struct DownloadParams {
    /// How many bytes to generate; absent means none, and it is clamped to
    /// the route ceiling so the example cannot be asked to stream forever.
    bytes: Option<usize>,
}

/// Answers `GET /download?bytes=N` with a [`ResponseStream`] that generates
/// `N` zero bytes in 64 KiB chunks (issue #585): the runtime bridges it
/// straight to the wire, so nothing near `N` is ever resident, and the
/// deterministic content means CI can compare `curl | sha256sum` against
/// `head -c N /dev/zero | sha256sum`.
async fn download(Query(params): Query<DownloadParams>) -> ResponseStream {
    let total = params.bytes.unwrap_or(0).min(STREAM_CEILING);
    ResponseStream::new(ZeroChunks::new(total))
}

/// Yields a fixed count of zero bytes as 64 KiB chunks, holding at most one
/// chunk at a time. `Infallible` because generation cannot fail.
struct ZeroChunks {
    remaining: usize,
}

impl ZeroChunks {
    fn new(total: usize) -> Self {
        Self { remaining: total }
    }
}

impl futures_core::Stream for ZeroChunks {
    type Item = Result<Vec<u8>, std::convert::Infallible>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let n = this.remaining.min(DOWNLOAD_CHUNK);
        this.remaining -= n;
        std::task::Poll::Ready(Some(Ok(vec![0u8; n])))
    }
}

/// The counter-example: a route that is **not** declared streaming, trying to
/// answer with 2 MiB. `response_to_worker` still buffers every non-streaming
/// response under its 1 MiB `MAX_RESPONSE_BUFFER`, so this fails rather than
/// silently switching to a stream — which is the CI assertion.
async fn big_buffered() -> axum::response::Response {
    axum::response::Response::new(axum::body::Body::from(vec![0u8; 2 * 1024 * 1024]))
}

/// The largest object the sample's large-blob routes accept (issue #586):
/// 256 MiB. Declared through `max_blob_object_bytes`, so the harness's
/// `ScopedBlob` enforces it on the streamed and multipart writes; CI uploads
/// 120 MB through the multipart routes below.
const LARGE_BLOB_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

/// The large-blob routes' own streaming ceiling (issue #585): 64 MiB,
/// comfortably above the 40 MB parts CI sends and below Cloudflare's 100 MB
/// request cap.
const LARGE_PART_CEILING: usize = 64 * 1024 * 1024;

/// The content type every large-blob route stores and serves with.
const LARGE_CONTENT_TYPE: &str = "application/octet-stream";

/// Starts a multipart upload for `key` (issue #586), the first of the three
/// large-object legs, and answers the opaque upload id the part and complete
/// routes take. The blob port is scoped to `sample/`, so the key never
/// escapes the module.
async fn create_large_upload(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(blob) = ctx.ports.blob.clone() else {
        return Err(internal(&scope));
    };
    let upload_id = blob
        .create_multipart(&key, LARGE_CONTENT_TYPE)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "large blob create failed");
            internal(&scope)
        })?;
    Ok(Json(json!({ "upload_id": upload_id.as_str() })))
}

/// Uploads one part of a multipart upload (issue #586), its body streamed in
/// by the runtime (`RequestStream`) and handed straight to the port, which
/// buffers the part bounded by the route ceiling. Answers the part number
/// and the `ETag` the client must replay at complete.
async fn upload_large_part(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    Path((key, upload_id, part_number)): Path<(String, String, u16)>,
    body: RequestStream,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(blob) = ctx.ports.blob.clone() else {
        return Err(internal(&scope));
    };
    let receipt = blob
        .upload_part(
            &key,
            &UploadId::new(upload_id),
            part_number,
            Box::pin(body),
            LARGE_PART_CEILING as u64,
        )
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "large blob part failed");
            internal(&scope)
        })?;
    Ok(Json(json!({
        "part_number": receipt.part_number,
        "etag": receipt.etag,
    })))
}

/// One part as the client reports it back: the receipt shape the part route
/// answered with.
#[derive(Deserialize)]
struct PartJson {
    part_number: u16,
    etag: String,
}

/// Completes a multipart upload from the client's receipts (issue #586): the
/// object becomes visible at `key` in one step, and the port refuses a part
/// whose `ETag` no longer matches.
async fn complete_large_upload(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    Path((key, upload_id)): Path<(String, String)>,
    Json(parts): Json<Vec<PartJson>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(blob) = ctx.ports.blob.clone() else {
        return Err(internal(&scope));
    };
    let receipts: Vec<PartReceipt> = parts
        .into_iter()
        .map(|part| PartReceipt {
            part_number: part.part_number,
            etag: part.etag,
        })
        .collect();
    blob.complete_multipart(&key, &UploadId::new(upload_id), &receipts)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "large blob complete failed");
            internal(&scope)
        })?;
    Ok(Json(json!({ "completed": true, "key": key })))
}

/// Streams the object at `key` back through `BlobStream::into_response_stream`
/// (issue #586): a 120 MB object is answered without ever holding it whole,
/// because the runtime bridges the port's stream straight to the wire.
async fn download_large(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    Path(key): Path<String>,
) -> Result<ResponseStream, Problem> {
    let Some(blob) = ctx.ports.blob.clone() else {
        return Err(internal(&scope));
    };
    match blob.get_stream(&key).await {
        Ok(Some(stream)) => Ok(stream.into_response_stream()),
        Ok(None) => Err(Problem::not_found().instance(&scope.request_id)),
        Err(err) => {
            tracing::error!(error = %err, "large blob get failed");
            Err(internal(&scope))
        }
    }
}

/// Removes the object at `key` (issue #586): the last leg, so the smoke run
/// leaves no large object behind in the bucket.
async fn delete_large(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, Problem> {
    let Some(blob) = ctx.ports.blob.clone() else {
        return Err(internal(&scope));
    };
    blob.delete(&key).await.map_err(|err| {
        tracing::error!(error = %err, "large blob delete failed");
        internal(&scope)
    })?;
    Ok(Json(json!({ "deleted": true, "key": key })))
}
