//! HTTP plumbing every venture router shares (issue #2): the problem+json
//! `Json` extractor, the request-id middleware that creates the [`Scope`],
//! and the `/v1/*` security headers.

use axum::body::Body;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderValue, Request as HttpRequest, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response as AxumResponse};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;

use crate::ports::{Defer, IdGen};
use crate::problem::Problem;
use crate::scope::Scope;
use tracing::info_span;

/// `x-request-id`: accepted from the client when it matches
/// `^[A-Za-z0-9_-]{8,128}$`, otherwise generated as a ULID. Always set on
/// the response (architecture section 6).
pub const X_REQUEST_ID: &str = "x-request-id";

/// Default request body limit for `/v1/*` JSON endpoints.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

// `Duration::from_days` is unstable on the pinned toolchain
// (`duration_constructors`), so this stays in seconds.
#[allow(clippy::duration_suboptimal_units)]
const CORS_PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(86_400);

/// The character class and length bounds of an accepted request id.
pub fn request_id_is_valid(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// State the request-id layer needs, resolved from `Ports` when the router
/// is assembled.
#[derive(Clone)]
pub(crate) struct ScopeState {
    pub defer: Arc<dyn Defer>,
    pub id_gen: Arc<dyn IdGen>,
}

/// Middleware: resolve the request id, build the [`Scope`] (request id,
/// defer, tracing span), insert it into extensions, echo the id on the
/// response.
pub(crate) async fn scope_layer(
    axum::extract::State(state): axum::extract::State<ScopeState>,
    mut request: Request,
    next: Next,
) -> AxumResponse {
    use tracing::Instrument as _;
    use tracing::field::Empty;

    let incoming = request
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| request_id_is_valid(value));
    let request_id = match incoming {
        Some(valid) => valid.to_owned(),
        None => state.id_gen.ulid(),
    };

    // The one structured span per request (issue #14). `route`,
    // `module`, `status` and `duration_ms` are recorded after the
    // handler runs; no field ever carries an email (only `ip_hash`).
    let method = request.method().as_str().to_owned();
    let ip_hash = crate::logging::subject_hash(
        &crate::rate_limit::client_ip(request.headers()).unwrap_or_default(),
    );
    let ua_family = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| "unknown".to_owned(), ua_family_of);
    let span = info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        route = Empty,
        module = Empty,
        status = Empty,
        duration_ms = Empty,
        ip_hash = %ip_hash,
        ua_family = %ua_family,
    );

    let scope = Scope {
        defer: Arc::clone(&state.defer),
        span: span.clone(),
        request_id: request_id.clone(),
    };
    request.extensions_mut().insert(scope);

    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|matched| matched.as_str().to_owned())
        .unwrap_or_default();

    // `std::time::Instant::now()` panics on wasm32-unknown-unknown with
    // "time not implemented on this platform", which took down every
    // request on Workers — `/__health` included. There is no monotonic
    // clock in that target, and `Date.now()` is frozen between I/O in
    // workerd, so a wall-clock delta would read 0 and look measured.
    // Timing is therefore recorded only where a real clock exists;
    // Cloudflare's own request logs carry it on Workers.
    #[cfg(not(target_arch = "wasm32"))]
    let started = std::time::Instant::now();
    let future = next.run(request);
    let mut response = future.instrument(span.clone()).await;

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    span.record("route", route.as_str());
    span.record(
        "module",
        route
            .strip_prefix("/v1/")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_default(),
    );
    span.record("status", response.status().as_u16());
    #[cfg(not(target_arch = "wasm32"))]
    {
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        span.record("duration_ms", duration_ms);
    }
    response
}

/// Coarse user-agent family: the first product token, lowercased —
/// enough to group browsers, bots and libraries without a UA parser.
fn ua_family_of(user_agent: &str) -> String {
    let token = user_agent
        .split(['/', ' ', ';', '('])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let truncated: String = token.chars().take(24).collect();
    if truncated.is_empty() {
        "unknown".to_owned()
    } else {
        truncated
    }
}

/// Middleware: `/v1/*` responses carry
/// `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and
/// `Referrer-Policy: no-referrer` (architecture section 6).
pub(crate) async fn security_headers_layer(request: Request, next: Next) -> AxumResponse {
    let is_api = request.uri().path().starts_with("/v1/");
    let mut response = next.run(request).await;
    if is_api {
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        );
    }
    response
}

/// A `Json` extractor and response whose rejections and serializations are
/// problem+json (architecture section 6). Deserialization failures become a
/// `400 validation-failed` problem listing the field.
pub struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request(request: HttpRequest<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let instance = request
            .extensions()
            .get::<Scope>()
            .map(|scope| scope.request_id.clone());
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Json(value)),
            Err(rejection) => {
                // Body reads fail through the shared 413 slug (the size
                // limit); everything else is a 400 validation problem.
                let mut problem = match &rejection {
                    axum::extract::rejection::JsonRejection::BytesRejection(_) => {
                        Problem::request_too_large()
                    }
                    _ => Problem::validation_failed(rejection.body_text()),
                };
                if let Some(instance) = instance {
                    problem = problem.instance(&instance);
                }
                Err(problem)
            }
        }
    }
}

impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> AxumResponse {
        axum::Json(self.0).into_response()
    }
}

/// A `429 rate-limited` problem carrying `Retry-After: <seconds>` when the
/// limiter reported a pause (architecture section 6).
pub fn rate_limited(retry_after: Option<Duration>) -> AxumResponse {
    let problem = Problem::new(&crate::problems::SLUGS.rate_limited);
    let mut response = problem.into_response();
    if let Some(pause) = retry_after {
        let secs = pause.as_secs().max(1);
        if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
            response
                .headers_mut()
                .insert(header::HeaderName::from_static("retry-after"), value);
        }
    }
    response
}

/// CORS allowlist from the venture's origins; never a wildcard
/// (architecture section 6). Tower-http echoes the matched origin rather
/// than emitting `*`, and requests from other origins get no CORS headers.
pub(crate) fn cors_layer(origins: &[String]) -> tower_http::cors::CorsLayer {
    use tower_http::cors::{AllowOrigin, CorsLayer};
    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE])
        .max_age(CORS_PREFLIGHT_MAX_AGE)
}
