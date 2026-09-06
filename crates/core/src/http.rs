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
    let incoming = request
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| request_id_is_valid(value));
    let request_id = match incoming {
        Some(valid) => valid.to_owned(),
        None => state.id_gen.ulid(),
    };

    let scope = Scope {
        defer: Arc::clone(&state.defer),
        span: info_span!("request", request_id = %request_id),
        request_id: request_id.clone(),
    };
    request.extensions_mut().insert(scope);

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    response
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
