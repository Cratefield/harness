//! The no-network request helper (issue #9): `tower::ServiceExt::oneshot`
//! straight into the router.

use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use serde_json::Value;

/// Sends a request through the router without a network. `json` (when
/// `Some`) becomes a JSON body with `content-type: application/json`.
///
/// # Panics
///
/// Panics when the router itself fails (never for ordinary responses).
pub async fn request(
    router: &axum::Router,
    method: Method,
    path: &str,
    json: Option<&str>,
) -> TestResponse {
    use tower::ServiceExt;
    let mut builder = Request::builder().method(method).uri(path);
    let body = match json {
        Some(payload) => {
            builder = builder.header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Body::from(payload.to_owned())
        }
        None => Body::empty(),
    };
    let request = builder.body(body).expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    TestResponse::from(response).await
}

/// A fully-buffered test response.
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    body: Bytes,
}

impl TestResponse {
    async fn from(response: Response) -> Self {
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .expect("test body reads");
        Self {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }

    /// The body parsed as JSON.
    ///
    /// # Panics
    ///
    /// Panics when the body is not valid JSON.
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("body is JSON")
    }

    /// The raw body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }
}
