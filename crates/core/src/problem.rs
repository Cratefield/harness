//! RFC 9457 problem+json errors (architecture section 6, issue #2).

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Base URI for every problem `type`:
/// `https://factory0.ventures/problems/<slug>`.
pub const PROBLEM_TYPE_BASE: &str = "https://factory0.ventures/problems/";

/// An API error, serialized as `application/problem+json`.
///
/// `type` is a stable URI under [`PROBLEM_TYPE_BASE`], `instance` is the
/// request id, and the body never leaks internals: 500s carry no stack, no
/// source error, nothing but the generic `internal` slug.
#[derive(Debug, Clone)]
pub struct Problem {
    pub slug: &'static str,
    pub status: StatusCode,
    pub title: &'static str,
    pub detail: Option<String>,
    pub instance: Option<String>,
}

impl Problem {
    pub fn new(def: &crate::problems::ProblemDef) -> Self {
        Self {
            slug: def.slug,
            status: def.status,
            title: def.title,
            detail: None,
            instance: None,
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Sets `instance` to the request's id.
    #[must_use]
    pub fn instance(mut self, request_id: &str) -> Self {
        self.instance = Some(request_id.to_string());
        self
    }

    pub fn internal() -> Self {
        Self::new(&crate::problems::SLUGS.internal)
    }

    pub fn validation_failed(detail: impl Into<String>) -> Self {
        Self::new(&crate::problems::SLUGS.validation_failed).with_detail(detail)
    }

    pub fn request_too_large() -> Self {
        Self::new(&crate::problems::SLUGS.request_too_large)
    }

    pub fn not_ready(detail: impl Into<String>) -> Self {
        Self::new(&crate::problems::SLUGS.not_ready).with_detail(detail)
    }

    pub fn not_found() -> Self {
        Self::new(&crate::problems::SLUGS.not_found)
    }

    pub fn type_uri(&self) -> String {
        format!("{PROBLEM_TYPE_BASE}{}", self.slug)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let mut body = json!({
            "type": self.type_uri(),
            "title": self.title,
            "status": self.status.as_u16(),
        });
        if let Some(detail) = &self.detail {
            body["detail"] = json!(detail);
        }
        if let Some(instance) = &self.instance {
            body["instance"] = json!(instance);
        }
        let mut response = (self.status, Json(body)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.type_uri(), self.status.as_u16())
    }
}

impl std::error::Error for Problem {}
