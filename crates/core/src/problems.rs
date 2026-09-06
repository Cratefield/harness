//! The registry of every problem slug the harness can emit (architecture
//! section 6): stable `type` URIs, statuses and descriptions. Modules add
//! their own slugs as `const ProblemDef`s in the same shape.

use axum::http::StatusCode;

/// Definition of one problem slug.
#[derive(Debug, Clone, Copy)]
pub struct ProblemDef {
    /// Last path segment of the `type` URI.
    pub slug: &'static str,
    pub status: StatusCode,
    /// Short, stable human title (RFC 9457 `title`).
    pub title: &'static str,
    /// One-line description for reviewers; not part of the response.
    pub description: &'static str,
}

/// Every slug core emits. Keep sorted by status.
pub struct Slugs {
    /// 400: a request body/query did not deserialize or failed validation.
    pub validation_failed: ProblemDef,
    /// 413: the request body exceeded the 64 KiB `/v1/*` limit.
    pub request_too_large: ProblemDef,
    /// 404: no route matched.
    pub not_found: ProblemDef,
    /// 500: unhandled error; body carries no internals.
    pub internal: ProblemDef,
    /// 503: readiness probe failed (`/__ready`): database missing, slow or
    /// erroring.
    pub not_ready: ProblemDef,
}

pub const SLUGS: Slugs = Slugs {
    validation_failed: ProblemDef {
        slug: "validation-failed",
        status: StatusCode::BAD_REQUEST,
        title: "Request validation failed",
        description: "The request body or query did not deserialize into a valid request.",
    },
    request_too_large: ProblemDef {
        slug: "request-too-large",
        status: StatusCode::PAYLOAD_TOO_LARGE,
        title: "Request body too large",
        description: "The request body exceeded the 64 KiB limit for /v1 endpoints.",
    },
    not_found: ProblemDef {
        slug: "not-found",
        status: StatusCode::NOT_FOUND,
        title: "Not found",
        description: "No route matched the request.",
    },
    internal: ProblemDef {
        slug: "internal",
        status: StatusCode::INTERNAL_SERVER_ERROR,
        title: "Internal error",
        description: "Unhandled error; no internals are exposed in the body.",
    },
    not_ready: ProblemDef {
        slug: "not-ready",
        status: StatusCode::SERVICE_UNAVAILABLE,
        title: "Service not ready",
        description: "Readiness probe failed: the database is missing, erroring or too slow.",
    },
};

/// Every core slug definition, for tests and docs.
pub fn registry() -> Vec<&'static ProblemDef> {
    vec![
        &SLUGS.validation_failed,
        &SLUGS.request_too_large,
        &SLUGS.not_found,
        &SLUGS.internal,
        &SLUGS.not_ready,
    ]
}
