//! Sidecar mounts (ADR 0009): a module served by its own Worker, mounted at
//! the same `/v1/<name>` as an in-process module and indistinguishable to a
//! caller.
//!
//! The mount table is **runtime configuration**, never a builder call. A
//! `.sidecar()` in `src/harness.rs` would bake a customer-specific mount into
//! the artifact, so the artifact would stop being a function of the module set
//! and could no longer be shared between ventures (#59).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use crate::config::Config;
use crate::http::{MAX_BODY_BYTES, X_REQUEST_ID};
use crate::module::HARNESS_API;
use crate::ports::Dispatcher;
use crate::problem::Problem;
use crate::problems::SLUGS;
use crate::scope::Scope;

/// Config key holding the mount table, a JSON object of
/// `{"<module name>": "<service binding>"}`.
pub const HARNESS_SIDECARS: &str = "HARNESS_SIDECARS";

/// Contract version stamped on every harness response, checked by the host on
/// every forwarded response. Stamping beats a cold-start handshake because an
/// isolate outlives a sidecar redeploy (ADR 0009).
pub const X_HARNESS_API: &str = "x-harness-api";
/// Module name stamped alongside [`X_HARNESS_API`].
pub const X_HARNESS_MODULE: &str = "x-harness-module";

/// Headers that must not be forwarded: hop-by-hop, plus `host`, which belongs
/// to the host Worker's own connection.
const NOT_FORWARDED: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// One mounted sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarMount {
    /// Module name; mounted at `/v1/<name>`.
    pub name: String,
    /// Service binding the runtime resolves to reach it.
    pub binding: String,
}

/// The mount table, parsed from configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SidecarMounts(Vec<SidecarMount>);

impl SidecarMounts {
    /// Reads and validates [`HARNESS_SIDECARS`]. Absent or empty is not an
    /// error: most ventures mount no sidecars.
    ///
    /// # Errors
    ///
    /// Every malformed entry, reported together so one deploy surfaces them
    /// all rather than one per attempt.
    pub fn from_config(config: &dyn Config) -> Result<Self, Vec<String>> {
        let Some(raw) = config
            .get(HARNESS_SIDECARS)
            .filter(|v| !v.trim().is_empty())
        else {
            return Ok(Self::default());
        };
        let parsed: BTreeMap<String, String> = serde_json::from_str(&raw).map_err(|err| {
            vec![format!(
                "{HARNESS_SIDECARS} must be a JSON object of {{\"module-name\": \"BINDING\"}}: {err}"
            )]
        })?;

        let mut errors = Vec::new();
        let mut mounts = Vec::new();
        for (name, binding) in parsed {
            if !is_kebab(&name) {
                errors.push(format!(
                    "sidecar name `{name}` must be kebab-case ([a-z0-9]+ separated by '-')"
                ));
            }
            if binding.trim().is_empty() {
                errors.push(format!("sidecar `{name}` has an empty service binding"));
            }
            mounts.push(SidecarMount { name, binding });
        }
        if errors.is_empty() {
            Ok(Self(mounts))
        } else {
            Err(errors)
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SidecarMount> {
        self.0.iter()
    }

    /// Names that collide with an in-process module. Both sides are known
    /// without an `Env`, so this is the one sidecar check that can run early.
    #[must_use]
    pub fn collisions(&self, module_names: &[&str]) -> Vec<String> {
        self.0
            .iter()
            .filter(|m| module_names.contains(&m.name.as_str()))
            .map(|m| {
                format!(
                    "sidecar `{}` claims `/v1/{}`, already served in-process",
                    m.name, m.name
                )
            })
            .collect()
    }
}

fn is_kebab(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

struct SidecarState {
    mount: SidecarMount,
    dispatcher: Option<Arc<dyn Dispatcher>>,
}

/// The router for one sidecar prefix: a fallback that forwards everything.
pub(crate) fn router(mount: SidecarMount, dispatcher: Option<Arc<dyn Dispatcher>>) -> Router {
    Router::new()
        .fallback(forward)
        .with_state(Arc::new(SidecarState { mount, dispatcher }))
}

async fn forward(
    State(state): State<Arc<SidecarState>>,
    scope: Scope,
    request: axum::extract::Request,
) -> Response {
    let unavailable = |detail: String| -> Response {
        Problem::new(&SLUGS.sidecar_unavailable)
            .with_detail(detail)
            .instance(&scope.request_id)
            .into_response()
    };

    let Some(dispatcher) = state.dispatcher.clone() else {
        tracing::warn!(
            module = state.mount.name,
            "sidecar mounted but the runtime provides no dispatcher"
        );
        return unavailable(format!(
            "`{}` is mounted as a sidecar but this runtime cannot dispatch",
            state.mount.name
        ));
    };
    if !dispatcher.has(&state.mount.binding) {
        tracing::warn!(
            module = state.mount.name,
            binding = state.mount.binding,
            "sidecar binding is not present in this deployment"
        );
        return unavailable(format!(
            "`{}` is mounted on binding `{}`, which this deployment does not have",
            state.mount.name, state.mount.binding
        ));
    }

    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return Problem::new(&SLUGS.request_too_large)
            .instance(&scope.request_id)
            .into_response();
    };

    let mut outbound = http::Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone());
    if let Some(headers) = outbound.headers_mut() {
        for (name, value) in &parts.headers {
            if NOT_FORWARDED.contains(&name.as_str()) {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        // One trail across both Workers. `insert`, so a client-supplied id
        // cannot arrive twice.
        if let Ok(value) = scope.request_id.parse() {
            headers.insert(X_REQUEST_ID, value);
        }
    }
    let outbound = match outbound.body(body) {
        Ok(req) => req,
        Err(err) => return unavailable(format!("could not build the forwarded request: {err}")),
    };

    match dispatcher.dispatch(&state.mount.binding, outbound).await {
        Ok(response) => match contract_of(&response) {
            Some(api) if api != HARNESS_API => {
                tracing::warn!(
                    module = state.mount.name,
                    sidecar_api = api,
                    host_api = HARNESS_API,
                    "sidecar contract mismatch"
                );
                Problem::new(&SLUGS.sidecar_contract_mismatch)
                    .with_detail(format!(
                        "`{}` answers contract {api}; this harness speaks {HARNESS_API}",
                        state.mount.name
                    ))
                    .instance(&scope.request_id)
                    .into_response()
            }
            _ => into_axum(response),
        },
        Err(err) => {
            tracing::warn!(module = state.mount.name, error = %err, "sidecar dispatch failed");
            unavailable(err.to_string())
        }
    }
}

/// The contract a response claims, if it claims one. A sidecar that stamps
/// nothing is not rejected here: it may predate the header, and the mismatch
/// that matters is a *wrong* number, not a missing one.
fn contract_of(response: &http::Response<Bytes>) -> Option<u32> {
    response
        .headers()
        .get(X_HARNESS_API)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

fn into_axum(response: http::Response<Bytes>) -> Response {
    let (parts, body) = response.into_parts();
    let mut out = Response::new(axum::body::Body::from(body));
    *out.status_mut() = parts.status;
    *out.headers_mut() = parts.headers;
    *out.version_mut() = parts.version;
    out
}
