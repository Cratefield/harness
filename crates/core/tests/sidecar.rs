//! Sidecar mounts (ADR 0009, issue #60): the mount table, forwarding, and the
//! rule that a broken sidecar degrades one prefix and nothing else.

// The recorder below stores what it was asked to forward. That is a test
// fixture, not request state (ADR 0007); the scoped allow follows the policy
// in the workspace clippy.toml, as `factory0-testing`'s fakes do.
#![allow(clippy::disallowed_types)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::http::{Method, StatusCode, header};
use bytes::Bytes;
use common::*;
use factory0_core::{
    DispatchError, Dispatcher, HARNESS_SIDECARS, MapConfig, Ports, SidecarMounts, X_HARNESS_API,
    X_REQUEST_ID,
};

/// Records what it was asked to forward, and answers with whatever it was
/// configured to answer. Core's tests cannot use `factory0-testing`, which
/// depends on core.
struct RecordingDispatcher {
    binding: &'static str,
    status: StatusCode,
    contract: Option<String>,
    calls: Arc<AtomicUsize>,
    seen: Arc<std::sync::Mutex<Vec<http::Request<Bytes>>>>,
}

impl RecordingDispatcher {
    fn new(binding: &'static str) -> Self {
        Self {
            binding,
            status: StatusCode::OK,
            contract: None,
            calls: Arc::new(AtomicUsize::new(0)),
            seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn answering_contract(mut self, api: u32) -> Self {
        self.contract = Some(api.to_string());
        self
    }
}

#[async_trait]
impl Dispatcher for RecordingDispatcher {
    fn has(&self, binding: &str) -> bool {
        binding == self.binding
    }

    async fn dispatch(
        &self,
        binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if binding != self.binding {
            return Err(DispatchError::NotBound(binding.to_owned()));
        }
        self.seen.lock().unwrap().push(request);
        let mut builder = http::Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(api) = &self.contract {
            builder = builder.header(X_HARNESS_API, api);
        }
        Ok(builder
            .body(Bytes::from_static(b"{\"from\":\"sidecar\"}"))
            .unwrap())
    }
}

struct NeverBound;

#[async_trait]
impl Dispatcher for NeverBound {
    fn has(&self, _binding: &str) -> bool {
        false
    }
    async fn dispatch(
        &self,
        binding: &str,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        Err(DispatchError::NotBound(binding.to_owned()))
    }
}

fn ports_with_sidecars(table: &str, dispatcher: Option<Arc<dyn Dispatcher>>) -> Ports {
    let mut ports =
        Ports::with_config(Arc::new(MapConfig::from_pairs([(HARNESS_SIDECARS, table)])));
    ports.dispatcher = dispatcher;
    ports
}

// ---------------------------------------------------------------- the table

#[test]
fn mount_table_parses_and_is_absent_by_default() {
    let empty = MapConfig(std::collections::HashMap::new());
    assert!(SidecarMounts::from_config(&empty).unwrap().is_empty());

    let config = MapConfig::from_pairs([(HARNESS_SIDECARS, r#"{"acme-pricing":"ACME"}"#)]);
    let mounts = SidecarMounts::from_config(&config).unwrap();
    let mount = mounts.iter().next().unwrap();
    assert_eq!(mount.name, "acme-pricing");
    assert_eq!(mount.binding, "ACME");
}

#[test]
fn mount_table_rejects_bad_names_and_empty_bindings() {
    let config = MapConfig::from_pairs([(HARNESS_SIDECARS, r#"{"Acme_Pricing":"ACME"}"#)]);
    let errors = SidecarMounts::from_config(&config).unwrap_err();
    assert!(errors[0].contains("kebab-case"), "{errors:?}");

    let config = MapConfig::from_pairs([(HARNESS_SIDECARS, r#"{"acme-pricing":""}"#)]);
    let errors = SidecarMounts::from_config(&config).unwrap_err();
    assert!(errors[0].contains("empty service binding"), "{errors:?}");

    let config = MapConfig::from_pairs([(HARNESS_SIDECARS, "not json")]);
    assert!(SidecarMounts::from_config(&config).is_err());
}

#[test]
fn a_sidecar_may_not_claim_a_prefix_an_in_process_module_serves() {
    let config = MapConfig::from_pairs([(HARNESS_SIDECARS, r#"{"sample":"ACME"}"#)]);
    let mounts = SidecarMounts::from_config(&config).unwrap();
    let collisions = mounts.collisions(&["sample"]);
    assert_eq!(collisions.len(), 1);
    assert!(collisions[0].contains("already served in-process"));
    assert!(mounts.collisions(&["other"]).is_empty());
}

// ----------------------------------------------------------- forwarding

#[pollster::test]
async fn a_mounted_sidecar_answers_under_its_prefix() {
    let dispatcher = Arc::new(RecordingDispatcher::new("ACME"));
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher.clone()),
    ));

    let response = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["from"], "sidecar");
    assert_eq!(dispatcher.calls.load(Ordering::SeqCst), 1, "must not retry");
}

#[pollster::test]
async fn the_request_id_crosses_the_boundary_once() {
    let dispatcher = Arc::new(RecordingDispatcher::new("ACME"));
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher.clone()),
    ));

    let response = request(
        &router,
        Method::GET,
        "/v1/acme-pricing/quote",
        &[(X_REQUEST_ID, "req-abcdefgh")],
        None,
    )
    .await;
    assert_eq!(
        response.headers().get(X_REQUEST_ID).unwrap(),
        "req-abcdefgh"
    );

    let seen = dispatcher.seen.lock().unwrap();
    let forwarded: Vec<_> = seen[0].headers().get_all(X_REQUEST_ID).iter().collect();
    assert_eq!(forwarded.len(), 1, "id must appear once, not twice");
    assert_eq!(forwarded[0], "req-abcdefgh");
}

#[pollster::test]
async fn host_and_hop_by_hop_headers_are_not_forwarded_but_the_client_ip_is() {
    let dispatcher = Arc::new(RecordingDispatcher::new("ACME"));
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher.clone()),
    ));

    let _ = request(
        &router,
        Method::GET,
        "/v1/acme-pricing/quote",
        &[
            ("host", "api.example.com"),
            ("connection", "keep-alive"),
            ("cf-connecting-ip", "203.0.113.7"),
        ],
        None,
    )
    .await;

    let seen = dispatcher.seen.lock().unwrap();
    let headers = seen[0].headers();
    assert!(headers.get("host").is_none(), "host must not be forwarded");
    assert!(
        headers.get("connection").is_none(),
        "hop-by-hop must not be forwarded"
    );
    assert_eq!(
        headers.get("cf-connecting-ip").unwrap(),
        "203.0.113.7",
        "the sidecar cannot see the caller without it"
    );
}

// -------------------------------------------------------------- degrading

#[pollster::test]
async fn a_missing_binding_degrades_only_that_prefix() {
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(Arc::new(NeverBound)),
    ));

    let response = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert_eq!(
        body_json(response).await["type"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap(),
        "sidecar-unavailable"
    );

    // The in-process module is untouched.
    let ok = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[pollster::test]
async fn no_dispatcher_at_all_degrades_only_that_prefix() {
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars(r#"{"acme-pricing":"ACME"}"#, None));
    let response = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let ok = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[pollster::test]
async fn a_contract_mismatch_is_refused() {
    let dispatcher = Arc::new(
        RecordingDispatcher::new("ACME").answering_contract(factory0_core::HARNESS_API + 1),
    );
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher),
    ));

    let response = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(response).await["type"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap(),
        "sidecar-contract-mismatch"
    );
}

#[pollster::test]
async fn a_matching_contract_passes_through() {
    let dispatcher =
        Arc::new(RecordingDispatcher::new("ACME").answering_contract(factory0_core::HARNESS_API));
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher),
    ));
    let response = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[pollster::test]
async fn a_colliding_mount_never_shadows_the_in_process_module() {
    let dispatcher = Arc::new(RecordingDispatcher::new("ACME"));
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars(
        r#"{"sample":"ACME"}"#,
        Some(dispatcher.clone()),
    ));

    let response = request(&router, Method::GET, "/v1/sample/row", &[], None).await;
    assert_ne!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the in-process module must still serve its own prefix"
    );
    assert_eq!(dispatcher.calls.load(Ordering::SeqCst), 0);
}

#[pollster::test]
async fn a_malformed_table_mounts_nothing_and_leaves_the_venture_serving() {
    let harness = harness_with_sample();
    let router = harness.router(ports_with_sidecars("not json", None));
    let ok = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(ok.status(), StatusCode::OK);
}
