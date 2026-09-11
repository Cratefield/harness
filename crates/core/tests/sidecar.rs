//! Sidecar mounts (ADR 0009, issue #60): the mount table, forwarding, and the
//! rule that a broken sidecar degrades one prefix and nothing else.

// The recorder below stores what it was asked to forward. That is a test
// fixture, not request state (ADR 0007); the scoped allow follows the policy
// in the workspace clippy.toml, as `cratefield-testing`'s fakes do.
#![allow(clippy::disallowed_types)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::http::{Method, StatusCode, header};
use bytes::Bytes;
use common::*;
use cratefield_core::{
    DispatchError, Dispatcher, GATEWAY_ADMIN_PURPOSE, GATEWAY_PURPOSE, HARNESS_ONE_WORKER,
    HARNESS_SIDECARS, HmacSigner, KeyRing, Kid, MapConfig, Payload, Ports, SIDECAR_GATEWAY_SECRET,
    SIDECAR_REQUIRE_GATEWAY, SidecarMounts, Signer, X_HARNESS_API, X_HARNESS_GATEWAY,
    X_HARNESS_MODULE, X_REQUEST_ID,
};

/// Records what it was asked to forward, and answers with whatever it was
/// configured to answer. Core's tests cannot use `cratefield-testing`, which
/// depends on core.
struct RecordingDispatcher {
    binding: &'static str,
    status: StatusCode,
    contract: Option<String>,
    extra_header: Option<(&'static str, &'static str)>,
    body: &'static str,
    calls: Arc<AtomicUsize>,
    seen: Arc<std::sync::Mutex<Vec<http::Request<Bytes>>>>,
}

impl RecordingDispatcher {
    fn new(binding: &'static str) -> Self {
        Self {
            binding,
            status: StatusCode::OK,
            contract: None,
            extra_header: None,
            body: "{\"from\":\"sidecar\"}",
            calls: Arc::new(AtomicUsize::new(0)),
            seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn answering_contract(mut self, api: u32) -> Self {
        self.contract = Some(api.to_string());
        self
    }

    fn answering_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.extra_header = Some((name, value));
        self
    }

    /// The body the sidecar answers `/__health` with. A real sidecar runs
    /// the same `health_handler` as its host, so its body carries
    /// `modules[].tables` — which is how the host learns what it claims
    /// in the shared database (issue #66).
    fn answering_body(mut self, body: &'static str) -> Self {
        self.body = body;
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
        if let Some((name, value)) = self.extra_header {
            builder = builder.header(name, value);
        }
        Ok(builder.body(Bytes::from(self.body)).unwrap())
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

    let response = request(
        &router,
        Method::GET,
        "/v1/acme-pricing/quote?plan=pro",
        &[],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["from"], "sidecar");
    assert_eq!(dispatcher.calls.load(Ordering::SeqCst), 1, "must not retry");

    // The sidecar is a whole harness serving its module at /v1/<name>, so it
    // must receive the path the caller used, not the nest remainder.
    let seen = dispatcher.seen.lock().unwrap();
    assert_eq!(seen[0].uri().path(), "/v1/acme-pricing/quote");
    assert_eq!(seen[0].uri().query(), Some("plan=pro"));
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
        RecordingDispatcher::new("ACME").answering_contract(cratefield_core::HARNESS_API + 1),
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
        Arc::new(RecordingDispatcher::new("ACME").answering_contract(cratefield_core::HARNESS_API));
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

// ------------------------------------------------- the trust boundary (#131)

/// Ports for a host that mounts one sidecar and holds the given extra
/// configuration — a gateway secret, an admin token, the one-Worker
/// declaration.
fn ports_for(
    table: &str,
    extra: &[(&str, &str)],
    dispatcher: Option<Arc<dyn Dispatcher>>,
) -> Ports {
    let mut pairs: Vec<(String, String)> = vec![(HARNESS_SIDECARS.to_owned(), table.to_owned())];
    pairs.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let mut ports = Ports::with_config(Arc::new(MapConfig::from_pairs(pairs)));
    ports.dispatcher = dispatcher;
    ports
}

/// A verifier built the way `gateway_signer` builds the host's minter, so a
/// test can read what a forwarded stamp actually asserts.
fn gateway_verifier(secret: &str) -> HmacSigner {
    let mut ring = KeyRing::new();
    ring.rotate_signing(Kid::Cur, secret.as_bytes().to_vec())
        .expect("test secret is long enough");
    HmacSigner::from_ring(ring)
}

const GATEWAY_SECRET: &str = "a-gateway-secret-long-enough-for-the-ring";
const ADMIN_TOKEN: &str = "admin-token-for-the-host";

#[test]
fn a_one_worker_deployment_refuses_to_mount_a_sidecar() {
    // Given a venture that declares it ships as a single Worker…
    let config = MapConfig::from_pairs([
        (HARNESS_SIDECARS, r#"{"acme-pricing":"ACME"}"#),
        (HARNESS_ONE_WORKER, "true"),
    ]);
    // When it also names a sidecar, Then the table is rejected outright
    // rather than starting a deployment that cannot reach it.
    let errors = SidecarMounts::from_config(&config).unwrap_err();
    assert!(errors[0].contains(HARNESS_ONE_WORKER), "{errors:?}");

    // Without the declaration the same table mounts normally.
    let config = MapConfig::from_pairs([(HARNESS_SIDECARS, r#"{"acme-pricing":"ACME"}"#)]);
    assert!(!SidecarMounts::from_config(&config).unwrap().is_empty());
}

#[pollster::test]
async fn caller_credentials_stop_at_the_host() {
    let dispatcher = Arc::new(RecordingDispatcher::new("ACME"));
    let harness = harness_with_sample();
    let router = harness.router(ports_for(
        r#"{"acme-pricing":"ACME"}"#,
        &[],
        Some(dispatcher.clone()),
    ));

    // Given a caller presenting credentials for the *venture*…
    let _ = request(
        &router,
        Method::GET,
        "/v1/acme-pricing/quote",
        &[
            ("authorization", "Bearer the-venture-admin-token"),
            ("cookie", "session=abc123"),
            ("x-some-extension", "surprise"),
            ("accept", "application/json"),
        ],
        None,
    )
    .await;

    // When the request is forwarded, Then only the allowlist crosses.
    let seen = dispatcher.seen.lock().unwrap();
    let headers = seen[0].headers();
    assert!(
        headers.get("authorization").is_none(),
        "the venture's bearer belongs to the host alone"
    );
    assert!(headers.get("cookie").is_none(), "cookies stop at the host");
    assert!(
        headers.get("x-some-extension").is_none(),
        "an allowlist, not a denylist: unknown headers do not cross"
    );
    assert_eq!(headers.get("accept").unwrap(), "application/json");
}

#[pollster::test]
async fn a_sidecar_cannot_plant_a_cookie_on_the_ventures_origin() {
    let dispatcher = Arc::new(
        RecordingDispatcher::new("ACME")
            .answering_header("set-cookie", "session=attacker; Path=/; HttpOnly"),
    );
    let harness = harness_with_sample();
    let router = harness.router(ports_for(
        r#"{"acme-pricing":"ACME"}"#,
        &[],
        Some(dispatcher),
    ));

    let response = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("set-cookie").is_none(),
        "a sidecar that can set cookies owns a session on a surface it does not serve"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json",
        "the allowlisted response headers still cross"
    );
}

#[pollster::test]
async fn the_host_authorizes_admin_paths_before_forwarding_them() {
    let dispatcher = Arc::new(RecordingDispatcher::new("ACME"));
    let harness = harness_with_sample();
    let router = harness.router(ports_for(
        r#"{"acme-pricing":"ACME"}"#,
        &[("ADMIN_TOKEN", ADMIN_TOKEN)],
        Some(dispatcher.clone()),
    ));

    // Given an unauthenticated caller of a mounted admin path…
    let response = request(
        &router,
        Method::GET,
        "/v1/acme-pricing/admin/export",
        &[],
        None,
    )
    .await;

    // When the host handles it, Then it is refused here — the sidecar is
    // never asked, so a mount cannot become a way around the admin gate.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        dispatcher.calls.load(Ordering::SeqCst),
        0,
        "an unauthorized admin request must not reach the sidecar"
    );
}

#[pollster::test]
async fn the_gateway_stamp_asserts_admin_only_when_the_host_authorized_it() {
    let dispatcher = Arc::new(RecordingDispatcher::new("ACME"));
    let harness = harness_with_sample();
    let router = harness.router(ports_for(
        r#"{"acme-pricing":"ACME"}"#,
        &[
            (SIDECAR_GATEWAY_SECRET, GATEWAY_SECRET),
            ("ADMIN_TOKEN", ADMIN_TOKEN),
        ],
        Some(dispatcher.clone()),
    ));
    let verifier = gateway_verifier(GATEWAY_SECRET);

    // A public request is stamped, but only with the plain purpose.
    let _ = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    // An admin request the host authorized is stamped with the admin purpose.
    let _ = request(
        &router,
        Method::GET,
        "/v1/acme-pricing/admin/export",
        &[("authorization", &format!("Bearer {ADMIN_TOKEN}"))],
        None,
    )
    .await;

    let seen = dispatcher.seen.lock().unwrap();
    let stamp = |i: usize| {
        seen[i]
            .headers()
            .get(X_HARNESS_GATEWAY)
            .expect("a stamp is minted whenever the secret is set")
            .to_str()
            .unwrap()
            .to_owned()
    };

    let public = stamp(0);
    assert!(
        verifier.verify(&public, GATEWAY_PURPOSE).is_some(),
        "a forwarded request carries the plain gateway purpose"
    );
    assert!(
        verifier.verify(&public, GATEWAY_ADMIN_PURPOSE).is_none(),
        "every proxied request carries a stamp, so a plain one must never \
         read as the host having authorized an admin"
    );

    let admin = stamp(1);
    assert!(
        verifier.verify(&admin, GATEWAY_ADMIN_PURPOSE).is_some(),
        "the host asserts its own admin verdict in the MAC"
    );
    assert!(
        verifier.verify(&admin, GATEWAY_PURPOSE).is_none(),
        "the purposes are disjoint (issue #137's rule)"
    );
}

#[pollster::test]
async fn no_gateway_secret_means_no_stamp() {
    let dispatcher = Arc::new(RecordingDispatcher::new("ACME"));
    let harness = harness_with_sample();
    let router = harness.router(ports_for(
        r#"{"acme-pricing":"ACME"}"#,
        &[],
        Some(dispatcher.clone()),
    ));
    let _ = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    let seen = dispatcher.seen.lock().unwrap();
    assert!(
        seen[0].headers().get(X_HARNESS_GATEWAY).is_none(),
        "absent secret, absent capability — and a sidecar that requires the \
         gateway then refuses every request rather than serving them open"
    );
}

#[pollster::test]
async fn requiring_the_gateway_without_a_secret_fails_closed() {
    // Given a sidecar-role deployment that demands the gateway but has no
    // key to verify one with…
    let harness = harness_with_sample();
    let router = harness.router(ports_for("", &[(SIDECAR_REQUIRE_GATEWAY, "true")], None));

    // When a guarded route is called, Then it is refused loudly.
    let response = request(&router, Method::GET, "/v1/sample/row", &[], None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // And the probe routes stay open: probes must probe.
    let health = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(health.status(), StatusCode::OK);
}

#[pollster::test]
async fn a_sidecar_that_requires_the_gateway_refuses_an_unstamped_caller() {
    let harness = harness_with_sample();
    let router = harness.router(ports_for(
        "",
        &[
            (SIDECAR_REQUIRE_GATEWAY, "true"),
            (SIDECAR_GATEWAY_SECRET, GATEWAY_SECRET),
        ],
        None,
    ));

    // A direct caller, reaching the sidecar without going through the host.
    let response = request(&router, Method::GET, "/v1/sample/row", &[], None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await["type"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap(),
        "sidecar-unauthorized"
    );

    // A forged stamp is no better than none.
    let response = request(
        &router,
        Method::GET,
        "/v1/sample/row",
        &[(X_HARNESS_GATEWAY, "not-a-token")],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The stamp the host actually mints is accepted.
    let signer = gateway_verifier(GATEWAY_SECRET);
    let token = signer.sign(&Payload {
        purpose: GATEWAY_PURPOSE.to_owned(),
        subject: "sample".to_owned(),
        exp: None,
        kid: Kid::Cur,
    });
    let response = request(
        &router,
        Method::GET,
        "/v1/sample/row",
        &[(X_HARNESS_GATEWAY, &token)],
        None,
    )
    .await;
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn a_plain_gateway_stamp_does_not_open_the_sidecars_admin_plane() {
    // Given a sidecar-role deployment that closes the gate and holds its
    // own admin token…
    let harness = harness_with_sample();
    let router = harness.router(ports_for(
        "",
        &[
            (SIDECAR_REQUIRE_GATEWAY, "true"),
            (SIDECAR_GATEWAY_SECRET, GATEWAY_SECRET),
            ("ADMIN_TOKEN", ADMIN_TOKEN),
        ],
        None,
    ));
    let signer = gateway_verifier(GATEWAY_SECRET);
    let stamp = |purpose: &str| {
        signer.sign(&Payload {
            purpose: purpose.to_owned(),
            subject: "sample".to_owned(),
            exp: None,
            kid: Kid::Cur,
        })
    };

    // When an admin path is called with the stamp every *proxied* request
    // carries, Then the gate lets it through — it did come from the host —
    // but the admin token is not re-materialized for it. Otherwise any
    // captured forwarded stamp would be an admin credential for its whole
    // lifetime.
    let response = request(
        &router,
        Method::GET,
        "/v1/sample/admin/whoami",
        &[(X_HARNESS_GATEWAY, &stamp(GATEWAY_PURPOSE))],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await["authorized"],
        false,
        "a plain forwarded stamp must not confer admin"
    );

    // And when the stamp is the one the host mints only after its own
    // admin gate passed, the sidecar's token is asserted for the module.
    let response = request(
        &router,
        Method::GET,
        "/v1/sample/admin/whoami",
        &[(X_HARNESS_GATEWAY, &stamp(GATEWAY_ADMIN_PURPOSE))],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await["authorized"],
        true,
        "the host's admin verdict is what re-materializes the token"
    );
}

// ---------------------------------------------- the identity stamp (issue #61)

/// Every response this deployment produces carries the contract stamp, and a
/// one-module deployment — the sidecar shape — also names its module. The
/// host reads both back on every forwarded response, which is how a sidecar
/// redeployed against a different contract is caught within one request
/// instead of at a cold start an isolate does not have.
#[pollster::test]
async fn a_sidecar_stamps_its_identity_on_every_response() {
    let router = harness_with_sample().router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(Arc::new(RecordingDispatcher::new("ACME"))),
    ));

    let forwarded = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    assert_eq!(
        forwarded.headers().get(X_HARNESS_API).unwrap(),
        cratefield_core::HARNESS_API.to_string().as_str()
    );
    assert_eq!(forwarded.headers().get(X_HARNESS_MODULE).unwrap(), "sample");

    let own = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(
        own.headers().get(X_HARNESS_API).unwrap(),
        cratefield_core::HARNESS_API.to_string().as_str()
    );
    assert_eq!(own.headers().get(X_HARNESS_MODULE).unwrap(), "sample");
}

/// A multi-module host serves no single module, so it stamps the contract
/// and stays silent about the name: a wrong name would be worse than none.
#[pollster::test]
async fn a_host_serving_two_modules_stamps_no_module_name() {
    let harness = builder_with_sample()
        .module(SampleModule::named("second"))
        .build()
        .expect("two-module harness builds");
    let router = harness.router(ports_with_sidecars("{}", None));

    let response = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(X_HARNESS_API).unwrap(),
        cratefield_core::HARNESS_API.to_string().as_str()
    );
    assert!(response.headers().get(X_HARNESS_MODULE).is_none());
}

/// `/__health` reports each mounted sidecar's contract, name and version,
/// and the listing is probed lazily and cached for a short window: a
/// polling dashboard must not turn every health check into a fan-out of
/// subrequests.
#[pollster::test]
async fn health_lists_each_sidecar_and_caches_the_probe() {
    let dispatcher =
        Arc::new(RecordingDispatcher::new("ACME").answering_contract(cratefield_core::HARNESS_API));
    let router = harness_with_sample().router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher.clone()),
    ));

    let response = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let sidecar = &body_json(response).await["sidecars"][0];
    assert_eq!(sidecar["name"], "acme-pricing");
    assert_eq!(sidecar["binding"], "ACME");
    assert_eq!(sidecar["probe"], "ok");
    assert_eq!(sidecar["contract"], cratefield_core::HARNESS_API);

    let _ = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(
        dispatcher.calls.load(Ordering::SeqCst),
        1,
        "the second health call within the TTL window must reuse the probe"
    );
}

/// A sidecar answering the wrong contract shows up in `/__health` as a
/// mismatch with both numbers visible — the per-request refusal tells the
/// caller, the health listing tells the operator.
#[pollster::test]
async fn health_reports_a_contract_mismatched_sidecar() {
    let dispatcher = Arc::new(
        RecordingDispatcher::new("ACME").answering_contract(cratefield_core::HARNESS_API - 1),
    );
    let router = harness_with_sample().router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher),
    ));

    let health = body_json(request(&router, Method::GET, "/__health", &[], None).await).await;
    let sidecar = &health["sidecars"][0];
    assert_eq!(sidecar["probe"], "mismatch");
    assert_eq!(sidecar["contract"], cratefield_core::HARNESS_API - 1);
}

/// A sidecar owns tables in the **same** database as its host, and the
/// build-time duplicate check cannot see it: `check_tables` walks
/// `harness.modules()`, which a mount is not in. Left undetected, both
/// modules run `CREATE TABLE IF NOT EXISTS subscribers` and quietly share
/// one table — the silent failure issue #66 is about.
#[pollster::test]
async fn health_reports_a_table_a_sidecar_shares_with_a_compiled_in_module() {
    let dispatcher = Arc::new(
        RecordingDispatcher::new("ACME")
            .answering_contract(cratefield_core::HARNESS_API)
            .answering_body(
                r#"{"modules":[{"name":"acme-pricing","version":"1.0.0","tables":["subscribers","acme_quotes"]}]}"#,
            ),
    );
    let harness = builder_with_sample_claiming(&["subscribers"]);
    let router = harness.router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher),
    ));

    let health = body_json(request(&router, Method::GET, "/__health", &[], None).await).await;
    let sidecar = &health["sidecars"][0];
    assert_eq!(sidecar["probe"], "table-collision");
    let clashes = sidecar["table_collisions"]
        .as_array()
        .expect("the clashing tables are named");
    assert_eq!(clashes.len(), 1, "only the shared one: {clashes:?}");
    let clash = clashes[0].as_str().expect("a string");
    assert!(clash.contains("subscribers"), "{clash}");
    assert!(
        clash.contains("sample"),
        "and names the module to rename: {clash}"
    );
    assert_eq!(
        sidecar["tables"],
        serde_json::json!(["acme_quotes", "subscribers"]),
        "what the sidecar claimed is shown, sorted, whether it clashes or not"
    );
}

/// The other half, which the collision test alone does not prove: a
/// sidecar whose tables are disjoint is plainly `ok`. Without this, a
/// check that flagged *every* sidecar would pass the test above.
#[pollster::test]
async fn a_sidecar_with_its_own_tables_is_not_a_collision() {
    let dispatcher = Arc::new(
        RecordingDispatcher::new("ACME")
            .answering_contract(cratefield_core::HARNESS_API)
            .answering_body(
                r#"{"modules":[{"name":"acme-pricing","version":"1.0.0","tables":["acme_quotes"]}]}"#,
            ),
    );
    let router = builder_with_sample_claiming(&["subscribers"]).router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher),
    ));

    let health = body_json(request(&router, Method::GET, "/__health", &[], None).await).await;
    let sidecar = &health["sidecars"][0];
    assert_eq!(sidecar["probe"], "ok");
    assert_eq!(sidecar["table_collisions"], serde_json::Value::Null);
}

/// A sidecar that declares nothing — unreachable, or an older build whose
/// `/__health` has no `tables` — must not read as "no clash". Absence of
/// evidence is the failure mode this check exists to remove, so it is
/// pinned: the probe says what it saw, and claims nothing it did not.
#[pollster::test]
async fn a_sidecar_that_declares_no_tables_is_not_reported_as_clean() {
    let dispatcher = Arc::new(
        RecordingDispatcher::new("ACME")
            .answering_contract(cratefield_core::HARNESS_API)
            .answering_body(r#"{"modules":[{"name":"acme-pricing","version":"1.0.0"}]}"#),
    );
    let router = builder_with_sample_claiming(&["subscribers"]).router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher),
    ));

    let health = body_json(request(&router, Method::GET, "/__health", &[], None).await).await;
    let sidecar = &health["sidecars"][0];
    assert_eq!(
        sidecar["tables"],
        serde_json::json!([]),
        "an empty declaration is shown as empty, not omitted"
    );
    assert_eq!(sidecar["probe"], "ok");
    assert_eq!(sidecar["table_collisions"], serde_json::Value::Null);
}

/// A sidecar that does not answer at all is `unreachable`, with nothing
/// claimed on its behalf.
#[pollster::test]
async fn health_reports_an_unreachable_sidecar() {
    let router = harness_with_sample().router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(Arc::new(NeverBound)),
    ));

    let health = body_json(request(&router, Method::GET, "/__health", &[], None).await).await;
    let sidecar = &health["sidecars"][0];
    assert_eq!(sidecar["probe"], "unreachable");
    assert_eq!(sidecar["contract"], serde_json::Value::Null);
}

/// The issue's own verification: a fake sidecar one contract behind
/// degrades its prefix to `503 sidecar-contract-mismatch` while every other
/// route keeps answering.
#[pollster::test]
async fn a_sidecar_one_contract_behind_degrades_only_its_prefix() {
    let dispatcher = Arc::new(
        RecordingDispatcher::new("ACME").answering_contract(cratefield_core::HARNESS_API - 1),
    );
    let router = harness_with_sample().router(ports_with_sidecars(
        r#"{"acme-pricing":"ACME"}"#,
        Some(dispatcher),
    ));

    let prefix = request(&router, Method::GET, "/v1/acme-pricing/quote", &[], None).await;
    assert_eq!(prefix.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(prefix).await["type"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap(),
        "sidecar-contract-mismatch"
    );

    let elsewhere = request(&router, Method::GET, "/v1/sample/hello", &[], None).await;
    assert_eq!(elsewhere.status(), StatusCode::OK);
}
