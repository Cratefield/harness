//! Cloudflare for `SaaS` adapter acceptance tests (issue #590): the request
//! shapes, the response mapping into the port's types, every error mapping,
//! the refusal and `NotConfigured` short-circuits (with zero requests), and
//! the token never appearing in any error or `Debug`.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_cloudflare_saas::{
    API_TOKEN_VAR, CNAME_TARGET_VAR, CloudflareSaas, CloudflareSaasConfig, ZONE_ID_VAR,
    ZONE_NAME_VAR,
};
use cratefield_core::{
    CertificateStatus, CustomHostnameError, CustomHostnames, DnsRecordType, HostnameClaim,
    HostnameRefusal, HttpClient, HttpError, ProviderStatus, ValidationMethod,
};
use http::{HeaderMap, Request, Response, StatusCode};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

// Obvious dummy token, never real.
const DUMMY_TOKEN: &str = "cf_dummy_token_000000000000";

const HOSTNAME_ID: &str = "0d89c70d-ad9f-4843-b99f-6cc0252067e9";
const OWNERSHIP_TXT: &str = "5cc07c04-ea62-4a5a-95f0-419334a875a4";

/// A recorded outgoing request.
struct CapturedRequest {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: String,
}

/// A recording fake `HttpClient`: it captures every request and answers
/// with the scripted response for that call, in order.
struct ScriptedHttp {
    responses: Vec<(u16, String)>,
    calls: AtomicUsize,
    tx: mpsc::Sender<CapturedRequest>,
}

#[async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = request.into_parts();
        self.tx
            .send(CapturedRequest {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: String::from_utf8_lossy(&body).to_string(),
            })
            .expect("test channel open");
        let (status, payload) = self
            .responses
            .get(index)
            .expect("a scripted response for every call");
        Response::builder()
            .status(StatusCode::from_u16(*status).expect("valid status"))
            .body(Bytes::copy_from_slice(payload.as_bytes()))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

/// A fake that always fails at the transport layer.
struct FailingHttp;

#[async_trait]
impl HttpClient for FailingHttp {
    async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        Err(HttpError::Transport("dns is down".to_owned()))
    }
}

fn scripted(responses: Vec<(u16, String)>) -> (Arc<ScriptedHttp>, mpsc::Receiver<CapturedRequest>) {
    let (tx, rx) = mpsc::channel();
    (
        Arc::new(ScriptedHttp {
            responses,
            calls: AtomicUsize::new(0),
            tx,
        }),
        rx,
    )
}

fn config() -> CloudflareSaasConfig {
    config_with_cname(Some("origin.cratefield.app"))
}

fn config_with_cname(cname_target: Option<&str>) -> CloudflareSaasConfig {
    CloudflareSaasConfig {
        zone_id: "a1b2c3d4e5f6".to_owned(),
        zone_name: "cratefield.app".to_owned(),
        api_token: DUMMY_TOKEN.to_owned(),
        cname_target: cname_target.map(str::to_owned),
    }
}

fn adapter(http: Arc<ScriptedHttp>) -> CloudflareSaas {
    CloudflareSaas::new(http, config())
}

// --- Fixtures -------------------------------------------------------------

/// A pending create: the ownership `TXT` and an HTTP challenge, no
/// certificate yet. `verification_errors` is informational while pending.
const HOSTNAME_PENDING: &str = r#"{
  "id": "0d89c70d-ad9f-4843-b99f-6cc0252067e9",
  "hostname": "share.acme.com",
  "status": "pending",
  "created_at": "2026-10-02T09:00:00.000000Z",
  "ownership_verification": {"type":"txt","name":"_cf-custom-hostname.share.acme.com","value":"5cc07c04-ea62-4a5a-95f0-419334a875a4"},
  "ownership_verification_http": {"http_url":"http://share.acme.com/.well-known/cf-custom-hostname-challenge/0d89c70d-ad9f-4843-b99f-6cc0252067e9","http_body":"5cc07c04-ea62-4a5a-95f0-419334a875a4"},
  "verification_errors": ["None of the A or AAAA records are owned by this account and the pre-generated ownership verification token was not found."],
  "ssl": {"id":"0d89c70d-ad9f-4843-b99f-6cc0252067e9","type":"dv","method":"http","status":"pending_validation","wildcard":false,"validation_errors":[],"validation_records":[{"status":"pending","http_url":"http://share.acme.com/.well-known/pki-validation/ca3-da12a1c25e7b48cf80408c6c1763b8a2.txt","http_body":"ca3-574923932a82475cb8592200f1a2a23d"}]}
}"#;

/// The same claim, live: certificate active, nothing left to publish.
const HOSTNAME_ACTIVE: &str = r#"{
  "id": "0d89c70d-ad9f-4843-b99f-6cc0252067e9",
  "hostname": "share.acme.com",
  "status": "active",
  "created_at": "2026-10-02T09:00:00.000000Z",
  "verification_errors": [],
  "ssl": {"id":"0d89c70d-ad9f-4843-b99f-6cc0252067e9","type":"dv","method":"http","status":"active","wildcard":false,"validation_errors":[],"validation_records":[]}
}"#;

/// A pending claim validated over `TXT`, with a DCV `TXT` record to publish.
const HOSTNAME_PENDING_TXT: &str = r#"{
  "id": "1f9ab2c3-1111-4222-8333-444455556666",
  "hostname": "share.acme.com",
  "status": "pending",
  "ownership_verification": {"type":"txt","name":"_cf-custom-hostname.share.acme.com","value":"ownership-token"},
  "verification_errors": [],
  "ssl": {"id":"1f9ab2c3-1111-4222-8333-444455556666","type":"dv","method":"txt","status":"pending_validation","wildcard":false,"validation_errors":[],"validation_records":[{"status":"pending","txt_name":"_acme-challenge.share.acme.com","txt_value":"dcv-txt-value"}]}
}"#;

/// A certificate whose DCV timed out: a failure, with the provider's reason.
const HOSTNAME_CERT_TIMED_OUT: &str = r#"{
  "id": "2c3d4e5f-aaaa-4bbb-8ccc-ddddeeeeffff",
  "hostname": "share.acme.com",
  "status": "pending",
  "verification_errors": [],
  "ssl": {"id":"2c3d4e5f-aaaa-4bbb-8ccc-ddddeeeeffff","type":"dv","method":"http","status":"validation_timed_out","wildcard":false,"validation_errors":[{"code":1102,"message":"Certificate validation timed out"}],"validation_records":[]}
}"#;

const SINGLE: &str = r#"{"success":true,"errors":[],"messages":[],"result":OBJECT}"#;
const LIST: &str = r#"{"success":true,"errors":[],"messages":[],"result":[OBJECT],"result_info":{"page":1,"per_page":20,"count":1,"total_count":1,"total_pages":1}}"#;
const LIST_EMPTY: &str = r#"{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":20,"count":0,"total_count":0,"total_pages":0}}"#;
const ERROR: &str =
    r#"{"success":false,"errors":[{"code":CODE,"message":"MESSAGE"}],"messages":[],"result":null}"#;
const DELETE_OK: &str = r#"{"success":true,"errors":[],"messages":[],"result":{"id":"0d89c70d-ad9f-4843-b99f-6cc0252067e9"}}"#;

fn single(object: &str) -> String {
    SINGLE.replace("OBJECT", object)
}

fn list(object: &str) -> String {
    LIST.replace("OBJECT", object)
}

fn error_body(code: i64, message: &str) -> String {
    ERROR
        .replace("CODE", &code.to_string())
        .replace("MESSAGE", message)
}

// --- create ---------------------------------------------------------------

#[pollster::test]
async fn create_posts_the_claim_and_lists_the_records_to_publish() {
    let (http, rx) = scripted(vec![
        (201, single(HOSTNAME_PENDING)),
        (201, single(HOSTNAME_PENDING)),
        (201, single(HOSTNAME_PENDING_TXT)),
    ]);
    let bare = CloudflareSaas::new(http.clone(), config_with_cname(None));

    // No CNAME target: the ownership TXT is the one record to publish.
    let created = bare
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .expect("claims");
    assert!(created.validation.iter().any(|record| {
        record.record_type == DnsRecordType::Txt
            && record.name == "_cf-custom-hostname.share.acme.com"
            && record.value == OWNERSHIP_TXT
    }));

    // The POST carries the claim and the token, with the HTTP DV method.
    let captured = rx.try_recv().expect("one request");
    assert_eq!(captured.method, "POST");
    assert_eq!(
        captured.uri,
        "https://api.cloudflare.com/client/v4/zones/a1b2c3d4e5f6/custom_hostnames"
    );
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        format!("Bearer {DUMMY_TOKEN}").as_str()
    );
    let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(body["hostname"], "share.acme.com");
    assert_eq!(body["ssl"]["method"], "http");
    assert_eq!(body["ssl"]["type"], "dv");

    // A configured CNAME target adds the cut-over hint.
    let with_cname = adapter(http.clone())
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .expect("claims");
    assert!(with_cname.validation.iter().any(|record| {
        record.record_type == DnsRecordType::Cname
            && record.name == "share.acme.com"
            && record.value == "origin.cratefield.app"
    }));
    rx.try_recv().expect("the CNAME claim");

    // TXT DCV asks for the method on the wire, and the DCV record joins.
    let txt_claim = HostnameClaim::new("share.acme.com").with_method(ValidationMethod::Txt);
    let created = bare.create(&txt_claim).await.expect("claims");
    let body: serde_json::Value =
        serde_json::from_str(&rx.try_recv().expect("the TXT claim").body).unwrap();
    assert_eq!(body["ssl"]["method"], "txt");
    assert_eq!(body["ssl"]["type"], "dv");
    assert!(created.validation.iter().any(|record| {
        record.record_type == DnsRecordType::Txt
            && record.name == "_acme-challenge.share.acme.com"
            && record.value == "dcv-txt-value"
    }));
}

#[pollster::test]
async fn create_conflict_1406_maps_to_already_exists() {
    let (http, _rx) = scripted(vec![(409, error_body(1406, "Duplicate custom hostname"))]);
    let err = adapter(http)
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .unwrap_err();
    assert_eq!(err, CustomHostnameError::AlreadyExists);
}

// --- get ------------------------------------------------------------------

#[pollster::test]
async fn get_reads_the_list_and_picks_the_exact_hostname() {
    let (http, rx) = scripted(vec![(200, list(HOSTNAME_PENDING))]);
    let found = CloudflareSaas::new(http.clone(), config_with_cname(None))
        .get("Share.Acme.COM.")
        .await
        .expect("reads")
        .expect("found");
    assert_eq!(found.id, HOSTNAME_ID);
    assert_eq!(found.hostname, "share.acme.com");
    assert_eq!(found.status, ProviderStatus::Pending);

    let captured = rx.try_recv().expect("one request");
    assert_eq!(captured.method, "GET");
    assert_eq!(
        captured.uri,
        "https://api.cloudflare.com/client/v4/zones/a1b2c3d4e5f6/custom_hostnames?hostname=share.acme.com&per_page=50"
    );
    assert_eq!(
        captured.headers.get("authorization").unwrap(),
        format!("Bearer {DUMMY_TOKEN}").as_str()
    );
}

/// The list endpoint returns one page per call, so a filter matching on a
/// later page would silently read as absent — and `delete` would report
/// success for a claim it never found. When the exact name is not on the
/// page but the filter matched more pages, the lookup fails closed.
#[pollster::test]
async fn a_name_off_the_first_page_fails_closed() {
    // The one page carries no exact match, and the filter matched a second
    // page: absence cannot be established from here, so the lookup refuses.
    let off_page = list(HOSTNAME_PENDING)
        .replace("share.acme.com", "other.acme.com")
        .replace("\"total_pages\":1", "\"total_pages\":2");

    let (http, _rx) = scripted(vec![(200, off_page.clone())]);
    let err = adapter(http).get("share.acme.com").await.unwrap_err();
    assert!(matches!(err, CustomHostnameError::Provider(_)), "{err}");

    // `delete` must not turn a lookup it could not complete into success.
    let (http, rx) = scripted(vec![(200, off_page)]);
    let err = adapter(http).delete("share.acme.com").await.unwrap_err();
    assert!(matches!(err, CustomHostnameError::Provider(_)), "{err}");
    assert_eq!(rx.try_recv().expect("the list lookup").method, "GET");
    assert!(rx.try_recv().is_err(), "no DELETE was sent");
}

#[pollster::test]
async fn get_absent_is_none() {
    let (http, _rx) = scripted(vec![(200, LIST_EMPTY.to_owned())]);
    let found = adapter(http).get("share.acme.com").await.expect("reads");
    assert!(found.is_none());
}

#[pollster::test]
async fn get_active_is_live_with_no_validation_records() {
    let (http, _rx) = scripted(vec![(200, list(HOSTNAME_ACTIVE))]);
    let found = adapter(http)
        .get("share.acme.com")
        .await
        .expect("reads")
        .expect("found");
    assert!(found.is_live());
    assert_eq!(found.certificate, CertificateStatus::Active);
    assert!(
        found.validation.is_empty(),
        "a live hostname has nothing to publish: {:?}",
        found.validation
    );
}

#[pollster::test]
async fn get_certificate_timeout_is_a_failure_with_the_reason() {
    let (http, _rx) = scripted(vec![(200, list(HOSTNAME_CERT_TIMED_OUT))]);
    let found = adapter(http)
        .get("share.acme.com")
        .await
        .expect("reads")
        .expect("found");
    assert_eq!(
        found.certificate,
        CertificateStatus::Failed {
            reason: "Certificate validation timed out".to_owned()
        }
    );
    assert!(!found.is_live());
}

// --- delete ---------------------------------------------------------------

#[pollster::test]
async fn delete_looks_the_id_up_then_deletes_it() {
    let (http, rx) = scripted(vec![
        (200, list(HOSTNAME_PENDING)),
        (200, DELETE_OK.to_owned()),
    ]);
    adapter(http)
        .delete("share.acme.com")
        .await
        .expect("deletes");

    let first = rx.try_recv().expect("the list lookup");
    assert_eq!(first.method, "GET");
    assert!(first.uri.contains("?hostname=share.acme.com&per_page=50"));
    let second = rx.try_recv().expect("the delete");
    assert_eq!(second.method, "DELETE");
    assert_eq!(
        second.uri,
        format!(
            "https://api.cloudflare.com/client/v4/zones/a1b2c3d4e5f6/custom_hostnames/{HOSTNAME_ID}"
        )
    );
}

#[pollster::test]
async fn delete_gone_between_lookup_and_delete_is_ok() {
    // A 404 on the DELETE, and the provider's own 1436 code on a 400: the
    // wanted end state either way.
    for (status, body) in [
        (404u16, error_body(0, "missing")),
        (400, error_body(1436, "missing")),
    ] {
        let (http, rx) = scripted(vec![(200, list(HOSTNAME_PENDING)), (status, body)]);
        adapter(http)
            .delete("share.acme.com")
            .await
            .expect("already gone");
        assert_eq!(rx.try_recv().expect("the list lookup").method, "GET");
        assert_eq!(rx.try_recv().expect("the delete").method, "DELETE");
    }
}

#[pollster::test]
async fn an_unsafe_provider_id_is_a_provider_error() {
    // The provider's id is interpolated into the URL path; one that is not
    // a safe segment is refused rather than sent.
    let bad = HOSTNAME_PENDING.replace(HOSTNAME_ID, "id/../elsewhere");
    let (http, rx) = scripted(vec![(200, list(&bad))]);
    let err = adapter(http).delete("share.acme.com").await.unwrap_err();
    assert!(matches!(err, CustomHostnameError::Provider(_)), "{err}");
    assert_eq!(rx.try_recv().expect("the list lookup").method, "GET");
    assert!(rx.try_recv().is_err(), "no DELETE was sent");
}

#[pollster::test]
async fn delete_absent_sends_no_delete() {
    let (http, rx) = scripted(vec![(200, LIST_EMPTY.to_owned())]);
    adapter(http)
        .delete("share.acme.com")
        .await
        .expect("idempotent");
    let only = rx.try_recv().expect("the list lookup");
    assert_eq!(only.method, "GET");
    assert!(rx.try_recv().is_err(), "no DELETE was sent");
}

// --- refresh --------------------------------------------------------------

#[pollster::test]
async fn refresh_patches_with_the_same_method() {
    let (http, rx) = scripted(vec![
        (200, list(HOSTNAME_PENDING_TXT)),
        (202, single(HOSTNAME_PENDING_TXT)),
    ]);
    let refreshed = adapter(http)
        .refresh("share.acme.com")
        .await
        .expect("refreshes");
    assert_eq!(refreshed.id, "1f9ab2c3-1111-4222-8333-444455556666");

    let first = rx.try_recv().expect("the list lookup");
    assert_eq!(first.method, "GET");
    let second = rx.try_recv().expect("the patch");
    assert_eq!(second.method, "PATCH");
    assert_eq!(
        second.uri,
        "https://api.cloudflare.com/client/v4/zones/a1b2c3d4e5f6/custom_hostnames/1f9ab2c3-1111-4222-8333-444455556666"
    );
    let body: serde_json::Value = serde_json::from_str(&second.body).unwrap();
    assert_eq!(
        body["ssl"]["method"], "txt",
        "the same method it was created with"
    );
    assert_eq!(body["ssl"]["type"], "dv");
}

#[pollster::test]
async fn refresh_absent_is_not_found() {
    let (http, _rx) = scripted(vec![(200, LIST_EMPTY.to_owned())]);
    let err = adapter(http).refresh("share.acme.com").await.unwrap_err();
    assert_eq!(err, CustomHostnameError::NotFound);
}

// --- error mapping --------------------------------------------------------

#[pollster::test]
async fn unauthorized_code_10000_maps_to_unauthorized() {
    let (http, _rx) = scripted(vec![(401, error_body(10_000, "Authentication error"))]);
    let err = adapter(http)
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .unwrap_err();
    assert_eq!(err, CustomHostnameError::Unauthorized);
}

#[pollster::test]
async fn forbidden_quota_1405_maps_to_rejected() {
    let (http, _rx) = scripted(vec![(
        403,
        error_body(1405, "You have exceeded your plan quota"),
    )]);
    let err = adapter(http)
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .unwrap_err();
    match err {
        CustomHostnameError::Rejected(message) => {
            assert!(message.contains("1405"), "{message}");
            assert!(message.contains("exceeded your plan quota"), "{message}");
        }
        other => panic!("wrong error: {other}"),
    }
}

#[pollster::test]
async fn not_found_404_maps_to_not_found() {
    let (http, _rx) = scripted(vec![(404, error_body(1436, "No route for that URI"))]);
    let err = adapter(http)
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .unwrap_err();
    assert_eq!(err, CustomHostnameError::NotFound);
}

#[pollster::test]
async fn rate_limited_429_maps_to_rate_limited() {
    let (http, _rx) = scripted(vec![(429, error_body(0, "Too many requests"))]);
    let err = adapter(http)
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .unwrap_err();
    assert_eq!(err, CustomHostnameError::RateLimited);
}

#[pollster::test]
async fn server_error_500_maps_to_provider() {
    let (http, _rx) = scripted(vec![(500, "boom".to_owned())]);
    let err = adapter(http)
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .unwrap_err();
    assert!(matches!(err, CustomHostnameError::Provider(_)), "{err}");
}

#[pollster::test]
async fn a_garbage_success_body_maps_to_provider() {
    let (http, _rx) = scripted(vec![(200, "not json at all".to_owned())]);
    let err = adapter(http)
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .unwrap_err();
    assert!(matches!(err, CustomHostnameError::Provider(_)), "{err}");
}

#[pollster::test]
async fn a_transport_failure_maps_to_transport() {
    let err = CloudflareSaas::new(Arc::new(FailingHttp), config())
        .create(&HostnameClaim::new("share.acme.com"))
        .await
        .unwrap_err();
    assert!(matches!(err, CustomHostnameError::Transport(_)), "{err}");
}

// --- refusals and degraded mode -------------------------------------------

#[pollster::test]
async fn refused_hostnames_never_reach_the_provider() {
    let cases = [
        ("acme.com", HostnameRefusal::Apex),
        ("192.0.2.1", HostnameRefusal::IpLiteral),
        ("*.acme.com", HostnameRefusal::Wildcard),
        ("share.cratefield.app", HostnameRefusal::OwnZone),
    ];
    for (raw, refusal) in cases {
        let (http, _rx) = scripted(Vec::new());
        let err = adapter(http.clone())
            .create(&HostnameClaim::new(raw))
            .await
            .unwrap_err();
        assert_eq!(err, CustomHostnameError::Refused(refusal), "{raw}");
        assert_eq!(
            http.calls.load(Ordering::SeqCst),
            0,
            "{raw}: no request may leave the process"
        );
    }
}

#[pollster::test]
async fn not_configured_answers_every_method_without_a_request() {
    let (http, _rx) = scripted(Vec::new());
    let hostnames = CloudflareSaas::not_configured(http.clone());
    assert!(!hostnames.is_configured());
    assert_eq!(
        hostnames
            .create(&HostnameClaim::new("share.acme.com"))
            .await
            .unwrap_err(),
        CustomHostnameError::NotConfigured
    );
    assert_eq!(
        hostnames.get("share.acme.com").await.unwrap_err(),
        CustomHostnameError::NotConfigured
    );
    assert_eq!(
        hostnames.delete("share.acme.com").await.unwrap_err(),
        CustomHostnameError::NotConfigured
    );
    assert_eq!(
        hostnames.refresh("share.acme.com").await.unwrap_err(),
        CustomHostnameError::NotConfigured
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
}

#[pollster::test]
async fn an_unsafe_zone_id_degrades_to_not_configured() {
    let (http, _rx) = scripted(Vec::new());
    let mut config = config();
    config.zone_id = "zone/id".to_owned();
    let hostnames = CloudflareSaas::new(http.clone(), config);
    assert!(!hostnames.is_configured());
    assert_eq!(
        hostnames.get("share.acme.com").await.unwrap_err(),
        CustomHostnameError::NotConfigured
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
}

// --- configuration --------------------------------------------------------

#[test]
fn from_vars_requires_every_required_value() {
    let present = || Some("value".to_owned());
    assert!(CloudflareSaasConfig::from_vars(None, present(), present(), None).is_none());
    assert!(CloudflareSaasConfig::from_vars(present(), None, present(), None).is_none());
    assert!(CloudflareSaasConfig::from_vars(present(), present(), None, None).is_none());
    // Blank is absent.
    assert!(
        CloudflareSaasConfig::from_vars(None, present(), present(), Some("  ".to_owned()))
            .is_none()
    );
    assert!(
        CloudflareSaasConfig::from_vars(Some(String::new()), present(), present(), None).is_none()
    );
}

#[test]
fn from_vars_rejects_a_zone_id_that_is_not_alphanumeric() {
    let present = || Some("cratefield.app".to_owned());
    // The zone id goes into a URL path: a slash or a dot-segment is a
    // misconfiguration, not a path to interpolate.
    for bad in ["zone/id", "../zones", "zone id", "zone.id"] {
        assert!(
            CloudflareSaasConfig::from_vars(
                Some(bad.to_owned()),
                present(),
                Some(DUMMY_TOKEN.to_owned()),
                None,
            )
            .is_none(),
            "{bad:?}"
        );
    }
}

#[test]
fn from_vars_builds_a_config_with_an_optional_cname_target() {
    let built = CloudflareSaasConfig::from_vars(
        Some("a1b2c3d4e5f6".to_owned()),
        Some("cratefield.app".to_owned()),
        Some(DUMMY_TOKEN.to_owned()),
        Some("origin.cratefield.app".to_owned()),
    )
    .expect("all required present");
    assert_eq!(built.zone_id, "a1b2c3d4e5f6");
    assert_eq!(built.cname_target.as_deref(), Some("origin.cratefield.app"));

    let no_target = CloudflareSaasConfig::from_vars(
        Some("a1b2c3d4e5f6".to_owned()),
        Some("cratefield.app".to_owned()),
        Some(DUMMY_TOKEN.to_owned()),
        None,
    )
    .expect("all required present");
    assert_eq!(no_target.cname_target, None);
}

#[test]
fn the_environment_variable_names_are_stable() {
    assert_eq!(ZONE_ID_VAR, "CF_SAAS_ZONE_ID");
    assert_eq!(ZONE_NAME_VAR, "CF_SAAS_ZONE_NAME");
    assert_eq!(API_TOKEN_VAR, "CF_SAAS_API_TOKEN");
    assert_eq!(CNAME_TARGET_VAR, "CF_SAAS_CNAME_TARGET");
}

// --- the token never leaks -------------------------------------------------

#[test]
fn config_and_adapter_debug_redact_the_token() {
    let rendered = format!("{:?}", config());
    assert!(!rendered.contains(DUMMY_TOKEN), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");

    let hostnames = CloudflareSaas::new(Arc::new(FailingHttp), config());
    let rendered = format!("{hostnames:?}");
    assert!(!rendered.contains(DUMMY_TOKEN), "{rendered}");
}

#[pollster::test]
async fn every_error_display_omits_the_token() {
    let cases = vec![
        (401u16, error_body(10_000, "Authentication error")),
        (403, error_body(1405, "quota")),
        (409, error_body(1406, "duplicate")),
        (404, error_body(1436, "missing")),
        (429, error_body(0, "slow down")),
        (500, "oops".to_owned()),
        (200, "not json".to_owned()),
        // Provider text that echoes the request's credential must not
        // survive into the rendered error: a 400 envelope message and a
        // raw 500 body are the two ways provider words become a reason.
        (
            400,
            error_body(0, &format!("bad token Bearer {DUMMY_TOKEN}")),
        ),
        (500, format!("upstream echoed Bearer {DUMMY_TOKEN}")),
    ];
    for (status, body) in cases {
        let (http, _rx) = scripted(vec![(status, body)]);
        let err = adapter(http)
            .create(&HostnameClaim::new("share.acme.com"))
            .await
            .expect_err("must fail");
        let rendered = err.to_string();
        // An empty rendering omits the token and everything else; the
        // display has to remain useful for this absence to mean anything.
        assert!(
            rendered.len() > 8,
            "status {status} rendered an error that says nothing: {rendered:?}"
        );
        assert!(
            !rendered.contains(DUMMY_TOKEN),
            "status {status} leaked the token: {rendered}"
        );
    }
}
