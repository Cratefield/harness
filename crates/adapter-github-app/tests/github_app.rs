//! Acceptance tests for the GitHub App client (issue #623): the JWT's shape
//! and signature, installation-token caching and single flight, the `401`
//! replay, user-to-server access checks, and the "no key means no network"
//! contract.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use common::{EXPIRES_AT, RecordingHttp, StepClock, TEST_KEY, ok_json, response, token_body};
use cratefield_adapter_github_app::{GithubApp, GithubAppError, with_etag};
use http::{Request, StatusCode};
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier as _;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const APP_ID: u64 = 123_456;
const BASE: &str = "https://api.github.test";

/// A clock 30 minutes before the fixtures' expiry — so a freshly minted token
/// has ~25 minutes of cacheable life left.
fn anchor() -> i64 {
    OffsetDateTime::parse(EXPIRES_AT, &Rfc3339)
        .expect("fixture expiry parses")
        .unix_timestamp()
        - 30 * 60
}

fn app(http: Arc<RecordingHttp>, clock: Arc<StepClock>) -> GithubApp {
    GithubApp::new(APP_ID, Some(TEST_KEY.to_owned()), http, clock, BASE)
}

fn get(uri: &str) -> Request<Bytes> {
    Request::get(uri).body(Bytes::new()).expect("request")
}

fn header(request: &Request<Bytes>, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// 1. The JWT's shape and signature.

#[test]
fn the_app_jwt_verifies_against_the_apps_public_key() {
    let http = RecordingHttp::scripted(vec![]);
    let app = GithubApp::new(
        APP_ID,
        Some(TEST_KEY.to_owned()),
        http,
        Arc::new(StepClock::at(1_700_000_000)),
        BASE,
    );
    let jwt = app.app_jwt().expect("a signed JWT");

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "header.claims.signature");
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).expect("base64url");

    let header: Value = serde_json::from_slice(&decode(parts[0])).expect("header JSON");
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");

    let claims: Value = serde_json::from_slice(&decode(parts[1])).expect("claims JSON");
    assert_eq!(claims["iss"], APP_ID.to_string());
    assert_eq!(claims["iat"], 1_700_000_000_i64 - 60);
    assert_eq!(claims["exp"], 1_700_000_000_i64 + 540);

    // Verified the long way round, so the test does not just re-run the code
    // it is testing: derive the public key from the fixture's private PEM and
    // check RS256 over the signing input.
    let private = rsa::RsaPrivateKey::from_pkcs1_pem(TEST_KEY).expect("PKCS#1 fixture key");
    let verifying = VerifyingKey::<rsa::sha2::Sha256>::new(rsa::RsaPublicKey::from(private));
    let signature = RsaSignature::try_from(decode(parts[2]).as_slice()).expect("signature bytes");
    verifying
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .expect("the JWT verifies under the matching public key");
}

// ---------------------------------------------------------------------------
// 2. Single flight.

#[test]
fn two_concurrent_installation_token_calls_make_one_exchange() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted_yielding(vec![ok_json(token_body("ghs_ONE"))]);
    let app = app(Arc::clone(&http), clock);

    let (a, b) = pollster::block_on(futures_util::future::join(
        app.installation_token(42, None, None),
        app.installation_token(42, None, None),
    ));

    assert_eq!(a.expect("first").token, "ghs_ONE");
    assert_eq!(b.expect("second").token, "ghs_ONE");
    assert_eq!(http.count(), 1, "two concurrent cold calls, one exchange");
}

// ---------------------------------------------------------------------------
// 3. Caching, expiry and the 401 replay.

#[test]
fn an_expired_installation_token_is_refreshed_transparently() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_ONE")),
        ok_json(token_body("ghs_TWO")),
    ]);
    let app = app(Arc::clone(&http), Arc::clone(&clock));

    assert_eq!(
        pollster::block_on(app.installation_token(7, None, None))
            .expect("minted")
            .token,
        "ghs_ONE"
    );
    assert_eq!(http.count(), 1);

    clock.advance(60);
    assert_eq!(
        pollster::block_on(app.installation_token(7, None, None))
            .expect("cached")
            .token,
        "ghs_ONE"
    );
    assert_eq!(http.count(), 1, "reused within its lifetime");

    // The stored lifetime is expiry - 5 min - now = 25 minutes here.
    clock.advance(26 * 60);
    assert_eq!(
        pollster::block_on(app.installation_token(7, None, None))
            .expect("refreshed")
            .token,
        "ghs_TWO"
    );
    assert_eq!(http.count(), 2, "past the safety margin, a fresh exchange");
}

#[test]
fn scoped_tokens_do_not_share_a_cache_entry() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_ONE")),
        ok_json(token_body("ghs_TWO")),
    ]);
    let app = app(Arc::clone(&http), clock);
    let permissions = BTreeMap::from([("contents".to_owned(), "read".to_owned())]);

    let default = pollster::block_on(app.installation_token(4, None, None)).expect("default");
    let scoped =
        pollster::block_on(app.installation_token(4, Some(&permissions), None)).expect("scoped");
    assert_eq!(default.token, "ghs_ONE");
    assert_eq!(scoped.token, "ghs_TWO");
    assert_eq!(http.count(), 2, "a narrower scope is its own entry");

    let again = pollster::block_on(app.installation_token(4, Some(&permissions), None))
        .expect("cached scoped");
    assert_eq!(again.token, "ghs_TWO");
    assert_eq!(http.count(), 2);
}

#[test]
fn an_empty_scope_is_not_the_unscoped_entry() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_NARROW")),
        ok_json(token_body("ghs_ALL")),
    ]);
    let app = app(Arc::clone(&http), clock);
    let empty: BTreeMap<String, String> = BTreeMap::new();

    // `Some(&empty)` sends `"permissions": {}` — "grant nothing" — which is
    // not the same request as `None`, which omits the field.
    let narrow = pollster::block_on(app.installation_token(4, Some(&empty), None)).expect("narrow");
    let all = pollster::block_on(app.installation_token(4, None, None)).expect("unscoped");
    assert_eq!(narrow.token, "ghs_NARROW");
    assert_eq!(all.token, "ghs_ALL", "not the narrow token");
    assert_eq!(http.count(), 2, "an empty scope is its own cache entry");

    assert_eq!(
        String::from_utf8_lossy(http.requests()[0].body()),
        r#"{"permissions":{}}"#
    );
    assert_eq!(
        String::from_utf8_lossy(http.requests()[1].body()),
        "{}",
        "the unscoped request omits both fields"
    );

    // And each stays cached in its own entry.
    pollster::block_on(app.installation_token(4, Some(&empty), None)).expect("cached narrow");
    pollster::block_on(app.installation_token(4, None, None)).expect("cached unscoped");
    assert_eq!(http.count(), 2);
}

#[test]
fn a_401_mints_one_fresh_token_and_replays_once() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_ONE")),
        response(401, "", &[]),
        ok_json(token_body("ghs_TWO")),
        response(200, r#"{"ok":true}"#, &[]),
    ]);
    let app = app(Arc::clone(&http), clock);

    let answer = pollster::block_on(app.request(99, get("/repos/acme/widgets"))).expect("answered");
    assert_eq!(answer.status(), StatusCode::OK);
    assert_eq!(
        http.count(),
        4,
        "exchange, refused request, re-mint, replay"
    );
    assert!(http.authorization(1).expect("first").ends_with("ghs_ONE"));
    assert!(
        http.authorization(3).expect("replay").ends_with("ghs_TWO"),
        "the replay carried the fresh token"
    );
}

#[test]
fn a_second_consecutive_401_is_not_retried() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_ONE")),
        response(401, "", &[]),
        ok_json(token_body("ghs_TWO")),
        response(401, "", &[]),
    ]);
    let app = app(Arc::clone(&http), clock);

    let answer = pollster::block_on(app.request(99, get("/repos/acme/widgets"))).expect("answered");
    assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        http.count(),
        4,
        "exactly one replay, then the 401 is returned"
    );
}

// ---------------------------------------------------------------------------
// 4. User-to-server access checks.

#[test]
fn user_can_access_installation_follows_pagination() {
    let clock = Arc::new(StepClock::at(anchor()));
    let link = "<https://api.github.test/user/installations?per_page=100&page=2>; rel=\"next\"";
    let http = RecordingHttp::scripted(vec![
        response(
            200,
            include_str!("fixtures/user-installations-page-1.json"),
            &[("link", link)],
        ),
        response(
            200,
            include_str!("fixtures/user-installations-page-2.json"),
            &[],
        ),
    ]);
    let app = app(Arc::clone(&http), clock);

    let found = pollster::block_on(app.user_can_access_installation("ghu_USER", 22_222_222))
        .expect("answered");
    assert!(found, "the installation is on the second page");
    assert_eq!(http.count(), 2, "the Link header was followed");
    assert!(http.authorization(0).expect("first").contains("ghu_USER"));
}

#[test]
fn user_can_access_installation_reports_an_absent_installation() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![response(
        200,
        include_str!("fixtures/user-installations-page-1.json"),
        &[],
    )]);
    let app = app(Arc::clone(&http), clock);

    let found = pollster::block_on(app.user_can_access_installation("ghu_USER", 99_999_999))
        .expect("answered");
    assert!(!found, "not among the user's installations");
    assert_eq!(http.count(), 1, "no next link, so one page");
}

#[test]
fn user_can_access_installation_fails_closed_on_a_foreign_next_link() {
    let clock = Arc::new(StepClock::at(anchor()));
    let link = "<https://evil.example.com/user/installations?page=2>; rel=\"next\"";
    let http = RecordingHttp::scripted(vec![response(
        200,
        include_str!("fixtures/user-installations-page-1.json"),
        &[("link", link)],
    )]);
    let app = app(Arc::clone(&http), clock);

    // The id is not on page 1, and the next page is not on the API origin, so
    // the walk stops and the answer is "no access" rather than a grant.
    let found = pollster::block_on(app.user_can_access_installation("ghu_USER", 99_999_999))
        .expect("answered");
    assert!(!found, "an unverifiable walk must not grant access");
    assert_eq!(http.count(), 1, "the foreign page was never fetched");
}

// ---------------------------------------------------------------------------
// 5. Configuration gates.

#[test]
fn an_unconfigured_app_makes_no_http_call() {
    let clock = Arc::new(StepClock::at(0));
    let http = RecordingHttp::scripted(vec![]);

    for key in [None, Some(String::new()), Some("   ".to_owned())] {
        let app = GithubApp::new(APP_ID, key, http.clone(), clock.clone(), BASE);
        assert!(!app.is_configured());
        assert!(matches!(app.app_jwt(), Err(GithubAppError::NotConfigured)));
        assert!(matches!(
            pollster::block_on(app.installation_token(1, None, None)),
            Err(GithubAppError::NotConfigured)
        ));
        assert!(matches!(
            pollster::block_on(app.request(1, get("/x"))),
            Err(GithubAppError::NotConfigured)
        ));
        // `paginate` goes through `request`, so it is gated too.
        assert!(matches!(
            pollster::block_on(app.paginate(1, "/x", 2)),
            Err(GithubAppError::NotConfigured)
        ));
    }
    assert_eq!(http.count(), 0, "nothing reached the network");
}

/// The two user-to-server flows authenticate with the client credentials and
/// the caller's own token, not the app's private key, so a keyless client
/// runs them. Only the flows that mint an app JWT need the key.
#[test]
fn the_user_flows_need_no_app_key() {
    let http = RecordingHttp::scripted(vec![
        response(200, include_str!("fixtures/user-token.json"), &[]),
        response(
            200,
            include_str!("fixtures/user-installations-page-1.json"),
            &[],
        ),
    ]);
    let app = GithubApp::new(APP_ID, None, http.clone(), Arc::new(StepClock::at(0)), BASE);
    assert!(!app.is_configured());

    let token = pollster::block_on(app.exchange_user_code("cid", "secret", "code", None))
        .expect("the code exchange needs no app key");
    assert_eq!(
        token.access_token,
        "ghu_FIXTURE000000000000000000000000000000"
    );

    let found = pollster::block_on(app.user_can_access_installation("ghu_USER", 11_111_111))
        .expect("the access check needs no app key");
    assert!(found, "the installation is on the first page");
    assert_eq!(http.count(), 2, "both flows reached GitHub");
}

#[test]
fn an_invalid_key_is_reported_without_echoing_it() {
    let http = RecordingHttp::scripted(vec![]);
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nnot-actually-a-key\n-----END RSA PRIVATE KEY-----";
    let app = GithubApp::new(
        APP_ID,
        Some(pem.to_owned()),
        http.clone(),
        Arc::new(StepClock::at(0)),
        BASE,
    );
    assert!(!app.is_configured());

    let error = app.app_jwt().expect_err("a malformed key is refused");
    assert!(matches!(error, GithubAppError::InvalidKey));
    let printed = format!("{error}");
    assert!(!printed.contains("not-actually-a-key"), "{printed}");
    assert!(!printed.contains("PRIVATE KEY"), "{printed}");

    let printed = format!("{app:?}");
    assert!(!printed.contains("not-actually-a-key"), "{printed}");
    assert!(printed.contains("configured: false"), "{printed}");
    assert_eq!(http.count(), 0);
}

// ---------------------------------------------------------------------------
// 6. Requests: headers, ETag, rate limit, relative URIs.

#[test]
fn a_request_carries_the_documented_headers_and_reads_the_rate_limit() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_ONE")),
        response(
            200,
            "{}",
            &[
                ("x-ratelimit-remaining", "4999"),
                ("x-ratelimit-reset", "1900000000"),
                ("retry-after", "30"),
            ],
        ),
    ]);
    let app = app(Arc::clone(&http), clock);

    // A root-relative URI resolves against the API base.
    let answer = pollster::block_on(app.request(5, get("/repos/acme/widgets"))).expect("answered");
    assert_eq!(answer.rate_limit.remaining, Some(4999));
    assert_eq!(
        answer.rate_limit.reset.expect("reset").unix_timestamp(),
        1_900_000_000
    );
    assert_eq!(answer.rate_limit.retry_after, Some(Duration::from_secs(30)));

    let sent = &http.requests()[1];
    assert_eq!(
        sent.uri().to_string(),
        "https://api.github.test/repos/acme/widgets"
    );
    assert_eq!(
        header(sent, "accept").as_deref(),
        Some("application/vnd.github+json")
    );
    assert_eq!(
        header(sent, "x-github-api-version").as_deref(),
        Some("2022-11-28")
    );
    assert_eq!(
        header(sent, "user-agent").as_deref(),
        Some("cratefield-adapter-github-app")
    );
    assert!(
        header(sent, "authorization")
            .expect("auth")
            .ends_with("ghs_ONE")
    );
}

#[test]
fn a_conditional_request_surfaces_304_and_the_etag() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_ONE")),
        response(304, "", &[("etag", "\"abc123\"")]),
    ]);
    let app = app(Arc::clone(&http), clock);

    let request = with_etag(get("/repos/acme/widgets"), "\"abc123\"");
    let answer = pollster::block_on(app.request(1, request)).expect("answered");

    assert!(answer.not_modified());
    assert_eq!(answer.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(answer.etag(), Some("\"abc123\""));
    assert_eq!(
        header(&http.requests()[1], "if-none-match").as_deref(),
        Some("\"abc123\"")
    );
}

#[test]
fn a_callers_own_authorization_is_not_overwritten() {
    // A caller-supplied credential means no installation token is minted.
    let http = RecordingHttp::scripted(vec![response(200, "{}", &[])]);
    let app = app(Arc::clone(&http), Arc::new(StepClock::at(anchor())));

    let request = Request::get("/x")
        .header("authorization", "Bearer ghu_CALLER")
        .body(Bytes::new())
        .expect("request");
    let answer = pollster::block_on(app.request(1, request)).expect("answered");
    assert_eq!(answer.status(), StatusCode::OK);
    assert_eq!(http.count(), 1, "no token exchange");
    assert_eq!(
        header(&http.requests()[0], "authorization").as_deref(),
        Some("Bearer ghu_CALLER")
    );
}

#[test]
fn a_cross_origin_next_link_is_not_followed() {
    let clock = Arc::new(StepClock::at(anchor()));
    let link = "<https://evil.example.com/steal>; rel=\"next\"";
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_ONE")),
        response(200, "{}", &[("link", link)]),
        response(200, "{}", &[]),
    ]);
    let app = app(Arc::clone(&http), clock);

    let pages = pollster::block_on(app.paginate(3, "/items?page=1", 5)).expect("paged");
    assert_eq!(pages.len(), 1, "a foreign next link ends the walk");
    assert_eq!(http.count(), 2, "the exchange and one page, nothing more");
    assert!(
        http.requests()
            .iter()
            .all(|request| request.uri().host() == Some("api.github.test")),
        "no request carried the installation token off-origin: {:?}",
        http.requests()
            .iter()
            .map(|request| request.uri().to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn paginate_stops_at_the_cap() {
    let clock = Arc::new(StepClock::at(anchor()));
    let link = "<https://api.github.test/items?page=2>; rel=\"next\"";
    let http = RecordingHttp::scripted(vec![
        ok_json(token_body("ghs_ONE")),
        response(200, "{}", &[("link", link)]),
        response(200, "{}", &[("link", link)]),
        response(200, "{}", &[("link", link)]),
    ]);
    let app = app(Arc::clone(&http), clock);

    let pages = pollster::block_on(app.paginate(3, "/items?page=1", 2)).expect("paged");
    assert_eq!(pages.len(), 2, "at most max_pages");
}

// ---------------------------------------------------------------------------
// 7. User-to-server code exchange.

#[test]
fn exchange_user_code_returns_the_user_token() {
    let http = RecordingHttp::scripted(vec![response(
        200,
        include_str!("fixtures/user-token.json"),
        &[],
    )]);
    let app = app(Arc::clone(&http), Arc::new(StepClock::at(0)));

    let token = pollster::block_on(app.exchange_user_code(
        "client-id",
        "client-secret",
        "the-code",
        Some("https://app.test/callback"),
    ))
    .expect("exchanged");

    assert_eq!(
        token.access_token,
        "ghu_FIXTURE000000000000000000000000000000"
    );
    assert_eq!(token.expires_in, Some(28_800));
    assert_eq!(token.token_type.as_deref(), Some("bearer"));
    assert!(token.refresh_token.is_some());
    assert_eq!(token.expose(), token.access_token);

    // The endpoint lives on the web host, not the API host.
    let sent = &http.requests()[0];
    assert_eq!(sent.uri().host(), Some("github.com"));
    assert_eq!(sent.uri().path(), "/login/oauth/access_token");
    let body = String::from_utf8_lossy(sent.body());
    assert!(
        body.contains("client-secret"),
        "the secret rides in the body"
    );
}

#[test]
fn exchange_user_code_maps_a_github_error_without_echoing_secrets() {
    let http = RecordingHttp::scripted(vec![response(
        200,
        include_str!("fixtures/oauth-error.json"),
        &[],
    )]);
    let app = app(Arc::clone(&http), Arc::new(StepClock::at(0)));

    let error = pollster::block_on(app.exchange_user_code(
        "client-id",
        "super-secret-value",
        "bad-code",
        None,
    ))
    .expect_err("GitHub refused");
    match &error {
        GithubAppError::OAuth(code) => assert_eq!(code, "bad_verification_code"),
        other => panic!("expected an OAuth error, got {other:?}"),
    }
    let printed = format!("{error}");
    assert!(!printed.contains("super-secret-value"), "{printed}");
    assert!(!printed.contains("client-id"), "{printed}");
}

#[test]
fn exchange_user_code_reports_a_non_json_failure_as_a_status() {
    // A gateway answered, not GitHub: the body is HTML, and the caller must
    // still get the status and the rate-limit headers rather than a decode
    // error about markup.
    let http = RecordingHttp::scripted(vec![response(
        502,
        "<html><body>bad gateway</body></html>",
        &[("x-ratelimit-remaining", "7")],
    )]);
    let app = app(Arc::clone(&http), Arc::new(StepClock::at(0)));

    let error = pollster::block_on(app.exchange_user_code("cid", "secret", "code", None))
        .expect_err("a 502 is not a token");
    match &error {
        GithubAppError::Status { status, rate_limit } => {
            assert_eq!(*status, StatusCode::BAD_GATEWAY);
            assert_eq!(rate_limit.remaining, Some(7));
        }
        other => panic!("expected Status, got {other:?}"),
    }
    assert!(!format!("{error}").contains("bad gateway"), "{error}");
}

#[test]
fn exchange_user_code_can_target_another_web_host() {
    let http = RecordingHttp::scripted(vec![response(
        200,
        include_str!("fixtures/user-token.json"),
        &[],
    )]);
    let app = app(Arc::clone(&http), Arc::new(StepClock::at(0)))
        .with_web_base("https://github.enterprise.test");
    pollster::block_on(app.exchange_user_code("cid", "secret", "code", None)).expect("exchanged");
    assert_eq!(
        http.requests()[0].uri().host(),
        Some("github.enterprise.test")
    );
}

// ---------------------------------------------------------------------------
// 8. The fixture itself.

#[test]
fn the_installation_token_fixture_parses() {
    let clock = Arc::new(StepClock::at(anchor()));
    let http = RecordingHttp::scripted(vec![response(
        200,
        include_str!("fixtures/installation-token.json"),
        &[],
    )]);
    let app = app(Arc::clone(&http), clock);
    let token = pollster::block_on(app.installation_token(1, None, None)).expect("minted");
    assert_eq!(token.token, "ghs_FIXTURE000000000000000000000000000000");
    assert_eq!(
        token.permissions.get("contents").map(String::as_str),
        Some("read")
    );
    assert_eq!(
        token.permissions.get("issues").map(String::as_str),
        Some("write")
    );
    assert_eq!(
        token.expires_at.unix_timestamp(),
        OffsetDateTime::parse(EXPIRES_AT, &Rfc3339)
            .expect("expiry")
            .unix_timestamp()
    );
}
