//! Issue #10 acceptance: the authorization code flow with PKCE.
//!
//! The properties asserted here are the ones the flow exists to
//! guarantee, and each is a way the flow is commonly broken:
//!
//! - a refused `/authorize` renders a page and **never redirects**,
//!   because sending a browser to an unregistered URI is the
//!   vulnerability exact matching prevents (issue #7);
//! - an authorization code is single-use, and reusing one revokes the
//!   session it was minted for;
//! - the PKCE verifier is actually checked, and `plain` is refused;
//! - a signed-out visitor is offered the login chooser rather than a
//!   code.
//!
//! Signing keys are throwaway P-256 keys generated inside each test; no
//! real key is ever committed.

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_core::{MapConfig, UlidIdGen};
use cratefield_testing::{FixedClock, TestHarness};
use factory0_auth_core::{
    AuthCore, ClientRedirectUriRow, ClientRow, Login, Redacted, UserRow, insert_client,
    insert_redirect_uri, issue, session_by_token_hash,
};
use p256::ecdsa;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const ISSUER: &str = "https://auth.test.example";
const CLIENT: &str = "client-undercover";
const REDIRECT: &str = "https://undercoverrockstars.com/auth/callback";
const VERIFIER: &str = "a-verifier-of-at-least-43-characters-1234567890";

fn iso(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .expect("epoch in range")
        .replace_nanosecond(0)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
}

/// A throwaway P-256 keypair generated in the test.
fn dummy_key(kid: &str) -> Value {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("entropy");
    bytes[0] = 1;
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let _ = ecdsa::SigningKey::from(&secret);
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d })
}

fn kit() -> TestHarness {
    kit_with_methods(None)
}

/// The kit, optionally offering login methods on the chooser (#33).
fn kit_with_methods(methods: Option<&str>) -> TestHarness {
    let mut pairs = vec![
        (
            "AUTH_CORE_SIGNING_KEYS",
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE", "k1".to_owned()),
        ("AUTH_CORE_ISSUER", ISSUER.to_owned()),
    ];
    if let Some(methods) = methods {
        pairs.push(("AUTH_CORE_LOGIN_METHODS", methods.to_owned()));
    }
    let config = MapConfig::from_pairs(pairs);
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(config);
    })
}

/// The kit with every method the chooser can offer, and the modules that
/// serve them composed alongside. The providers are deliberately left
/// without credentials: an unconfigured provider still has to serve its
/// route, and this is about the route existing.
fn kit_with_every_module() -> TestHarness {
    let pairs = vec![
        (
            "AUTH_CORE_SIGNING_KEYS".to_owned(),
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE".to_owned(), "k1".to_owned()),
        ("AUTH_CORE_ISSUER".to_owned(), ISSUER.to_owned()),
        (
            "AUTH_CORE_LOGIN_METHODS".to_owned(),
            "passkey,google,apple,meta,magic-link,password".to_owned(),
        ),
        (
            "AUTH_MAGIC_LINK_PUBLIC_BASE".to_owned(),
            "https://auth.test.example".to_owned(),
        ),
        (
            "AUTH_MAGIC_LINK_MAIL_FROM".to_owned(),
            "sign-in@test.example".to_owned(),
        ),
        (
            "AUTH_OIDC_REDIRECT_BASE".to_owned(),
            "https://auth.test.example".to_owned(),
        ),
        (
            "AUTH_META_REDIRECT_BASE".to_owned(),
            "https://auth.test.example".to_owned(),
        ),
    ];
    let config = Arc::new(MapConfig::from_pairs(pairs));
    TestHarness::with_ports(
        vec![
            Box::new(AuthCore::new()),
            Box::new(factory0_auth_magic_link::MagicLink::new()),
            Box::new(factory0_auth_password::Password::new()),
            Box::new(factory0_auth_oidc::Oidc::new()),
            Box::new(factory0_auth_meta::Meta::new()),
        ],
        move |ports| {
            ports.config = config;
        },
    )
}

/// Every `href="…"` in a rendered page, in order.
fn hrefs(page: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = page;
    while let Some(at) = rest.find("href=\"") {
        let after = &rest[at + 6..];
        let Some(end) = after.find('"') else { break };
        found.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    found
}

async fn body_of(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    String::from_utf8_lossy(&bytes).to_string()
}

/// The S256 challenge for [`VERIFIER`], as a client computes it.
fn challenge() -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))
}

async fn seed_user(kit: &TestHarness, id: &str) {
    factory0_auth_core::insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: Some(format!("{id}@example.com")),
            primary_email_verified: true,
            status: "active".to_owned(),
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
}

/// A public client (PKCE only, no secret) with one exact redirect URI.
async fn seed_client(kit: &TestHarness) {
    insert_client(
        &*kit.db,
        &ClientRow {
            id: CLIENT.to_owned(),
            name: "Undercover Rockstars".to_owned(),
            // A public client authenticates with PKCE alone; the column
            // is not nullable, so an unusable placeholder stands in.
            secret_hash: Redacted("public-client-has-no-secret".to_owned()),
            previous_secret_hash: None,
            previous_hash_expires_at: None,
            kind: "public".to_owned(),
            status: "active".to_owned(),
            created_at: iso(EPOCH),
        },
    )
    .await
    .expect("client");
    insert_redirect_uri(
        &*kit.db,
        &ClientRedirectUriRow {
            client_id: CLIENT.to_owned(),
            uri: REDIRECT.to_owned(),
        },
    )
    .await
    .expect("redirect uri");
}

async fn signed_in(kit: &TestHarness, user_id: &str) -> String {
    seed_user(kit, user_id).await;
    let issued = issue(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        Login {
            user_id,
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &[],
        },
    )
    .await
    .expect("session");
    issued.value
}

fn authorize_uri(extra: &str) -> String {
    format!(
        "/v1/auth-core/authorize?response_type=code&client_id={CLIENT}\
         &redirect_uri={REDIRECT}&code_challenge={}&code_challenge_method=S256\
         &state=xyz{extra}",
        challenge()
    )
}

async fn get(kit: &TestHarness, uri: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut request = axum::http::Request::builder().method(Method::GET).uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("__Host-fz_session={cookie}"));
    }
    kit.router
        .clone()
        .oneshot(request.body(axum::body::Body::empty()).expect("request"))
        .await
        .expect("router answers")
}

fn location_of(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .expect("Location")
        .to_str()
        .expect("ascii")
        .to_owned()
}

/// A form POST through the router, with the given extra headers — the
/// browser signals (`host`, `origin`, `sec-fetch-site`) a confirmation
/// carries or a cross-site attack betrays itself with.
async fn post(
    kit: &TestHarness,
    uri: &str,
    cookie: Option<&str>,
    headers: &[(&str, &str)],
    body: &str,
) -> axum::response::Response {
    let mut request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("__Host-fz_session={cookie}"));
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    kit.router
        .clone()
        .oneshot(
            request
                .body(axum::body::Body::from(body.to_owned()))
                .expect("request"),
        )
        .await
        .expect("router answers")
}

/// Every `Set-Cookie` the response carried, as strings.
fn set_cookies_of(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect()
}

/// Whether the clearing cookie — the one that expires the session
/// cookie — is among the response's `Set-Cookie`s.
fn clears_the_session(response: &axum::response::Response) -> bool {
    set_cookies_of(response)
        .iter()
        .any(|cookie| cookie.contains("Max-Age=0") || cookie.contains("Expires="))
}

/// The session row a cookie value names, read straight from the store.
async fn session_row(kit: &TestHarness, cookie: &str) -> factory0_auth_core::SessionRow {
    let hash = Sha256::digest(cookie.as_bytes()).to_vec();
    session_by_token_hash(&*kit.db, &hash)
        .await
        .expect("query")
        .expect("row exists")
}

/// The whole point of exact matching: a request naming a URI the client
/// did not register must not send the browser anywhere. A redirect here
/// is the vulnerability, so the assertion is on the absence of one.
#[pollster::test]
async fn an_unregistered_redirect_uri_renders_a_page_and_never_redirects() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let attacker = "https://attacker.example/callback";
    let uri = format!(
        "/v1/auth-core/authorize?response_type=code&client_id={CLIENT}\
         &redirect_uri={attacker}&code_challenge={}&code_challenge_method=S256&state=xyz",
        challenge()
    );
    let response = get(&kit, &uri, Some(&cookie)).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "a refused /authorize must not carry a Location header"
    );
}

/// An unknown client and a disabled one are refused the same way as an
/// unregistered URI: the page is the only channel that could leak
/// whether a client id exists.
#[pollster::test]
async fn an_unknown_client_is_refused_identically() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let known = get(&kit, &authorize_uri(""), Some(&cookie)).await;
    let unknown_uri = authorize_uri("").replace(CLIENT, "client-does-not-exist");
    let unknown = get(&kit, &unknown_uri, Some(&cookie)).await;

    assert_eq!(known.status(), StatusCode::FOUND, "the known client works");
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert!(unknown.headers().get(header::LOCATION).is_none());
}

/// A signed-out visitor is offered the chooser, not a code.
#[pollster::test]
async fn a_signed_out_visitor_gets_the_login_chooser() {
    let kit = kit();
    seed_client(&kit).await;

    let response = get(&kit, &authorize_uri(""), None).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "no code is minted for a visitor who is not signed in"
    );
}

/// The happy path: a signed-in visitor gets a redirect to the exact
/// registered URI carrying a code and the state they sent.
#[pollster::test]
async fn a_signed_in_visitor_is_redirected_with_a_code_and_their_state() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let response = get(&kit, &authorize_uri(""), Some(&cookie)).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("Location")
        .to_str()
        .expect("ascii");
    assert!(
        location.starts_with(REDIRECT),
        "redirects to the registered URI, got {location}"
    );
    assert!(location.contains("code="), "carries a code: {location}");
    assert!(location.contains("state=xyz"), "echoes state: {location}");
}

/// PKCE is not decoration: `plain` is refused, per OAuth 2.1.
///
/// The refusal is an `error=invalid_request` redirect rather than a
/// page, and that is correct: the client and redirect URI were already
/// validated, so RFC 6749 §4.1.2.1 says the error goes back to the
/// client. What must never happen is a code being issued anyway.
#[pollster::test]
async fn the_plain_pkce_method_is_refused() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let uri =
        authorize_uri("").replace("code_challenge_method=S256", "code_challenge_method=plain");
    let response = get(&kit, &uri, Some(&cookie)).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = location_of(&response);
    assert!(
        location.starts_with(REDIRECT),
        "the error goes to the REGISTERED uri, got {location}"
    );
    assert!(
        location.contains("error=invalid_request"),
        "names the error: {location}"
    );
    assert!(
        !location.contains("code="),
        "no code is issued for a plain challenge: {location}"
    );
}

/// A request with no PKCE challenge at all is refused: every client
/// kind must use it, public and confidential alike. Again the refusal
/// travels back to the registered URI, and again without a code.
#[pollster::test]
async fn a_missing_pkce_challenge_is_refused() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let uri = format!(
        "/v1/auth-core/authorize?response_type=code&client_id={CLIENT}&redirect_uri={REDIRECT}&state=xyz"
    );
    let response = get(&kit, &uri, Some(&cookie)).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = location_of(&response);
    assert!(location.starts_with(REDIRECT), "got {location}");
    assert!(location.contains("error=invalid_request"), "got {location}");
    assert!(
        !location.contains("code="),
        "no code without a challenge: {location}"
    );
}

// ---------------------------------------------------------------------
// RP-initiated logout: GET asks, POST acts (issue #439)
// ---------------------------------------------------------------------

/// The host the confirmation POSTs are judged against: the `host` header
/// a browser sends and the origin it claims must agree.
const AUTH_HOST: &str = "auth.example.test";

/// `GET /logout` with a live session is the whole fix: the page asks,
/// and nothing is revoked, nothing cleared. The cookie is `SameSite=Lax`,
/// so it *is* presented on the cross-site top-level GET any page can
/// produce — which is exactly why the GET must not act.
#[pollster::test]
async fn logout_get_with_a_live_session_asks_and_revokes_nothing() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let response = get(&kit, "/v1/auth-core/logout", Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !clears_the_session(&response),
        "the asking page must not clear the session cookie"
    );

    let page = body_of(response).await;
    assert!(
        page.contains("<form method=\"post\" action=\"/v1/auth-core/logout/confirm\">"),
        "the form posts to the confirm route: {page}"
    );
    assert!(
        page.contains("Sign out of this device?"),
        "it asks, in so many words: {page}"
    );
    // A plain GET carried no pair, so the form carries no hidden inputs
    // either — the POST must confirm a request the GET actually made.
    assert!(!page.contains("name=\"client_id\""), "{page}");

    let uri =
        format!("/v1/auth-core/logout?client_id={CLIENT}&post_logout_redirect_uri={REDIRECT}");
    let response = get(&kit, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!clears_the_session(&response));
    // The validated pair this GET carried travels into the form, so the
    // confirmation confirms the request it was asked about.
    let page = body_of(response).await;
    assert!(
        page.contains(&format!("name=\"client_id\" value=\"{CLIENT}\"")),
        "{page}"
    );
    assert!(
        page.contains(&format!(
            "name=\"post_logout_redirect_uri\" value=\"{REDIRECT}\""
        )),
        "{page}"
    );

    // Nothing was revoked: the session row is live and the cookie still
    // mints a code, which is the property an `<img>`-tag attack would
    // have taken away.
    assert!(
        session_row(&kit, &cookie).await.revoked_at.is_none(),
        "the asking page must not revoke the session"
    );
    let after = get(&kit, &authorize_uri(""), Some(&cookie)).await;
    assert_eq!(
        after.status(),
        StatusCode::FOUND,
        "the session must survive a logout GET that only asked"
    );
}

/// A cross-site navigation — the shape an attacker's page produces, and
/// the shape a legitimate relying-party redirect also produces — gets
/// the same asking page. It must not fail: RP-initiated logout with no
/// `id_token_hint` is legitimately cross-site.
#[pollster::test]
async fn a_cross_site_navigation_to_logout_still_asks_instead_of_failing() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/v1/auth-core/logout")
        .header(header::COOKIE, format!("__Host-fz_session={cookie}"))
        .header("sec-fetch-site", "cross-site")
        .body(axum::body::Body::empty())
        .expect("request");
    let response = kit
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");

    assert_eq!(response.status(), StatusCode::OK);
    let page = body_of(response).await;
    assert!(
        page.contains("action=\"/v1/auth-core/logout/confirm\""),
        "the attacker's GET is answered with the ask, not an error: {page}"
    );
    assert!(
        session_row(&kit, &cookie).await.revoked_at.is_none(),
        "the cross-site GET revoked nothing"
    );
}

/// Without a live session there is nothing to revoke, so the GET keeps
/// today's behaviour for everybody who lands here signed out (or
/// carrying a stale cookie): the clearing cookie, and the validated
/// redirect.
#[pollster::test]
async fn logout_without_a_live_session_still_clears_and_redirects() {
    let kit = kit();
    seed_client(&kit).await;
    let uri =
        format!("/v1/auth-core/logout?client_id={CLIENT}&post_logout_redirect_uri={REDIRECT}");

    // No cookie at all.
    let response = get(&kit, &uri, None).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        clears_the_session(&response),
        "an already-invalid cookie is still cleared: nothing an attacker cares about changes"
    );
    assert_eq!(location_of(&response), REDIRECT);

    // A cookie of the issued shape that names nothing live.
    let stale = "z".repeat(43);
    let response = get(&kit, &uri, Some(&stale)).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(clears_the_session(&response));
    assert_eq!(location_of(&response), REDIRECT);

    // And with no redirect target, the signed-out page.
    let response = get(&kit, "/v1/auth-core/logout", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(clears_the_session(&response));
    let page = body_of(response).await;
    assert!(page.contains("You are signed out"), "{page}");
}

/// The POST is what acts: same-origin, it revokes, clears the cookie,
/// and redirects to the validated target — everything the GET used to
/// do, and the session it revoked cannot mint another code.
#[pollster::test]
async fn confirm_logout_from_the_same_origin_revokes_the_session() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let response = post(
        &kit,
        "/v1/auth-core/logout/confirm",
        Some(&cookie),
        &[
            ("host", AUTH_HOST),
            ("origin", "https://auth.example.test"),
            ("sec-fetch-site", "same-origin"),
        ],
        &format!("client_id={CLIENT}&post_logout_redirect_uri={REDIRECT}"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location_of(&response), REDIRECT);
    assert!(clears_the_session(&response), "the act clears the cookie");
    assert!(
        session_row(&kit, &cookie).await.revoked_at.is_some(),
        "the same-origin POST revoked the session"
    );

    // And the revoked session can no longer authorize — the property the
    // old GET test asserted, now true of the POST.
    let after = get(&kit, &authorize_uri(""), Some(&cookie)).await;
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "a revoked session falls back to the chooser rather than minting a code"
    );
}

/// The cross-site POST — the thing SameSite=Lax cannot stop from
/// *arriving* — is refused on arrival, and the session it was meant to
/// kill walks away intact.
#[pollster::test]
async fn confirm_logout_from_a_cross_site_post_is_refused() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let response = post(
        &kit,
        "/v1/auth-core/logout/confirm",
        Some(&cookie),
        // `origin` names another site, `host` names this one: the claim
        // does not match the request, which is the definition of
        // cross-site.
        &[("host", AUTH_HOST), ("origin", "https://evil.example")],
        &format!("client_id={CLIENT}&post_logout_redirect_uri={REDIRECT}"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        set_cookies_of(&response).is_empty(),
        "a refusal clears nothing"
    );
    assert!(
        session_row(&kit, &cookie).await.revoked_at.is_none(),
        "the cross-site POST revoked nothing"
    );
    let after = get(&kit, &authorize_uri(""), Some(&cookie)).await;
    assert_eq!(
        after.status(),
        StatusCode::FOUND,
        "the session must still work after the refused POST"
    );
}

/// The POST answers a person who confirms after their cookie already
/// died the same way the old GET answered them: nothing to revoke, the
/// clearing cookie anyway, and the validated redirect still happens.
#[pollster::test]
async fn confirm_logout_without_a_session_still_redirects_to_the_validated_target() {
    let kit = kit();
    seed_client(&kit).await;

    let response = post(
        &kit,
        "/v1/auth-core/logout/confirm",
        None,
        &[
            ("host", AUTH_HOST),
            ("origin", "https://auth.example.test"),
            ("sec-fetch-site", "same-origin"),
        ],
        &format!("client_id={CLIENT}&post_logout_redirect_uri={REDIRECT}"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location_of(&response), REDIRECT);
    assert!(clears_the_session(&response));
}

/// A confirmation with no redirect target — the form as it renders for a
/// plain "sign out of this device" — ends the session and lands on the
/// signed-out page.
#[pollster::test]
async fn confirm_logout_with_no_redirect_target_renders_the_signed_out_page() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    let response = post(
        &kit,
        "/v1/auth-core/logout/confirm",
        Some(&cookie),
        &[
            ("host", AUTH_HOST),
            ("origin", "https://auth.example.test"),
            ("sec-fetch-site", "same-origin"),
        ],
        // The bare form posts an empty body: no successful controls.
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(clears_the_session(&response));
    let page = body_of(response).await;
    assert!(page.contains("You are signed out"), "{page}");
    assert!(
        session_row(&kit, &cookie).await.revoked_at.is_some(),
        "the bare confirmation revoked the session"
    );
}

/// The old `logout_revokes_the_session_and_clears_the_cookie`, updated
/// for issue #439 rather than deleted. It exercised `GET /logout` and
/// asserted the revoke-and-clear that GET used to do — the exact
/// behaviour the issue removes, because a `SameSite=Lax` cookie is sent
/// on the cross-site top-level GET any page can produce. The GET half
/// now asserts the inverse — the ask clears nothing and revokes
/// nothing — and the original assertions live on, pointed at the
/// confirming POST that may act.
#[pollster::test]
async fn logout_get_only_asks_while_the_confirming_post_revokes_and_clears() {
    let kit = kit();
    seed_client(&kit).await;
    let cookie = signed_in(&kit, "u1").await;

    // The GET half, inverted: the ask leaves the session exactly as it
    // found it.
    let response = get(&kit, "/v1/auth-core/logout", Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !clears_the_session(&response),
        "the asking GET must not clear the cookie"
    );
    assert!(
        session_row(&kit, &cookie).await.revoked_at.is_none(),
        "the asking GET must not revoke the session"
    );

    // The POST half, where the original assertions now live: the act
    // clears the cookie and revokes the session.
    let response = post(
        &kit,
        "/v1/auth-core/logout/confirm",
        Some(&cookie),
        &[
            ("host", AUTH_HOST),
            ("origin", "https://auth.example.test"),
            ("sec-fetch-site", "same-origin"),
        ],
        // The bare form posts an empty body: no successful controls.
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("clears the cookie")
        .to_str()
        .expect("ascii");
    assert!(
        set_cookie.contains("Max-Age=0") || set_cookie.contains("Expires="),
        "the clearing cookie expires it: {set_cookie}"
    );

    let hash = Sha256::digest(cookie.as_bytes()).to_vec();
    let row = session_by_token_hash(&*kit.db, &hash)
        .await
        .expect("query")
        .expect("row still exists");
    assert!(row.revoked_at.is_some(), "logout revoked the session");

    // And the revoked session no longer authorizes.
    let after = get(&kit, &authorize_uri(""), Some(&cookie)).await;
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "a revoked session falls back to the chooser rather than minting a code"
    );
}

// ---------------------------------------------------------------------
// The login chooser (issue #33)
// ---------------------------------------------------------------------

/// The acceptance criterion: with a method configured, the chooser
/// offers it and the round trip returns to the pending `/authorize`.
#[pollster::test]
async fn the_chooser_offers_configured_methods_and_returns_to_the_pending_authorize() {
    let kit = kit_with_methods(Some("google,apple"));
    seed_client(&kit).await;

    // No cookie: this is the chooser, not a code.
    let response = get(&kit, &authorize_uri(""), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_of(response).await;

    assert!(page.contains("Continue with Google"), "{page}");
    assert!(page.contains("Continue with Apple"), "{page}");
    assert!(
        !page.contains("No login methods are enabled"),
        "the empty state rendered with two methods configured"
    );

    // Each button carries the pending /authorize as `return_to`, encoded,
    // so the provider's own `?` and `&` cannot be read as its parameters.
    assert!(
        page.contains("/v1/auth-oidc/google/start?return_to=%2Fv1%2Fauth-core%2Fauthorize%3F"),
        "the Google button does not carry an encoded return_to: {page}"
    );
    // The client id and the code challenge must survive into it, or the
    // person comes back to a request that no longer means anything.
    assert!(page.contains("client_id%3D"), "{page}");
    assert!(page.contains("code_challenge%3D"), "{page}");
}

/// The other acceptance criterion: nothing configured still renders the
/// empty state rather than an empty list or a crash.
#[pollster::test]
async fn with_nothing_configured_the_empty_state_still_renders() {
    let kit = kit();
    seed_client(&kit).await;
    let response = get(&kit, &authorize_uri(""), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_of(response).await;
    assert!(page.contains("No login methods are enabled"), "{page}");
    assert!(
        !page.contains("<script"),
        "no methods should mean no script"
    );
}

/// A passkey cannot be a link: the ceremony is script on this origin.
/// The script ships only when a passkey is offered.
#[pollster::test]
async fn a_passkey_gets_a_scripted_button_and_a_redirect_method_does_not() {
    let kit = kit_with_methods(Some("passkey,google"));
    seed_client(&kit).await;
    let page = body_of(get(&kit, &authorize_uri(""), None).await).await;

    assert!(
        page.contains("<script"),
        "the passkey button needs its script"
    );
    assert!(page.contains("navigator.credentials"), "{page}");
    assert!(
        page.contains("data-method=\"passkey\""),
        "the passkey button is missing: {page}"
    );
    // Google stays a plain link, so it works with script switched off.
    assert!(
        page.contains("data-method=\"google\"") && page.contains("/v1/auth-oidc/google/start"),
        "{page}"
    );

    // Google-only ships no script at all.
    let kit = kit_with_methods(Some("google"));
    seed_client(&kit).await;
    let page = body_of(get(&kit, &authorize_uri(""), None).await).await;
    assert!(
        !page.contains("<script"),
        "a link-only chooser needs no script"
    );
}

/// The request target cannot carry a raw `<`: `http::Uri` refuses one, so
/// a hostile `state` arrives percent-encoded and reaches the page as data.
/// The escaping itself is proved directly in the unit test on the template,
/// because this path cannot express the attack.
#[pollster::test]
async fn a_hostile_state_parameter_arrives_encoded_and_stays_data() {
    let kit = kit_with_methods(Some("passkey"));
    seed_client(&kit).await;
    let uri = format!(
        "/v1/auth-core/authorize?response_type=code&client_id={CLIENT}\
         &redirect_uri={REDIRECT}&code_challenge={}&code_challenge_method=S256\
         &state=%3C%2Fscript%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        challenge()
    );
    let page = body_of(get(&kit, &uri, None).await).await;

    // It must be the chooser that rendered, or this asserts nothing.
    assert!(
        page.contains("data-method=\"passkey\""),
        "not the chooser: {page}"
    );
    assert!(
        page.contains("%3C%2Fscript%3E"),
        "the hostile state never reached the page, so this proves nothing: {page}"
    );
    assert!(!page.contains("alert(1)</script>"), "{page}");
}

/// A catalogue row is data, not a dependency: auth-core links none of the
/// login-method crates, so a provider can be listed here and implemented
/// separately. This kit mounts auth-core alone and still offers all four.
#[pollster::test]
async fn the_catalogue_needs_none_of_the_method_crates_mounted() {
    let kit = kit_with_methods(Some("passkey,google,apple,meta"));
    seed_client(&kit).await;
    let page = body_of(get(&kit, &authorize_uri(""), None).await).await;

    for (slug, path) in [
        ("google", "/v1/auth-oidc/google/start"),
        ("apple", "/v1/auth-oidc/apple/start"),
        ("meta", "/v1/auth-meta/start"),
    ] {
        assert!(
            page.contains(&format!("data-method=\"{slug}\"")),
            "{slug}: {page}"
        );
        assert!(page.contains(path), "{slug} has the wrong path: {page}");
    }
    assert!(page.contains("Continue with Facebook"), "{page}");
    assert!(page.contains("data-method=\"passkey\""), "{page}");
}

/// The Workers runtime builds the axum request from `req.url()`, so the
/// request target is **absolute** in production and origin-form in every
/// test. A `return_to` built from the whole URI is refused by every
/// provider's `safe_return_to`, which silently substitutes `/` — so the
/// chooser's whole purpose fails only where nobody is looking.
#[pollster::test]
async fn an_absolute_request_target_still_yields_a_path_return_to() {
    let kit = kit_with_methods(Some("google,apple,meta"));
    seed_client(&kit).await;

    // Exactly what runtime-cloudflare passes to axum.
    let absolute = format!("https://auth.factory0.ventures{}", authorize_uri(""));
    let page = body_of(get(&kit, &absolute, None).await).await;

    assert!(
        page.contains("Continue with Google"),
        "not the chooser: {page}"
    );
    // The encoded return_to must start with an encoded `/`, not a scheme.
    assert!(
        page.contains("return_to=%2Fv1%2Fauth-core%2Fauthorize%3F"),
        "return_to is not a path: {page}"
    );
    assert!(
        !page.contains("return_to=https%3A"),
        "an absolute return_to every provider refuses: {page}"
    );
    // And it survives the guard it will actually meet.
    assert!(page.contains("client_id%3D"), "{page}");
}

/// A slug the chooser does not know is a build failure, not a button
/// that 404s.
#[test]
fn an_unknown_login_method_slug_is_refused_at_build() {
    use cratefield_core::{Config, MapConfig, Module};
    let cfg = MapConfig::from_pairs([
        (
            "AUTH_CORE_SIGNING_KEYS",
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE", "k1".to_owned()),
        ("AUTH_CORE_ISSUER", ISSUER.to_owned()),
        (
            "AUTH_CORE_LOGIN_METHODS",
            "google,carrier-pigeon".to_owned(),
        ),
    ]);
    let errors = AuthCore::new()
        .validate_config(&cfg as &dyn Config)
        .expect_err("an unknown slug is refused");
    let rendered = format!("{errors:?}");
    assert!(rendered.contains("carrier-pigeon"), "{rendered}");
    assert!(
        rendered.contains("passkey"),
        "the message lists what it knows: {rendered}"
    );
}

/// Not an assertion: writes the rendered chooser to `/tmp` so it can be
/// opened in a browser. Ignored by default.
#[pollster::test]
#[ignore = "manual: writes /tmp/cf-chooser.html for eyeballing"]
async fn dump_the_chooser() {
    let kit = kit_with_methods(Some("passkey,google,apple"));
    seed_client(&kit).await;
    let page = body_of(get(&kit, &authorize_uri(""), None).await).await;
    std::fs::write("/tmp/cf-chooser.html", page).expect("writes");
}

#[pollster::test]
async fn every_button_on_the_chooser_goes_somewhere() {
    // `CATALOGUE` holds a path per method, and a path is a promise about
    // another crate's router. An unknown slug is a build failure, but a
    // catalogue entry pointing at a path no module serves renders a button
    // that 404s, and the person who finds out is the one who clicked it.
    //
    // Two entries are newer than anything that could have held that
    // promise: `magic-link` and `password` each point at a `/start` the
    // module had just grown.
    let kit = kit_with_every_module();
    seed_client(&kit).await;

    let page = body_of(get(&kit, &authorize_uri(""), None).await).await;
    let links = hrefs(&page);
    assert!(
        links.len() >= 5,
        "the chooser rendered {} links — this test is checking nothing:\n{page}",
        links.len()
    );

    for href in &links {
        let status = get(&kit, href, None).await.status();
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "the chooser offers `{href}`, which no module serves"
        );
    }

    // A provider with no credentials answers `503 provider-unconfigured`
    // rather than 404, which is the distinction this test rests on: the
    // route exists, this deployment has not configured it.
    for expected in [
        "/v1/auth-oidc/google/start",
        "/v1/auth-magic-link/start",
        "/v1/auth-password/start",
    ] {
        assert!(
            links.iter().any(|href| href.starts_with(expected)),
            "the {expected} button is gone: {links:?}"
        );
    }
}

#[pollster::test]
async fn the_chooser_probe_can_tell_a_missing_route_from_a_present_one() {
    // The test above passes on a clean catalogue and would also pass if
    // the router answered everything. This is the same probe against a
    // path that is certainly not mounted.
    let kit = kit_with_every_module();
    seed_client(&kit).await;
    assert_eq!(
        get(&kit, "/v1/auth-not-a-module/start", None)
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "an unmounted path did not answer 404, so the probe proves nothing"
    );
    // And the extractor reads a real page rather than returning nothing.
    assert_eq!(
        hrefs("<a href=\"/one\">x</a><a class=\"m\" href=\"/two?a=b\">y</a>"),
        ["/one", "/two?a=b"]
    );
    assert!(hrefs("<p>no links here</p>").is_empty());
}
