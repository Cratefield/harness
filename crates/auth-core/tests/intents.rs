//! One entry flow, the auth-core half: sign-up intents on clients, the Continue
//! screen, the `/signup` and `/signin` redirects, `login_hint`, the application's
//! own `intents=`, `prompt=intents`, the `intents` claim in the ID token and at
//! userinfo, and the rule that an intent never grants a role.
//!
//! The magic-link half (the question asked after the mailbox is proven, and the
//! anti-enumeration of the email path) lives in `cratefield-auth-magic-link`.

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_auth_core::{AuthCore, Login, UserRow, insert_user, issue};
use cratefield_core::{MapConfig, UlidIdGen};
use cratefield_testing::{FixedClock, TestHarness};
use p256::ecdsa;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const ISSUER: &str = "https://auth.test.example";
const ADMIN: &str = "test-admin-token-0123456789abcdef";
const AUTH_HOST: &str = "auth.example.test";
const REDIRECT: &str = "https://undercoverrockstars.com/auth/callback";
const VERIFIER: &str = "a-verifier-of-at-least-43-characters-1234567890";
const BASE: &str = "/v1/auth-core";

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
}

fn dummy_key(kid: &str) -> Value {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("entropy");
    bytes[0] = 1;
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let _ = ecdsa::SigningKey::from(&secret);
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d })
}

/// The kit: signing keys, an issuer, the admin token, and the given config
/// pairs on top (login methods, magic-link registration).
fn kit(extra: &[(&str, &str)]) -> TestHarness {
    let mut pairs = vec![
        (
            "AUTH_CORE_SIGNING_KEYS".to_owned(),
            serde_json::to_string(&vec![dummy_key("k1")]).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE".to_owned(), "k1".to_owned()),
        ("AUTH_CORE_ISSUER".to_owned(), ISSUER.to_owned()),
        ("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()),
    ];
    for (key, value) in extra {
        pairs.push(((*key).to_owned(), (*value).to_owned()));
    }
    let config = Arc::new(MapConfig::from_pairs(pairs));
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], move |ports| {
        ports.config = config;
    })
}

fn challenge() -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(VERIFIER.as_bytes()))
}

struct Reply {
    status: StatusCode,
    json: Value,
}

async fn reply(response: axum::response::Response) -> Reply {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    Reply { status, json }
}

async fn admin_call(kit: &TestHarness, method: Method, path: &str, body: Option<Value>) -> Reply {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"));
    let request = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            builder.body(axum::body::Body::from(value.to_string()))
        }
        None => builder.body(axum::body::Body::empty()),
    }
    .expect("request builds");
    reply(kit.router.clone().oneshot(request).await.expect("answers")).await
}

async fn send(
    kit: &TestHarness,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> axum::response::Response {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, format!("__Host-session={cookie}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(axum::body::Body::from(body.unwrap_or_default().to_owned()))
        .expect("request");
    kit.router.clone().oneshot(request).await.expect("answers")
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    String::from_utf8_lossy(&bytes).to_string()
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

/// A public client with the given sign-up intents (JSON, or none) and roles.
async fn public_client(kit: &TestHarness, intents: Option<Value>, roles: bool) -> String {
    let mut body = json!({
        "name": "Undercover Rockstars",
        "kind": "public",
        "redirect_uris": [REDIRECT],
        "roles_claim": roles,
    });
    if let Some(list) = intents {
        body["signup_intents"] = list;
    }
    let response = admin_call(
        kit,
        Method::POST,
        &format!("{BASE}/admin/clients"),
        Some(body),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.json);
    response.json["id"].as_str().expect("id").to_owned()
}

fn builder_list() -> Value {
    json!([
        {
            "key": "builder",
            "label": { "en": "I build things", "de": "Ich baue Dinge" },
            "description": { "en": "Shipping software or hardware." }
        },
        {
            "key": "buyer",
            "label": { "en": "I buy things" }
        },
        {
            "key": "just_looking",
            "label": { "en": "Just looking" },
            "multi": false
        }
    ])
}

async fn seed_user(kit: &TestHarness, id: &str) {
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: Some(format!("{id}@example.com")),
            primary_email_verified: true,
            locale: None,
            status: "active".to_owned(),
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
}

fn iso(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .expect("in range")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339")
}

async fn signed_in(kit: &TestHarness, user_id: &str) -> String {
    seed_user(kit, user_id).await;
    issue(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        Login {
            user_id,
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &["email"],
        },
    )
    .await
    .expect("session")
    .value
}

/// `/authorize` for a client, with extra query parameters appended raw.
fn authorize_uri(client: &str, extra: &str) -> String {
    format!(
        "{BASE}/authorize?response_type=code&client_id={client}&redirect_uri={REDIRECT}\
         &code_challenge={}&code_challenge_method=S256&state=xyz&scope=openid{extra}",
        challenge()
    )
}

/// Redeems a code from a `Location` header at `/token`, and returns the body.
async fn redeem(kit: &TestHarness, client: &str, location: &str) -> Value {
    let code = location
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("a code");
    let form = format!(
        "grant_type=authorization_code&client_id={client}&code={code}\
         &redirect_uri={REDIRECT}&code_verifier={VERIFIER}"
    );
    let response = send(
        kit,
        Method::POST,
        &format!("{BASE}/token"),
        None,
        &[],
        Some(&form),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_str(&body_text(response).await).expect("token JSON")
}

/// The payload of a compact JWT, decoded without checking its signature.
fn claims_of(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("payload");
    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(part).expect("base64url"))
        .expect("claims JSON")
}

// --- the admin API ---------------------------------------------------------

#[pollster::test]
async fn a_client_registers_and_changes_its_sign_up_intents() {
    let kit = kit(&[]);
    let id = public_client(&kit, Some(builder_list()), false).await;

    let listed = admin_call(&kit, Method::GET, &format!("{BASE}/admin/clients"), None).await;
    let row = listed
        .json
        .as_array()
        .expect("array")
        .iter()
        .find(|row| row["id"] == id)
        .expect("row");
    assert_eq!(row["signup_intents"][0]["key"], "builder");
    assert_eq!(row["signup_intents"][0]["multi"], true);
    assert_eq!(row["signup_intents"][2]["multi"], false);

    let replaced = admin_call(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/{id}"),
        Some(json!({ "signup_intents": [{ "key": "teacher", "label": { "en": "I teach" } }] })),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.json);
    assert_eq!(replaced.json["signup_intents"][0]["key"], "teacher");

    let cleared = admin_call(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/{id}"),
        Some(json!({ "signup_intents": null })),
    )
    .await;
    assert_eq!(cleared.status, StatusCode::OK);
    assert!(cleared.json["signup_intents"].is_null());
}

#[pollster::test]
async fn an_invalid_intent_list_is_refused_at_registration_and_patch() {
    let kit = kit(&[]);
    let refused = [
        json!([]),
        json!([{ "key": "Builder", "label": { "en": "x" } }]),
        json!([{ "key": "builder", "label": { "de": "Bauherr" } }]),
        json!([{ "key": "a", "label": { "en": "x" } }, { "key": "a", "label": { "en": "y" } }]),
        json!([{ "key": "a", "label": { "en": "x" }, "description": { "fr fr": "x" } }]),
        json!("builder"),
    ];
    for list in refused {
        let response = admin_call(
            &kit,
            Method::POST,
            &format!("{BASE}/admin/clients"),
            Some(json!({
                "name": "x",
                "kind": "public",
                "redirect_uris": [REDIRECT],
                "signup_intents": list,
            })),
        )
        .await;
        assert!(
            response.status == StatusCode::BAD_REQUEST,
            "{list} accepted with {}",
            response.status
        );
    }
    let id = public_client(&kit, None, false).await;
    let patched = admin_call(
        &kit,
        Method::PATCH,
        &format!("{BASE}/admin/clients/{id}"),
        Some(json!({ "signup_intents": [] })),
    )
    .await;
    assert_eq!(patched.status, StatusCode::BAD_REQUEST);
}

// --- the Continue screen and its URLs --------------------------------------

#[pollster::test]
async fn the_continue_screen_offers_one_email_step_and_a_passkey_first() {
    let kit = kit(&[
        ("AUTH_CORE_LOGIN_METHODS", "passkey,magic-link,google"),
        ("AUTH_MAGIC_LINK_ALLOW_REGISTRATION", "true"),
    ]);
    let id = public_client(&kit, None, false).await;
    let response = send(&kit, Method::GET, &authorize_uri(&id, ""), None, &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_text(response).await;
    assert!(page.contains("<h1>Sign in</h1>"), "{page}");
    assert!(page.contains("We'll set up your account"), "{page}");
    assert!(!page.contains("Sign up"), "{page}");
    assert!(!page.contains("Continue</h1>"), "{page}");
    assert!(
        page.contains("action=\"/v1/auth-magic-link/start\""),
        "{page}"
    );
    assert!(page.contains("name=\"email\""), "{page}");
    assert!(
        page.contains("autocomplete=\"username webauthn\""),
        "{page}"
    );
    assert!(page.contains("id=\"cf-passkey\""), "{page}");
    assert!(page.contains("Email me a sign-in link"), "{page}");
    assert!(page.contains("Continue with Google"), "{page}");
    assert!(!page.contains("This app is invite-only"), "{page}");
}

#[pollster::test]
async fn an_invite_only_instance_says_so_without_an_address_on_the_page() {
    let kit = kit(&[("AUTH_CORE_LOGIN_METHODS", "magic-link")]);
    let id = public_client(&kit, None, false).await;
    let page =
        body_text(send(&kit, Method::GET, &authorize_uri(&id, ""), None, &[], None).await).await;
    assert!(page.contains("This app is invite-only"), "{page}");
    assert!(
        !page.contains("cf-passkey"),
        "no passkey was enabled: {page}"
    );
}

#[pollster::test]
async fn login_hint_prefills_the_address_and_shows_the_method_choice() {
    let kit = kit(&[
        ("AUTH_CORE_LOGIN_METHODS", "passkey,magic-link"),
        ("AUTH_MAGIC_LINK_ALLOW_REGISTRATION", "true"),
    ]);
    let id = public_client(&kit, None, false).await;
    let uri = authorize_uri(&id, "&login_hint=Ada%40Example.com");
    let page = body_text(send(&kit, Method::GET, &uri, None, &[], None).await).await;
    assert!(
        page.contains("Signing in as <strong>ada@example.com</strong>"),
        "{page}"
    );
    assert!(
        page.contains("name=\"email\" id=\"cf-email-fixed\""),
        "{page}"
    );
    assert!(
        !page.contains("id=\"cf-email\""),
        "no typing needed: {page}"
    );
    assert!(page.contains("Use a different address"), "{page}");
    assert!(page.contains("id=\"cf-passkey\""), "{page}");
}

#[pollster::test]
async fn signup_and_signin_redirect_to_the_continue_screen_keeping_the_query() {
    let kit = kit(&[]);
    let id = public_client(&kit, None, false).await;
    let query = format!("client_id={id}&redirect_uri={REDIRECT}&response_type=code");
    for old in ["signup", "signin"] {
        let response = send(
            &kit,
            Method::GET,
            &format!("{BASE}/{old}?{query}"),
            None,
            &[],
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND, "/{old}");
        assert_eq!(location_of(&response), format!("{BASE}/authorize?{query}"));
    }
}

// --- intents on /authorize -------------------------------------------------

#[pollster::test]
async fn an_undeclared_or_unknown_intents_parameter_is_an_oauth_error() {
    let kit = kit(&[]);
    let with_list = public_client(&kit, Some(builder_list()), false).await;
    let without = public_client(&kit, None, false).await;

    let unknown = send(
        &kit,
        Method::GET,
        &authorize_uri(&with_list, "&intents=wizard"),
        None,
        &[],
        None,
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::FOUND);
    assert!(location_of(&unknown).contains("error=invalid_request"));

    let exclusive = send(
        &kit,
        Method::GET,
        &authorize_uri(&with_list, "&intents=just_looking,builder"),
        None,
        &[],
        None,
    )
    .await;
    assert!(location_of(&exclusive).contains("error=invalid_request"));

    let no_list = send(
        &kit,
        Method::GET,
        &authorize_uri(&without, "&intents=builder"),
        None,
        &[],
        None,
    )
    .await;
    assert!(location_of(&no_list).contains("error=invalid_request"));
}

#[pollster::test]
async fn chosen_intents_reach_the_id_token_and_userinfo_and_never_roles() {
    let kit = kit(&[]);
    let id = public_client(&kit, Some(builder_list()), true).await;
    let cookie = signed_in(&kit, "u1").await;

    let response = send(
        &kit,
        Method::GET,
        &authorize_uri(&id, "&intents=builder,buyer"),
        Some(&cookie),
        &[],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let tokens = redeem(&kit, &id, &location_of(&response)).await;
    let id_claims = claims_of(tokens["id_token"].as_str().expect("id token"));
    assert_eq!(id_claims["intents"], json!(["builder", "buyer"]));
    // The grant is the person's: the role is the account's, and an intent is
    // never a role.
    assert_eq!(id_claims["roles"], json!(["member"]));

    let access = tokens["access_token"].as_str().expect("access token");
    let info = send(
        &kit,
        Method::GET,
        &format!("{BASE}/userinfo"),
        None,
        &[("authorization", format!("Bearer {access}").as_str())],
        None,
    )
    .await;
    assert_eq!(info.status(), StatusCode::OK);
    let info: Value = serde_json::from_str(&body_text(info).await).expect("JSON");
    assert_eq!(info["sub"], "u1");
    assert_eq!(info["intents"], json!(["builder", "buyer"]));

    let refused = send(
        &kit,
        Method::GET,
        &format!("{BASE}/userinfo"),
        None,
        &[],
        None,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn a_client_without_a_list_gets_no_intents_claim() {
    let kit = kit(&[]);
    let id = public_client(&kit, None, false).await;
    let cookie = signed_in(&kit, "u1").await;
    let response = send(
        &kit,
        Method::GET,
        &authorize_uri(&id, ""),
        Some(&cookie),
        &[],
        None,
    )
    .await;
    let tokens = redeem(&kit, &id, &location_of(&response)).await;
    let id_claims = claims_of(tokens["id_token"].as_str().expect("id token"));
    assert!(id_claims.get("intents").is_none(), "{id_claims}");
}

#[pollster::test]
async fn prompt_intents_asks_again_and_records_the_answer() {
    let kit = kit(&[]);
    let id = public_client(&kit, Some(builder_list()), false).await;
    let cookie = signed_in(&kit, "u1").await;
    let uri = authorize_uri(&id, "&prompt=intents");

    let step = send(&kit, Method::GET, &uri, Some(&cookie), &[], None).await;
    assert_eq!(step.status(), StatusCode::OK);
    let page = body_text(step).await;
    // The form carries the request without `prompt=intents`; the browser posts
    // that value back, unescaped from the attribute.
    let carried = page
        .split("name=\"return_to\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the step carries its return path")
        .replace("&amp;", "&");
    assert!(!carried.contains("prompt="), "{carried}");
    assert!(page.contains("What brings you here?"), "{page}");
    assert!(
        page.contains("name=\"intents\" value=\"builder\""),
        "{page}"
    );
    assert!(
        page.contains("aria-describedby=\"intent-builder-hint\""),
        "{page}"
    );
    assert!(page.contains("action=\"/v1/auth-core/intents\""), "{page}");

    // A cross-site post cannot record anything.
    let forged = send(
        &kit,
        Method::POST,
        &format!("{BASE}/intents"),
        Some(&cookie),
        &[
            ("host", AUTH_HOST),
            ("origin", "https://evil.example"),
            ("sec-fetch-site", "cross-site"),
        ],
        Some("return_to=%2Fv1%2Fauth-core%2Fauthorize&intents=buyer"),
    )
    .await;
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);

    let answered = send(
        &kit,
        Method::POST,
        &format!("{BASE}/intents"),
        Some(&cookie),
        &[
            ("host", AUTH_HOST),
            ("origin", "https://auth.example.test"),
            ("sec-fetch-site", "same-origin"),
        ],
        Some(&format!(
            "return_to={}&intents=builder&intents=buyer",
            url_encode(&carried)
        )),
    )
    .await;
    let answered_status = answered.status();
    let answered_location = answered.headers().get(header::LOCATION).cloned();
    assert_eq!(
        answered_status,
        StatusCode::SEE_OTHER,
        "{carried} {answered_location:?}"
    );
    let target = location_of(&answered);
    assert!(
        !target.contains("prompt=intents"),
        "the step is not asked again: {target}"
    );
    assert!(target.contains(&format!("client_id={id}")), "{target}");

    // The recorded answer is what the next code carries.
    let next = send(&kit, Method::GET, &target, Some(&cookie), &[], None).await;
    let tokens = redeem(&kit, &id, &location_of(&next)).await;
    let id_claims = claims_of(tokens["id_token"].as_str().expect("id token"));
    assert_eq!(id_claims["intents"], json!(["builder", "buyer"]));
}

#[pollster::test]
async fn the_intents_step_refuses_an_exclusive_mix_and_an_unknown_key() {
    let kit = kit(&[]);
    let id = public_client(&kit, Some(builder_list()), false).await;
    let cookie = signed_in(&kit, "u1").await;
    let uri = authorize_uri(&id, "&prompt=intents");
    for body in [
        format!(
            "return_to={}&intents=just_looking&intents=builder",
            url_encode(&uri)
        ),
        format!("return_to={}&intents=wizard", url_encode(&uri)),
    ] {
        let response = send(
            &kit,
            Method::POST,
            &format!("{BASE}/intents"),
            Some(&cookie),
            &[
                ("host", AUTH_HOST),
                ("origin", "https://auth.example.test"),
                ("sec-fetch-site", "same-origin"),
            ],
            Some(&body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
}

fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

// --- hardening: intents= never overwrites, return paths, deferred insert -----

#[pollster::test]
async fn an_application_answer_never_overwrites_one_already_recorded() {
    let kit = kit(&[]);
    let id = public_client(&kit, Some(builder_list()), false).await;
    let cookie = signed_in(&kit, "u1").await;
    cratefield_auth_core::intents::record(&*kit.db, &at(EPOCH), "u1", &id, &["buyer".to_owned()])
        .await
        .expect("record");

    // The application asks for "builder" on a sign-in; the stored answer stands.
    let response = send(
        &kit,
        Method::GET,
        &authorize_uri(&id, "&intents=builder"),
        Some(&cookie),
        &[],
        None,
    )
    .await;
    let tokens = redeem(&kit, &id, &location_of(&response)).await;
    let id_claims = claims_of(tokens["id_token"].as_str().expect("id token"));
    assert_eq!(id_claims["intents"], json!(["buyer"]));
    assert_eq!(
        cratefield_auth_core::intents::chosen(&*kit.db, "u1", &id)
            .await
            .expect("query"),
        Some(vec!["buyer".to_owned()])
    );
}

#[pollster::test]
async fn an_account_with_no_answer_takes_the_application_answer() {
    let kit = kit(&[]);
    let id = public_client(&kit, Some(builder_list()), false).await;
    let cookie = signed_in(&kit, "u1").await;
    send(
        &kit,
        Method::GET,
        &authorize_uri(&id, "&intents=builder"),
        Some(&cookie),
        &[],
        None,
    )
    .await;
    assert_eq!(
        cratefield_auth_core::intents::chosen(&*kit.db, "u1", &id)
            .await
            .expect("query"),
        Some(vec!["builder".to_owned()])
    );
}

#[pollster::test]
async fn the_intents_prompt_still_changes_a_recorded_answer() {
    let kit = kit(&[]);
    let id = public_client(&kit, Some(builder_list()), false).await;
    let cookie = signed_in(&kit, "u1").await;
    cratefield_auth_core::intents::record(&*kit.db, &at(EPOCH), "u1", &id, &["buyer".to_owned()])
        .await
        .expect("record");
    let uri = authorize_uri(&id, "&prompt=intents");
    let answered = send(
        &kit,
        Method::POST,
        &format!("{BASE}/intents"),
        Some(&cookie),
        &[
            ("host", AUTH_HOST),
            ("origin", "https://auth.example.test"),
            ("sec-fetch-site", "same-origin"),
        ],
        Some(&format!("return_to={}&intents=builder", url_encode(&uri))),
    )
    .await;
    assert_eq!(answered.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        cratefield_auth_core::intents::chosen(&*kit.db, "u1", &id)
            .await
            .expect("query"),
        Some(vec!["builder".to_owned()])
    );
}

#[pollster::test]
async fn a_return_path_with_a_control_character_or_an_overlong_value_is_refused() {
    let kit = kit(&[]);
    let id = public_client(&kit, Some(builder_list()), false).await;
    let cookie = signed_in(&kit, "u1").await;
    let base = authorize_uri(&id, "");
    let hostile = [
        format!("{base}&x=\n\r"),
        format!("{}&pad={}", base, "a".repeat(4100)),
        "/\\evil.example/v1/auth-core/authorize".to_owned(),
    ];
    for path in hostile {
        let response = send(
            &kit,
            Method::POST,
            &format!("{BASE}/intents"),
            Some(&cookie),
            &[
                ("host", AUTH_HOST),
                ("origin", "https://auth.example.test"),
                ("sec-fetch-site", "same-origin"),
            ],
            Some(&format!("return_to={}&intents=builder", url_encode(&path))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }
}

#[pollster::test]
async fn a_second_account_for_one_email_is_never_inserted() {
    let kit = kit(&[]);
    seed_user(&kit, "ada").await;
    let duplicate = UserRow {
        id: "ada-2".to_owned(),
        display_name: None,
        primary_email: Some("ada@example.com".to_owned()),
        primary_email_verified: false,
        locale: None,
        status: "active".to_owned(),
        created_at: iso(EPOCH),
        updated_at: iso(EPOCH),
    };
    let inserted = cratefield_auth_core::insert_user_if_email_free(&*kit.db, &duplicate)
        .await
        .expect("query");
    assert!(!inserted, "the address already has an account");
    assert!(
        cratefield_auth_core::user_by_primary_email(&*kit.db, "ada@example.com")
            .await
            .expect("query")
            .is_some_and(|user| user.id == "ada")
    );
}
