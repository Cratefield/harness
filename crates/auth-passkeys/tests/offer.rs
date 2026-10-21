//! The passkey offer after a sign-in (`AUTH_PASSKEYS_OFFER_AFTER_SIGNIN`).
//!
//! The offer is decided inside `/authorize`, so these tests drive the real
//! authorization request: a fresh magic-link or password session is offered a
//! passkey, and "Add" or "Not now" carries the browser back to the same
//! request. The OAuth parameters (`state`, PKCE, `redirect_uri`) are compared
//! byte for byte.

mod support;

use cratefield_auth_core::page::escape;
use cratefield_auth_core::{
    CLIENT_PUBLIC, ClientRedirectUriRow, ClientRow, Redacted, STATUS_ACTIVE, insert_client,
    insert_redirect_uri,
};
use http::{Method, StatusCode};
use support::{
    Algorithm, Kit, ORIGIN, RP_ID, Res, SoftAuthenticator, challenge_of, config_pairs, count, kit,
    kit_with, post, send, send_form, send_with_headers,
};

const AUTHORIZE: &str = "/v1/auth-core/authorize";
const OFFER: &str = "/v1/auth-passkeys/offer";
const DISMISS: &str = "/v1/auth-passkeys/offer/dismiss";
const OPTIONS: &str = "/v1/auth-passkeys/register/options";
const VERIFY: &str = "/v1/auth-passkeys/register/verify";
const REDIRECT: &str = "https://app.example/auth/callback";
/// A well-formed S256 challenge (RFC 7636 appendix B).
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const HTML: [(&str, &str); 1] = [("accept", "text/html")];

/// The authorization request as a client sends it. `extra` is appended
/// verbatim, for `prompt`, `max_age` and the like.
fn authorize_path(extra: &str) -> String {
    format!(
        "{AUTHORIZE}?client_id=01CLIENT&redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback\
&response_type=code&code_challenge={CHALLENGE}&code_challenge_method=S256&state=st4te\
&scope=openid&nonce=n0nce{extra}"
    )
}

fn offer_kit() -> Kit {
    let mut pairs = config_pairs();
    pairs.push((
        "AUTH_PASSKEYS_OFFER_AFTER_SIGNIN".to_owned(),
        "true".to_owned(),
    ));
    kit_with(pairs)
}

fn offer_kit_snoozing(days: &str) -> Kit {
    let mut pairs = config_pairs();
    pairs.push((
        "AUTH_PASSKEYS_OFFER_AFTER_SIGNIN".to_owned(),
        "true".to_owned(),
    ));
    pairs.push((
        "AUTH_PASSKEYS_OFFER_SNOOZE_DAYS".to_owned(),
        days.to_owned(),
    ));
    kit_with(pairs)
}

async fn register_client(kit: &Kit) {
    insert_client(
        &*kit.db,
        &ClientRow {
            id: "01CLIENT".to_owned(),
            name: "App".to_owned(),
            secret_hash: Redacted(String::new()),
            previous_secret_hash: None,
            previous_hash_expires_at: None,
            kind: CLIENT_PUBLIC.to_owned(),
            status: STATUS_ACTIVE.to_owned(),
            created_at: "2026-09-07T10:00:00Z".to_owned(),
        },
    )
    .await
    .expect("client inserts");
    insert_redirect_uri(
        &*kit.db,
        &ClientRedirectUriRow {
            client_id: "01CLIENT".to_owned(),
            uri: REDIRECT.to_owned(),
        },
    )
    .await
    .expect("redirect inserts");
}

async fn authorize(kit: &Kit, path: &str, cookie: Option<&str>) -> Res {
    send_with_headers(kit, Method::GET, path, None, cookie, &HTML).await
}

fn location(response: &Res) -> String {
    response
        .headers
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// The `continue` the offer carries, decoded.
fn continue_of(location: &str) -> String {
    let url = url::Url::parse(&format!("https://auth.acme.example{location}")).expect("a url");
    let (_, value) = url
        .query_pairs()
        .find(|(key, _)| key == "continue")
        .unwrap_or_else(|| panic!("no continue in {location}"));
    value.into_owned()
}

/// Whether a location is the client's redirect with a code, carrying the
/// request's own state.
fn is_code_redirect(location: &str) -> bool {
    location.starts_with(&format!("{REDIRECT}?code=")) && location.contains("&state=st4te")
}

fn is_offer(location: &str) -> bool {
    location.starts_with(&format!("{OFFER}?continue="))
}

/// Same-origin headers a browser form post sends.
const SAME_ORIGIN: [(&str, &str); 3] = [
    ("host", RP_ID),
    ("origin", ORIGIN),
    ("sec-fetch-site", "same-origin"),
];

/// Enrols a passkey for the account through the real ceremony.
async fn enrol_passkey(kit: &Kit, cookie: &str) {
    let options = post(kit, OPTIONS, "{}", Some(cookie)).await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text());
    let authenticator = SoftAuthenticator::new(Algorithm::Es256);
    let credential = authenticator.register(RP_ID, ORIGIN, &challenge_of(&options.json()));
    let body = serde_json::json!({ "credential": credential, "label": "Test" }).to_string();
    let stored = post(kit, VERIFY, &body, Some(cookie)).await;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
}

#[test]
fn a_magic_link_or_password_sign_in_is_offered_a_passkey_first() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        for (email, method) in [("nick@example.com", "email"), ("ada@example.com", "pwd")] {
            let user = kit.user(email).await;
            let cookie = kit.sign_in_as(&user, &[method]).await;

            let response = authorize(&kit, &authorize_path(""), Some(&cookie)).await;
            assert_eq!(response.status, StatusCode::FOUND, "{method}");
            let loc = location(&response);
            assert!(is_offer(&loc), "{method}: {loc}");
            // The continue value is the authorization request, unchanged.
            assert_eq!(continue_of(&loc), authorize_path(""), "{method}");

            let page = send_with_headers(&kit, Method::GET, &loc, None, Some(&cookie), &HTML).await;
            assert_eq!(page.status, StatusCode::OK, "{method}");
            let html = page.text();
            assert!(html.contains("Sign in faster next time"), "{html}");
            assert!(
                html.contains(
                    "Add a passkey so you can sign in with your fingerprint, face or device PIN. \
No email needed."
                ),
                "{html}"
            );
            assert!(html.contains("id=\"cf-offer-add\""), "{html}");
            assert!(html.contains(">Not now</button>"), "{html}");
            assert!(
                html.contains(&format!(
                    "data-continue=\"{}\"",
                    escape(&authorize_path(""))
                )),
                "{html}"
            );
            // A browser without WebAuthn is sent on by the script, not asked.
            assert!(html.contains("cfPasskey.supported()"), "{html}");
            assert!(
                html.contains("window.location.replace(root.getAttribute(\"data-skip\")"),
                "{html}"
            );
        }
    });
}

#[test]
fn a_passkey_sign_in_is_not_offered_one() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["passkey", "user"]).await;
        let response = authorize(&kit, &authorize_path(""), Some(&cookie)).await;
        assert!(
            is_code_redirect(&location(&response)),
            "{}",
            location(&response)
        );
    });
}

#[test]
fn an_account_that_has_a_passkey_is_not_offered_one() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        enrol_passkey(&kit, &cookie).await;

        // A later magic-link sign-in: the account has a passkey now.
        let later = kit.sign_in_as(&user, &["email"]).await;
        let response = authorize(&kit, &authorize_path(""), Some(&later)).await;
        assert!(
            is_code_redirect(&location(&response)),
            "{}",
            location(&response)
        );
    });
}

#[test]
fn nothing_is_offered_while_the_setting_is_off() {
    pollster::block_on(async {
        // The default: no AUTH_PASSKEYS_OFFER_AFTER_SIGNIN at all.
        let kit = kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        let response = authorize(&kit, &authorize_path(""), Some(&cookie)).await;
        assert!(
            is_code_redirect(&location(&response)),
            "{}",
            location(&response)
        );
    });
}

#[test]
fn a_step_up_is_never_interrupted() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        // A demand for a fresh ceremony: the chooser, not the offer.
        for extra in ["&prompt=login", "&max_age=0"] {
            let response = authorize(&kit, &authorize_path(extra), Some(&cookie)).await;
            let loc = location(&response);
            assert!(!is_offer(&loc), "{extra}: {loc}");
            assert!(
                !response.text().contains("Sign in faster next time"),
                "{extra}"
            );
        }
    });
}

#[test]
fn an_api_client_or_a_silent_request_gets_no_page() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;

        // No `Accept: text/html`: an API client.
        let api = send(&kit, Method::GET, &authorize_path(""), None, Some(&cookie)).await;
        assert!(is_code_redirect(&location(&api)), "{}", location(&api));

        // `prompt=none`: a silent request, which can only answer with a code.
        let silent = authorize(&kit, &authorize_path("&prompt=none"), Some(&cookie)).await;
        assert!(
            is_code_redirect(&location(&silent)),
            "{}",
            location(&silent)
        );
    });
}

#[test]
fn a_session_older_than_the_ceremony_window_is_not_offered() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        kit.clock.advance_secs(121);
        let response = authorize(&kit, &authorize_path(""), Some(&cookie)).await;
        assert!(
            is_code_redirect(&location(&response)),
            "{}",
            location(&response)
        );
    });
}

#[test]
fn not_now_returns_to_the_original_request_with_identical_parameters() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        let loc = location(&authorize(&kit, &authorize_path(""), Some(&cookie)).await);
        let continue_to = continue_of(&loc);

        let form = format!("continue={}", form_encode(&continue_to));
        let dismissed = send_form(&kit, DISMISS, &form, Some(&cookie), &SAME_ORIGIN).await;
        assert_eq!(
            dismissed.status,
            StatusCode::SEE_OTHER,
            "{}",
            dismissed.text()
        );
        assert_eq!(location(&dismissed), authorize_path(""));

        // The original request now mints its code, with the same state and
        // redirect_uri, and no second offer.
        let back = authorize(&kit, &location(&dismissed), Some(&cookie)).await;
        assert!(is_code_redirect(&location(&back)), "{}", location(&back));
        assert!(location(&back).starts_with(REDIRECT));
        assert_eq!(count(&kit, "auth_passkeys_offer_dismissals"), 1);
    });
}

#[test]
fn a_dismissal_holds_for_the_snooze_and_then_lapses() {
    pollster::block_on(async {
        let kit = offer_kit_snoozing("2");
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        let loc = location(&authorize(&kit, &authorize_path(""), Some(&cookie)).await);
        let form = format!("continue={}", form_encode(&continue_of(&loc)));
        send_form(&kit, DISMISS, &form, Some(&cookie), &SAME_ORIGIN).await;

        // A new sign-in inside the snooze: no offer. The dismissal follows the
        // account, not the browser, so a new session is not a new offer.
        kit.clock.advance_secs(24 * 60 * 60);
        let again = kit.sign_in_as(&user, &["email"]).await;
        let inside = location(&authorize(&kit, &authorize_path(""), Some(&again)).await);
        assert!(is_code_redirect(&inside), "{inside}");

        // Past the snooze: offered again.
        kit.clock.advance_secs(2 * 24 * 60 * 60);
        let later = kit.sign_in_as(&user, &["email"]).await;
        let after = location(&authorize(&kit, &authorize_path(""), Some(&later)).await);
        assert!(is_offer(&after), "{after}");
    });
}

#[test]
fn the_default_snooze_is_thirty_days() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        let loc = location(&authorize(&kit, &authorize_path(""), Some(&cookie)).await);
        let form = format!("continue={}", form_encode(&continue_of(&loc)));
        send_form(&kit, DISMISS, &form, Some(&cookie), &SAME_ORIGIN).await;

        kit.clock.advance_secs(29 * 24 * 60 * 60);
        let inside = kit.sign_in_as(&user, &["email"]).await;
        let still = location(&authorize(&kit, &authorize_path(""), Some(&inside)).await);
        assert!(is_code_redirect(&still), "{still}");

        kit.clock.advance_secs(2 * 24 * 60 * 60);
        let past = kit.sign_in_as(&user, &["email"]).await;
        let offered = location(&authorize(&kit, &authorize_path(""), Some(&past)).await);
        assert!(is_offer(&offered), "{offered}");
    });
}

#[test]
fn adding_a_passkey_from_the_offer_returns_to_the_original_request() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        let loc = location(&authorize(&kit, &authorize_path(""), Some(&cookie)).await);
        assert!(is_offer(&loc), "{loc}");

        // The page's ceremony: options, then verify, on the fresh session.
        enrol_passkey(&kit, &cookie).await;

        // Continuing the original request: a code, and no second offer.
        let back = location(&authorize(&kit, &continue_of(&loc), Some(&cookie)).await);
        assert!(is_code_redirect(&back), "{back}");
        assert_eq!(count(&kit, "auth_passkeys_offer_dismissals"), 0);
    });
}

#[test]
fn a_stale_offer_cannot_add_a_passkey() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        let loc = location(&authorize(&kit, &authorize_path(""), Some(&cookie)).await);
        assert!(is_offer(&loc), "{loc}");

        // The page sat open past the ceremony window: the enrolment gate
        // refuses, the same as for any first passkey.
        kit.clock.advance_secs(121);
        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await;
        assert_ne!(options.status, StatusCode::OK, "{}", options.text());
    });
}

#[test]
fn a_cross_site_dismissal_is_refused_and_records_nothing() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        let form = format!("continue={}", form_encode(&authorize_path("")));
        let refused = send_form(
            &kit,
            DISMISS,
            &form,
            Some(&cookie),
            &[
                ("host", RP_ID),
                ("origin", "https://evil.example"),
                ("sec-fetch-site", "cross-site"),
            ],
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text());
        assert_eq!(count(&kit, "auth_passkeys_offer_dismissals"), 0);
    });
}

#[test]
fn continue_must_name_the_authorization_endpoint() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        for hostile in [
            "https://evil.example/",
            "//evil.example/",
            "/v1/auth-core/sessions",
            "/v1/auth-core/authorizex",
        ] {
            let page = send_with_headers(
                &kit,
                Method::GET,
                &format!("{OFFER}?continue={}", form_encode(hostile)),
                None,
                Some(&cookie),
                &HTML,
            )
            .await;
            assert_eq!(page.status, StatusCode::BAD_REQUEST, "{hostile}");
            assert!(location(&page).is_empty(), "{hostile}");

            let form = format!("continue={}", form_encode(hostile));
            let dismissed = send_form(&kit, DISMISS, &form, Some(&cookie), &SAME_ORIGIN).await;
            assert_eq!(dismissed.status, StatusCode::BAD_REQUEST, "{hostile}");
        }
        assert_eq!(count(&kit, "auth_passkeys_offer_dismissals"), 0);
    });
}

#[test]
fn the_offer_page_without_a_session_goes_on_to_the_request() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let page = send_with_headers(
            &kit,
            Method::GET,
            &format!("{OFFER}?continue={}", form_encode(&authorize_path(""))),
            None,
            None,
            &HTML,
        )
        .await;
        assert_eq!(page.status, StatusCode::FOUND);
        assert_eq!(location(&page), authorize_path(""));
    });
}

#[test]
fn a_browser_that_cannot_offer_is_sent_on_once_and_not_offered_again() {
    pollster::block_on(async {
        let kit = offer_kit();
        register_client(&kit).await;
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in_as(&user, &["email"]).await;
        let loc = location(&authorize(&kit, &authorize_path(""), Some(&cookie)).await);
        assert!(is_offer(&loc), "{loc}");
        let page = send_with_headers(&kit, Method::GET, &loc, None, Some(&cookie), &HTML).await;
        // The page's skip target is the same request, behind the skip route.
        let skip_target = format!(
            "/v1/auth-passkeys/offer/skip?continue={}",
            form_encode(&authorize_path(""))
        );
        assert!(
            page.text().contains(&escape(&skip_target)),
            "{}",
            page.text()
        );

        // The skip sends the browser on, and sets the marker for this session.
        let skipped = authorize_skip(&kit, &skip_target, &cookie).await;
        assert_eq!(skipped.status, StatusCode::FOUND);
        assert_eq!(location(&skipped), authorize_path(""));
        let marker = skipped.set_cookie().expect("a marker cookie");
        let session = session_id(&kit, &cookie).await;
        assert!(
            marker.starts_with(&format!("__Host-sign-in-step={session};")),
            "{marker}"
        );
        assert!(
            marker.contains("HttpOnly") && marker.contains("Secure"),
            "{marker}"
        );

        // Back at /authorize with the marker: a code, not the offer again.
        let back = send_with_headers(
            &kit,
            Method::GET,
            &authorize_path(""),
            None,
            Some(&cookie),
            &[("accept", "text/html"), ("cookie", &marker_pair(&marker))],
        )
        .await;
        assert!(is_code_redirect(&location(&back)), "{}", location(&back));

        // A marker from an earlier sign-in never counts for a later one.
        let later = kit.sign_in_as(&user, &["email"]).await;
        let stale = send_with_headers(
            &kit,
            Method::GET,
            &authorize_path(""),
            None,
            Some(&later),
            &[("accept", "text/html"), ("cookie", &marker_pair(&marker))],
        )
        .await;
        assert!(is_offer(&location(&stale)), "{}", location(&stale));
    });
}

async fn authorize_skip(kit: &Kit, path: &str, cookie: &str) -> Res {
    send_with_headers(kit, Method::GET, path, None, Some(cookie), &HTML).await
}

/// The session id a session cookie names.
async fn session_id(kit: &Kit, cookie: &str) -> String {
    cratefield_auth_core::validate(&*kit.db, &*kit.clock, cookie)
        .await
        .expect("validates")
        .expect("a live session")
        .id
}

/// `name=value` from a `Set-Cookie` line, for the next request's `Cookie`.
fn marker_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap_or_default().to_owned()
}

/// Percent-encodes a value for a query or form field, the way a browser does.
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
