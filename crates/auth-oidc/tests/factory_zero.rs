//! Venture linking: "Continue with Factory Zero" through the real provider
//! flow, judged by the linking rules (issue #22). The fake provider is a
//! Factory Zero shaped one: ES256 ID tokens, an EC JWKS, and the venture's
//! client id as the audience.
//!
//! Rule 2 (a person already signed in to the venture confirms the link) is
//! not exercised here: it needs a venture session cookie, and the rules
//! themselves are covered for every provider by `tests/linking.rs` and
//! `cratefield-auth-core`'s `linking` tests.

mod support;

use cratefield_auth_core::{UserRow, insert_user};
use http::StatusCode;
use support::kit::{Kit, Res, get, kit_with, start_at};
use support::provider::{FACTORY_ZERO_CLIENT_ID, FACTORY_ZERO_CLIENT_SECRET, TokenClaims};
use support::{column, count};

const START: &str = "/v1/auth-oidc/factory-zero/start";
const CALLBACK: &str = "/v1/auth-oidc/factory-zero/callback";

fn factory_zero_kit() -> Kit {
    let mut pairs = support::kit::config_pairs();
    pairs.extend([
        // A venture sign-in the link page can offer (the Google one the kit
        // already configures). Factory Zero itself is never offered there.
        (
            "AUTH_CORE_LOGIN_METHODS".to_owned(),
            "google,factory-zero".to_owned(),
        ),
        (
            "AUTH_OIDC_FACTORY_ZERO_CLIENT_ID".to_owned(),
            FACTORY_ZERO_CLIENT_ID.to_owned(),
        ),
        (
            "AUTH_OIDC_FACTORY_ZERO_CLIENT_SECRET".to_owned(),
            FACTORY_ZERO_CLIENT_SECRET.to_owned(),
        ),
    ]);
    let kit = kit_with(pairs);
    // The kit's own fake is Google-shaped; the Factory Zero tests drive a
    // Factory Zero fake instead, wired in before any request is made.
    kit.provider.set_claims(TokenClaims::factory_zero());
    kit
}

async fn sign_in(kit: &Kit) -> Res {
    let started = start_at(kit, START, "").await;
    get(
        kit,
        &format!("{CALLBACK}?code=auth-code&state={}", started.state),
        &[("__Host-auth_oidc", &started.flow_cookie)],
    )
    .await
}

async fn seed_user(kit: &Kit, email: &str, verified: bool) -> String {
    let id = kit.id_gen.ulid();
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.clone(),
            display_name: None,
            primary_email: Some(email.to_owned()),
            primary_email_verified: verified,
            locale: None,
            status: "active".to_owned(),
            created_at: "2026-09-07T10:00:00Z".to_owned(),
            updated_at: "2026-09-07T10:00:00Z".to_owned(),
        },
    )
    .await
    .expect("user inserts");
    id
}

#[test]
fn a_first_factory_zero_sign_in_creates_a_user_linked_to_factory_zero() {
    pollster::block_on(async {
        let kit = factory_zero_kit();
        let response = sign_in(&kit).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert!(response.cookie("__Host-session").is_some());

        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 1);
        assert_eq!(
            column(&kit, "SELECT provider FROM identities", "provider").as_deref(),
            Some("factory-zero")
        );
        assert_eq!(
            column(
                &kit,
                "SELECT provider_subject FROM identities",
                "provider_subject"
            )
            .as_deref(),
            Some("factory-zero-subject-1")
        );
    });
}

#[test]
fn a_returning_factory_zero_identity_is_the_same_user() {
    // Rule 1: the (provider, subject) pair is the person. A second sign-in
    // must not make a second account.
    pollster::block_on(async {
        let kit = factory_zero_kit();
        assert_eq!(sign_in(&kit).await.status, StatusCode::FOUND);
        assert_eq!(sign_in(&kit).await.status, StatusCode::FOUND);
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 1);
    });
}

#[test]
fn a_verified_address_on_both_sides_links_to_the_existing_account() {
    // Rule 3: Factory Zero vouches for the address, and so does the account.
    pollster::block_on(async {
        let kit = factory_zero_kit();
        let existing = seed_user(&kit, "nick@example.com", true).await;
        let response = sign_in(&kit).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(
            column(&kit, "SELECT user_id FROM identities", "user_id").as_deref(),
            Some(existing.as_str())
        );
    });
}

#[test]
fn an_unverified_account_address_is_not_guessed_at() {
    // The account holds the address but nobody proved it: linking on that
    // basis is how someone takes over an account. No session, no identity,
    // no second account either.
    pollster::block_on(async {
        let kit = factory_zero_kit();
        seed_user(&kit, "nick@example.com", false).await;
        let response = sign_in(&kit).await;
        assert_ne!(response.status, StatusCode::FOUND, "{}", response.text());
        assert!(response.cookie("__Host-session").is_none());
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 0);
    });
}

#[test]
fn an_address_factory_zero_does_not_vouch_for_never_links() {
    // The mirror case: the account is verified, the provider's claim is not.
    pollster::block_on(async {
        let kit = factory_zero_kit();
        seed_user(&kit, "nick@example.com", true).await;
        kit.provider.set_claims(TokenClaims {
            email_verified: false,
            ..TokenClaims::factory_zero()
        });
        let response = sign_in(&kit).await;
        assert_ne!(response.status, StatusCode::FOUND, "{}", response.text());
        assert_eq!(count(&kit, "identities"), 0);
    });
}

#[test]
fn an_rs256_token_claiming_factory_zero_is_refused() {
    // The algorithm is pinned to ES256 for this provider. An RS256 token from
    // anything claiming the issuer is not believed, whatever the key says.
    pollster::block_on(async {
        let kit = factory_zero_kit();
        kit.provider.set_claims(TokenClaims {
            es256: false,
            ..TokenClaims::factory_zero()
        });
        let response = sign_in(&kit).await;
        assert_ne!(response.status, StatusCode::FOUND, "{}", response.text());
        assert_eq!(count(&kit, "users"), 0);
        assert_eq!(count(&kit, "identities"), 0);
    });
}

#[test]
fn a_token_from_another_issuer_is_refused() {
    pollster::block_on(async {
        let kit = factory_zero_kit();
        kit.provider.set_claims(TokenClaims {
            issuer: "https://evil.example".to_owned(),
            ..TokenClaims::factory_zero()
        });
        let response = sign_in(&kit).await;
        assert_ne!(response.status, StatusCode::FOUND, "{}", response.text());
        assert_eq!(count(&kit, "identities"), 0);
    });
}

#[test]
fn a_token_minted_for_another_client_is_refused() {
    // Another venture's client id must not be able to use this venture's
    // Factory Zero registration (audience check).
    pollster::block_on(async {
        let kit = factory_zero_kit();
        kit.provider.set_claims(TokenClaims {
            audience: "some-other-venture".to_owned(),
            ..TokenClaims::factory_zero()
        });
        let response = sign_in(&kit).await;
        assert_ne!(response.status, StatusCode::FOUND, "{}", response.text());
        assert_eq!(count(&kit, "identities"), 0);
    });
}

/// The resume token a link page carries, read out of one of its sign-in
/// links: the link's `return_to` is the resumed `/start`, percent-encoded.
fn resume_token(page: &str) -> String {
    let start = page.find("return_to=").expect("a sign-in link") + "return_to=".len();
    let end = start + page[start..].find('"').expect("the link ends");
    let resumed = percent_decode(&page[start..end]);
    resumed
        .split("resume=")
        .nth(1)
        .expect("the resumed start names a token")
        .to_owned()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("ascii");
            out.push(u8::from_str_radix(hex, 16).expect("hex"));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).expect("utf-8")
}

/// The link page: nobody is signed in to the venture yet.
async fn start_link_without_session(kit: &Kit) -> Res {
    get(kit, &format!("{START}?intent=link"), &[]).await
}

#[test]
fn a_link_without_a_venture_session_shows_sign_in_first_and_links_nothing() {
    // The guard: a link request never falls through to the plain sign-in
    // rules. No session means no redirect to Factory Zero, no flow, no
    // identity, and no account.
    pollster::block_on(async {
        let kit = factory_zero_kit();
        let response = start_link_without_session(&kit).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        assert!(response.location().is_none(), "redirected to a provider");
        assert!(
            response.cookie("__Host-auth_oidc").is_none(),
            "started a flow"
        );
        assert!(response.text().contains("Sign in to this service first"));
        assert!(
            !response.text().contains("Continue with Factory Zero"),
            "offered Factory Zero as a sign-in"
        );
        // The resume token rides in the sign-in links; the next test reads it.
        assert!(response.text().contains("return_to="), "no sign-in link");
        assert_eq!(count(&kit, "users"), 0);
        assert_eq!(count(&kit, "identities"), 0);
    });
}

#[test]
fn a_link_resumes_after_the_venture_sign_in_and_is_single_use() {
    pollster::block_on(async {
        let kit = factory_zero_kit();
        let token = resume_token(&start_link_without_session(&kit).await.text());

        // The person signs in to the venture (here: through Factory Zero's
        // own sign-in, which leaves a live venture session behind).
        let session = sign_in(&kit).await;
        let cookie = session.cookie("__Host-session").expect("a venture session");

        let resume = format!("{START}?intent=link&resume={token}");
        let resumed = get(&kit, &resume, &[("__Host-session", &cookie)]).await;
        assert_eq!(resumed.status, StatusCode::FOUND, "{}", resumed.text());
        assert!(
            resumed
                .location()
                .is_some_and(|l| l.starts_with("https://auth.factory0.ventures")),
            "the link did not continue to Factory Zero"
        );
        assert!(
            resumed.cookie("__Host-auth_oidc").is_some(),
            "no flow cookie"
        );

        // Spent: the same token cannot start a second link.
        let again = get(&kit, &resume, &[("__Host-session", &cookie)]).await;
        assert_eq!(again.status, StatusCode::BAD_REQUEST, "{}", again.text());
        assert!(again.location().is_none());
        assert!(again.cookie("__Host-auth_oidc").is_none());
    });
}

#[test]
fn a_link_token_expires() {
    pollster::block_on(async {
        let kit = factory_zero_kit();
        let token = resume_token(&start_link_without_session(&kit).await.text());
        let cookie = sign_in(&kit)
            .await
            .cookie("__Host-session")
            .expect("a venture session");

        kit.clock.advance_secs(601);
        let late = get(
            &kit,
            &format!("{START}?intent=link&resume={token}"),
            &[("__Host-session", &cookie)],
        )
        .await;
        assert_eq!(late.status, StatusCode::BAD_REQUEST, "{}", late.text());
        assert!(late.location().is_none());
    });
}

#[test]
fn a_link_token_is_not_honoured_for_another_provider() {
    pollster::block_on(async {
        let kit = factory_zero_kit();
        let token = resume_token(&start_link_without_session(&kit).await.text());
        let cookie = sign_in(&kit)
            .await
            .cookie("__Host-session")
            .expect("a venture session");

        let other = get(
            &kit,
            &format!("/v1/auth-oidc/google/start?intent=link&resume={token}"),
            &[("__Host-session", &cookie)],
        )
        .await;
        assert_eq!(other.status, StatusCode::BAD_REQUEST, "{}", other.text());
    });
}

#[test]
fn a_live_session_can_link_directly() {
    pollster::block_on(async {
        let kit = factory_zero_kit();
        let cookie = sign_in(&kit)
            .await
            .cookie("__Host-session")
            .expect("a venture session");
        let direct = get(
            &kit,
            &format!("{START}?intent=link"),
            &[("__Host-session", &cookie)],
        )
        .await;
        assert_eq!(direct.status, StatusCode::FOUND, "{}", direct.text());
    });
}
