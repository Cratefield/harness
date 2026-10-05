//! Issue #648 acceptance: changing the address an account is reached at.
//!
//! Most of what is asserted here is an *absence*: that a taken address and
//! a free one answer identically and no mail reaches the taken one, that a
//! wrong password and an old session are one answer, that a link works
//! once, and that the event carries an id and no address.
//!
//! Both dialects run ([`TestHarness::all_dialects_with_ports`]): SQLite in
//! memory always, Postgres when `FZ_TEST_POSTGRES_URL` names a server.

use cratefield_auth_core::{
    AuthCore, CREDENTIAL_PASSWORD, CredentialRow, EVENT_EMAIL_CHANGED, IdentityRow, Login,
    PROVIDER_PASSWORD, SingleUseTokenRow, TOKEN_EMAIL_CHANGE, UserRow, hash_password,
    insert_credential, insert_identity, insert_user, issue, user_by_id, user_by_primary_email,
};
use cratefield_core::{MapConfig, Module, Statement};
use cratefield_testing::{FixedClock, TestHarness};
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const HOUR: i64 = 3_600;
const OLD: &str = "ada@example.test";
const TAKEN: &str = "grace@example.test";
const FRESH: &str = "new@example.test";
const PASSWORD: &str = "a long enough password";

const CHANGE: &str = "/v1/auth-core/email/change";
const CONFIRM: &str = "/v1/auth-core/email/confirm";

// ---------------------------------------------------------------------------
// Harness

fn config() -> Arc<MapConfig> {
    Arc::new(MapConfig::from_pairs([
        (
            "AUTH_CORE_PUBLIC_BASE".to_owned(),
            "https://auth.example.test".to_owned(),
        ),
        (
            "AUTH_CORE_MAIL_FROM".to_owned(),
            "auth@example.test".to_owned(),
        ),
    ]))
}

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(AuthCore::new())],
        |ports| ports.config = config(),
    )
}

/// The same harness with a module alongside, for the one test that needs to
/// see what `auth-core` emits.
fn spy_kits(spy: &EventSpy) -> Vec<TestHarness> {
    let spy = spy.clone();
    TestHarness::all_dialects_with_ports(
        move || vec![Box::new(AuthCore::new()), Box::new(spy.clone())],
        |ports| ports.config = config(),
    )
}

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
}

fn iso(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .expect("epoch in range")
        .replace_nanosecond(0)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

/// An account, with the password credential *and* the `password` identity
/// `auth-password`'s registration writes when `password` is set, so the recency
/// rule has something to fall back on and the identity's subject is under test.
async fn account(kit: &TestHarness, id: &str, email: &str, password: bool) {
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: Some(email.to_owned()),
            primary_email_verified: true,
            locale: None,
            status: "active".to_owned(),
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
    if !password {
        return;
    }
    pollster::block_on(insert_identity(
        &*kit.db,
        &IdentityRow {
            id: format!("i-{id}"),
            user_id: id.to_owned(),
            provider: PROVIDER_PASSWORD.to_owned(),
            // The normalised address is this provider's subject.
            provider_subject: email.to_owned(),
            email: Some(email.to_owned()),
            email_verified: true,
            name_at_link: None,
            created_at: iso(EPOCH),
            last_login_at: None,
        },
    ))
    .expect("identity");
    pollster::block_on(insert_credential(
        &*kit.db,
        &CredentialRow {
            id: format!("c-{id}"),
            user_id: id.to_owned(),
            kind: CREDENTIAL_PASSWORD.to_owned(),
            passkey_credential_id: None,
            passkey_public_key_cose: None,
            passkey_sign_count: None,
            passkey_aaguid: None,
            passkey_transports: None,
            password_hash: Some(cratefield_auth_core::Redacted(
                hash_password(PASSWORD).expect("hashes"),
            )),
            label: None,
            created_at: iso(EPOCH),
            last_used_at: None,
            passkey_suspect_at: None,
            failed_attempts: 0,
            failed_window_started_at: None,
            locked_until: None,
        },
    ))
    .expect("credential");
}

/// A live session cookie, signed in `secs_ago` seconds before now — the clock
/// the row is written with is the caller's, so an old session can be had without
/// moving the harness's own clock.
async fn sign_in(kit: &TestHarness, user_id: &str, secs_ago: i64) -> String {
    issue(
        &*kit.db,
        &at(EPOCH - secs_ago),
        &cratefield_core::UlidIdGen,
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
    .expect("session")
    .value
}

// ---------------------------------------------------------------------------
// Requests

struct Res {
    status: StatusCode,
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn slug(&self) -> String {
        self.json()["type"].as_str().unwrap_or_default().to_owned()
    }
}

async fn send(
    kit: &TestHarness,
    method: Method,
    uri: &str,
    body: Option<Value>,
    extra: &[(String, String)],
) -> Res {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    for (name, value) in extra {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let response = kit
        .router
        .clone()
        .oneshot(
            builder
                .body(axum::body::Body::from(
                    body.map_or_else(String::new, |body| body.to_string()),
                ))
                .expect("request"),
        )
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        body: body.to_vec(),
    }
}

async fn change(kit: &TestHarness, session: &str, body: Value) -> Res {
    let extra = vec![(
        header::COOKIE.to_string(),
        format!("__Host-session={session}"),
    )];
    let response = send(kit, Method::POST, CHANGE, Some(body), &extra).await;
    kit.defer.drain().await;
    response
}

/// The same confirm as the GET page's button sends it: form-encoded bytes with
/// a form content type, not a JSON object.
async fn confirm_from_page(kit: &TestHarness, token: &str) -> Res {
    let response = kit
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(CONFIRM)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!("token={token}")))
                .expect("request"),
        )
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        body: body.to_vec(),
    }
}

async fn confirm(kit: &TestHarness, token: &str) -> Res {
    send(
        kit,
        Method::POST,
        CONFIRM,
        Some(json!({ "token": token })),
        &[],
    )
    .await
}

/// The token out of the link in the newest confirm mail, the way a person
/// would read it.
fn token_from(kit: &TestHarness) -> String {
    let message = kit
        .mailer
        .sent()
        .into_iter()
        .rev()
        .find(|message| message.text.contains("/v1/auth-core/email/confirm?token="))
        .expect("a confirm mail");
    let marker = "/v1/auth-core/email/confirm?token=";
    let start = message.text.find(marker).expect("marker") + marker.len();
    let rest = &message.text[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    rest[..end].to_owned()
}

fn mail_to(kit: &TestHarness, to: &str) -> Vec<cratefield_core::Message> {
    kit.mailer
        .sent()
        .into_iter()
        .filter(|message| message.to == to)
        .collect()
}

fn count(kit: &TestHarness, sql: &str) -> i64 {
    let rows = pollster::block_on(kit.db.query(&Statement::new(sql.to_owned()))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

fn tokens(kit: &TestHarness) -> i64 {
    count(kit, "SELECT COUNT(*) AS n FROM single_use_tokens")
}

fn count_of_kind(kit: &TestHarness, kind: &str) -> i64 {
    count(
        kit,
        &format!("SELECT COUNT(*) AS n FROM single_use_tokens WHERE kind = '{kind}'"),
    )
}

fn spent_of_kind(kit: &TestHarness, kind: &str) -> i64 {
    count(
        kit,
        &format!(
            "SELECT COUNT(*) AS n FROM single_use_tokens WHERE kind = '{kind}' \
             AND consumed_at IS NOT NULL"
        ),
    )
}

fn live_sessions(kit: &TestHarness) -> i64 {
    count(
        kit,
        "SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL",
    )
}

/// Whether a session cookie still validates — the question "am I still signed
/// in?" actually gets answered.
async fn live(kit: &TestHarness, value: &str) -> bool {
    cratefield_auth_core::validate(&*kit.db, &at(EPOCH), value)
        .await
        .expect("validate")
        .is_some()
}

fn email_of(kit: &TestHarness, id: &str) -> Option<String> {
    pollster::block_on(user_by_id(&*kit.db, id))
        .expect("query")
        .expect("a user")
        .primary_email
}

/// Whether `auth-password`'s sign-in would find this account by address: the
/// lookup it does, and nothing more, since its module is not a dev-dependency.
fn login_finds(kit: &TestHarness, email: &str) -> bool {
    pollster::block_on(user_by_primary_email(&*kit.db, email))
        .expect("query")
        .is_some()
}

/// The `password` identity row for an address. Its subject is the address and
/// `(provider, provider_subject)` is unique, so which subject a row holds is the
/// whole of what sign-in can find.
fn password_identity(kit: &TestHarness, email: &str) -> Option<IdentityRow> {
    pollster::block_on(cratefield_auth_core::identity_by_provider_subject(
        &*kit.db,
        PROVIDER_PASSWORD,
        email,
    ))
    .expect("query")
}

// ---------------------------------------------------------------------------
// Tests

/// The headline property: a free address and somebody else's answer identically,
/// the taken one is never mailed, and the old address is told either way — that
/// mail is the only signal its owner gets.
#[test]
fn a_taken_address_answers_exactly_as_a_free_one_and_the_old_one_is_told() {
    pollster::block_on(async {
        for kit in kits() {
            account(&kit, "ada", OLD, true).await;
            account(&kit, "grace", TAKEN, false).await;
            let ada = sign_in(&kit, "ada", 5).await;

            let free = change(&kit, &ada, json!({ "new_email": FRESH })).await;
            let taken = change(&kit, &ada, json!({ "new_email": TAKEN })).await;

            assert_eq!(free.status, StatusCode::ACCEPTED);
            assert_eq!(taken.status, free.status);
            assert_eq!(taken.json(), free.json(), "the bodies must be identical");

            // The link went to the free address and nowhere near the one
            // that already holds an account, and exactly one token was issued.
            assert_eq!(
                mail_to(&kit, FRESH).len(),
                1,
                "one link to the free address"
            );
            assert!(
                mail_to(&kit, TAKEN).is_empty(),
                "a taken address is never mailed"
            );
            assert_eq!(tokens(&kit), 1);

            let notices = mail_to(&kit, OLD);
            assert_eq!(notices.len(), 2, "one notice per request");
            for notice in &notices {
                assert!(
                    notice.text.contains("email address is being changed"),
                    "{}",
                    notice.text
                );
                // The "this wasn't me" line names somewhere to write.
                assert!(notice.text.contains("this was not you"), "{}", notice.text);
            }
            // The refused one names the address it would have moved to, which is
            // what lets its owner recognise the attempt.
            assert!(notices[1].text.contains(TAKEN), "{}", notices[1].text);
        }
    });
}

/// Confirm moves the address, marks it verified, spends the link, and announces
/// the change with an id and no address.
#[test]
fn confirming_moves_the_address_and_announces_it_with_ids_only() {
    pollster::block_on(async {
        let spy = EventSpy::new(&[EVENT_EMAIL_CHANGED]);
        for kit in spy_kits(&spy) {
            spy.seen.write().expect("lock").clear();
            account(&kit, "ada", OLD, true).await;
            let ada = sign_in(&kit, "ada", 5).await;
            change(&kit, &ada, json!({ "new_email": FRESH })).await;
            let token = token_from(&kit);

            let response = confirm(&kit, &token).await;
            assert_eq!(response.status, StatusCode::OK, "{}", response.text());

            let user = pollster::block_on(user_by_id(&*kit.db, "ada"))
                .expect("query")
                .unwrap();
            assert_eq!(user.primary_email.as_deref(), Some(FRESH));
            assert!(user.primary_email_verified);
            assert_eq!(email_of(&kit, "ada").as_deref(), Some(FRESH));

            let seen = spy.seen.read().expect("lock").clone();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].0, EVENT_EMAIL_CHANGED);
            assert_eq!(seen[0].1, json!({ "user_id": "ada" }));
            // Ids only: an address in the payload is what this event must never carry.
            assert!(!seen[0].1.to_string().contains("example.test"));
        }
    });
}

/// The reason confirm moves the `password` identity too. Sign-in finds the
/// account by address and this provider's identity subject *is* that address:
/// leave it behind and the person must sign in with the address they just gave
/// up, and nobody may ever register it again, because
/// `(provider, provider_subject)` is unique and still held.
#[test]
fn confirming_moves_the_password_identity_so_sign_in_follows_the_address() {
    pollster::block_on(async {
        for kit in kits() {
            account(&kit, "ada", OLD, true).await;
            let ada = sign_in(&kit, "ada", 5).await;
            change(&kit, &ada, json!({ "new_email": FRESH })).await;
            assert_eq!(
                confirm(&kit, &token_from(&kit)).await.status,
                StatusCode::OK
            );

            // Sign-in's own lookup: the new address finds the account, the old
            // one does not.
            assert!(login_finds(&kit, FRESH), "the new address signs in");
            assert!(!login_finds(&kit, OLD), "the old address does not");
            assert_eq!(
                password_identity(&kit, FRESH)
                    .expect("the identity follows")
                    .user_id,
                "ada"
            );
            assert!(
                password_identity(&kit, OLD).is_none(),
                "the old subject is released for whoever registers it next"
            );
            // The hash is untouched: this moved the address, not the secret.
            assert!(
                pollster::block_on(cratefield_auth_core::password_credential(&*kit.db, "ada"))
                    .expect("query")
                    .expect("a password credential")
                    .password_hash
                    .is_some()
            );
        }
    });
}

/// The confirm page's button posts form-encoded bytes. If confirm only read
/// JSON, that button would answer 415 and the page would be a dead end.
#[test]
fn the_confirm_pages_button_works() {
    pollster::block_on(async {
        for kit in kits() {
            account(&kit, "ada", OLD, true).await;
            let ada = sign_in(&kit, "ada", 5).await;
            change(&kit, &ada, json!({ "new_email": FRESH })).await;
            let token = token_from(&kit);

            let response = confirm_from_page(&kit, &token).await;
            // A browser gets a page, not a JSON document — but it is the same
            // 200 the API caller gets, and the address moved.
            assert_eq!(response.status, StatusCode::OK, "{}", response.text());
            assert!(response.text().contains("<!doctype html>"));
            assert_eq!(email_of(&kit, "ada").as_deref(), Some(FRESH));

            // And a spent one reads as a page saying so, not as a problem
            // document an API client would know how to parse.
            let again = confirm_from_page(&kit, &token).await;
            assert_eq!(again.status, StatusCode::BAD_REQUEST);
            assert!(again.text().contains("no longer valid"));
        }
    });
}

/// A link works once, and past the hour it is gone. A link that cannot be
/// honoured is the same answer as one that never existed.
#[test]
fn a_link_works_once_and_expires_after_an_hour() {
    pollster::block_on(async {
        for kit in kits() {
            account(&kit, "ada", OLD, true).await;
            let ada = sign_in(&kit, "ada", 5).await;
            change(&kit, &ada, json!({ "new_email": FRESH })).await;
            let token = token_from(&kit);

            assert_eq!(confirm(&kit, &token).await.status, StatusCode::OK);
            let again = confirm(&kit, &token).await;
            assert_eq!(again.status, StatusCode::BAD_REQUEST);
            assert_eq!(again.slug(), confirm(&kit, "never-issued").await.slug());
            // And a spent link cannot move the address a second time.
            assert_eq!(email_of(&kit, "ada").as_deref(), Some(FRESH));

            // The harness's clock is fixed, so the hour is crossed by ageing
            // the row: `expires_at` is what the guarded consume reads, and it
            // now sits an hour behind "now". Scoped to the unspent row, so the
            // link already used above is left alone.
            account(&kit, "bob", "bob@example.test", false).await;
            let bob = sign_in(&kit, "bob", 5).await;
            change(&kit, &bob, json!({ "new_email": "b@example.test" })).await;
            let second = token_from(&kit);
            let expired = pollster::block_on(kit.db.execute(&Statement::new(format!(
                "UPDATE single_use_tokens SET expires_at = '{}' WHERE consumed_at IS NULL",
                iso(EPOCH - HOUR)
            ))))
            .expect("expire");
            assert_eq!(expired, 1);

            let response = confirm(&kit, &second).await;
            assert_eq!(response.status, StatusCode::BAD_REQUEST);
            assert_eq!(email_of(&kit, "bob").as_deref(), Some("bob@example.test"));
        }
    });
}

/// Confirming revokes the account's other sessions — the address moved, so a
/// session signed in against the old one is a way in. The session that carried
/// the confirm survives, because that person is mid-flow.
#[test]
fn confirming_revokes_the_accounts_other_sessions() {
    pollster::block_on(async {
        for kit in kits() {
            account(&kit, "ada", OLD, true).await;
            let first = sign_in(&kit, "ada", 5).await;
            let second = sign_in(&kit, "ada", 5).await;
            change(&kit, &first, json!({ "new_email": FRESH })).await;
            let token = token_from(&kit);

            // Confirming *with* the session cookie: that one survives.
            let extra = vec![(
                header::COOKIE.to_string(),
                format!("__Host-session={first}"),
            )];
            let kept = send(
                &kit,
                Method::POST,
                CONFIRM,
                Some(json!({ "token": token })),
                &extra,
            )
            .await;
            assert_eq!(kept.status, StatusCode::OK, "{}", kept.text());
            assert_eq!(
                live_sessions(&kit),
                1,
                "only the confirming session survives"
            );
            assert!(live(&kit, &first).await, "the confirming session is live");
            assert!(!live(&kit, &second).await, "the other is revoked");
        }
    });
}

/// The one thing the address change must not be reachable on: a session nobody
/// re-proved. With a password credential the caller can re-prove it; without
/// one there is nothing to re-prove with, so only a recent session gets through.
#[test]
fn an_old_session_needs_the_password_back() {
    pollster::block_on(async {
        for kit in kits() {
            account(&kit, "ada", OLD, true).await;
            account(&kit, "bob", "bob@example.test", false).await;
            let old_with_password = sign_in(&kit, "ada", 2 * HOUR).await;
            let old_without = sign_in(&kit, "bob", 2 * HOUR).await;
            let fresh = sign_in(&kit, "bob", 60).await;

            let refused = change(&kit, &old_with_password, json!({ "new_email": FRESH })).await;
            assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text());
            assert!(refused.slug().ends_with("reauthentication-required"));

            let wrong = change(
                &kit,
                &old_with_password,
                json!({ "new_email": FRESH, "current_password": "not it" }),
            )
            .await;
            assert_eq!(wrong.status, refused.status);
            assert_eq!(wrong.json()["type"], refused.json()["type"]);

            let right = change(
                &kit,
                &old_with_password,
                json!({ "new_email": FRESH, "current_password": PASSWORD }),
            )
            .await;
            assert_eq!(right.status, StatusCode::ACCEPTED, "{}", right.text());

            // No password credential to re-enter: recency is all there is.
            let want = json!({ "new_email": "b@example.test" });
            assert_eq!(
                change(&kit, &old_without, want.clone()).await.status,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                change(&kit, &fresh, want).await.status,
                StatusCode::ACCEPTED
            );
        }
    });
}

/// An address free when the link was mailed may not be by the time it is opened:
/// taking it would swallow somebody else's account, and the refusal must be the
/// one a bad link gets. A token of another kind is not ours to spend either.
#[test]
fn a_refused_token_looks_the_same_whether_it_is_stale_taken_or_another_kind() {
    pollster::block_on(async {
        let other = "A".repeat(43);
        for kit in kits() {
            account(&kit, "ada", OLD, true).await;
            let ada = sign_in(&kit, "ada", 5).await;
            change(&kit, &ada, json!({ "new_email": FRESH })).await;
            let token = token_from(&kit);
            let bad = confirm(&kit, "nope").await;

            // Somebody registers the address in the meantime.
            account(&kit, "grace", FRESH, false).await;
            let now_taken = confirm(&kit, &token).await;
            assert_eq!(now_taken.status, StatusCode::BAD_REQUEST);
            assert_eq!(now_taken.json()["type"], bad.json()["type"]);
            assert_eq!(email_of(&kit, "ada").as_deref(), Some(OLD));

            pollster::block_on(cratefield_auth_core::insert_single_use_token(
                &*kit.db,
                &SingleUseTokenRow {
                    id: "tok-1".to_owned(),
                    kind: "magic_link".to_owned(),
                    token_hash: {
                        use sha2::Digest as _;
                        cratefield_auth_core::Redacted(
                            sha2::Sha256::digest(other.as_bytes()).to_vec(),
                        )
                    },
                    user_id: Some("ada".to_owned()),
                    client_id: None,
                    payload: None,
                    expires_at: iso(EPOCH + HOUR),
                    consumed_at: None,
                },
            ))
            .expect("token");
            assert_eq!(
                confirm(&kit, &other).await.json()["type"],
                bad.json()["type"]
            );
            // And that row is untouched: another kind's link is not ours to
            // spend. (The taken-address attempt above *did* spend its own —
            // spending first is what makes the link single-use, whether or not
            // the move then goes ahead.)
            assert_eq!(spent_of_kind(&kit, "magic_link"), 0);
        }
    });
}

/// Everything but the answer is invisible from outside: no mail, no token, and a
/// body that says nothing about who holds the address. A second request retires
/// the first link, so only the newest one works.
#[test]
fn a_request_without_a_session_does_nothing_and_a_second_one_retires_the_first_link() {
    pollster::block_on(async {
        for kit in kits() {
            account(&kit, "ada", OLD, true).await;
            let anon = send(
                &kit,
                Method::POST,
                CHANGE,
                Some(json!({ "new_email": FRESH })),
                &[],
            )
            .await;
            assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
            kit.defer.drain().await;
            assert!(kit.mailer.sent().is_empty());
            assert_eq!(tokens(&kit), 0);

            let ada = sign_in(&kit, "ada", 5).await;
            change(&kit, &ada, json!({ "new_email": "one@example.test" })).await;
            let first = token_from(&kit);
            change(&kit, &ada, json!({ "new_email": "two@example.test" })).await;
            let second = token_from(&kit);
            assert_ne!(first, second);

            assert_eq!(confirm(&kit, &first).await.status, StatusCode::BAD_REQUEST);
            assert_eq!(confirm(&kit, &second).await.status, StatusCode::OK);
            assert_eq!(email_of(&kit, "ada").as_deref(), Some("two@example.test"));
            assert_eq!(
                count_of_kind(&kit, TOKEN_EMAIL_CHANGE),
                2,
                "both rows remain, one spent"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Event spy

/// A module that subscribes to the events a test names and keeps every
/// payload, so the test can assert on what actually leaves the service.
#[derive(Clone, Default)]
struct EventSpy {
    seen: Arc<RwLock<Vec<(String, Value)>>>,
    events: &'static [&'static str],
}

impl EventSpy {
    fn new(events: &'static [&'static str]) -> Self {
        Self {
            seen: Arc::default(),
            events,
        }
    }
}

impl Module for EventSpy {
    fn name(&self) -> &'static str {
        "event-spy"
    }

    fn version(&self) -> &'static str {
        "0.0.0"
    }

    fn requires(&self) -> &'static [cratefield_core::Port] {
        &[]
    }

    fn migrations(&self) -> cratefield_core::Migrations {
        cratefield_core::Migrations::EMPTY
    }

    fn validate_config(
        &self,
        _cfg: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }

    fn router(&self, _ctx: cratefield_core::ModuleContext) -> axum::Router {
        axum::Router::new()
    }

    fn events(&self) -> Vec<(cratefield_core::EventName, cratefield_core::EventHandler)> {
        self.events
            .iter()
            .map(|name| {
                let seen = Arc::clone(&self.seen);
                let event = (*name).to_owned();
                let handler: cratefield_core::EventHandler = Arc::new(
                    move |_scope: &cratefield_core::Scope,
                          payload: Value|
                          -> cratefield_core::BoxFuture<
                        'static,
                        Result<(), cratefield_core::AnyError>,
                    > {
                        seen.write().expect("lock").push((event.clone(), payload));
                        Box::pin(async { Ok(()) })
                    },
                );
                ((*name).to_owned(), handler)
            })
            .collect()
    }
}
