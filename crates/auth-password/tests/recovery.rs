//! Issues #19 and #20 end to end: address verification, and getting back
//! in without the old password.
//!
//! These run on every dialect the environment provides
//! ([`TestHarness::all_dialects_with_ports`]): SQLite in memory always,
//! Postgres when `FZ_TEST_POSTGRES_URL` names a server, which
//! `.github/workflows/parity.yml` provides.
//!
//! Most of what is asserted here is an *absence*: that a taken address and
//! a free one answer identically, that a link works once, that a GET never
//! spends one, and that no event carries an address.

mod common;

use common::{
    EventSpy, Res, exec, get, post_form_fields, post_json, post_json_with, scalar, send,
    user_id_of, verified,
};
use cratefield_testing::TestHarness;
use factory0_auth_core::{
    AuthCore, Redacted, STATUS_ACTIVE, SingleUseTokenRow, TOKEN_REFRESH, UserRow,
    insert_single_use_token, insert_user,
};
use factory0_auth_password::Password;
use http::{Method, StatusCode};
use serde_json::{Value, json};

const BASE: &str = "https://auth.example.test";
const LOGIN: &str = "/v1/auth-password/login";
const CHANGE: &str = "/v1/auth-password/change";
const VERIFY: &str = "/v1/auth-password/verify";
const RESEND: &str = "/v1/auth-password/verify/resend";
const RESET: &str = "/v1/auth-password/reset";
const RESET_REQUEST: &str = "/v1/auth-password/reset/request";

const GOOD: &str = "a long enough password";
const NEW: &str = "a different long password";

const VERIFY_LINK: &str = "/v1/auth-password/verify?token=";
const RESET_LINK: &str = "/v1/auth-password/reset?token=";

const FORM: &str = "application/x-www-form-urlencoded";

/// The events this suite subscribes to.
const EVENTS: &[&str] = &["auth-password.email_verified", "auth-password.reset"];

// ---------------------------------------------------------------------------
// Harness

fn kits() -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(AuthCore::new()), Box::new(Password::new())],
        |ports| {
            ports.config = common::config_with(Vec::new());
        },
    )
}

fn kits_with_pairs(extra: Vec<(String, String)>) -> Vec<TestHarness> {
    TestHarness::all_dialects_with_ports(
        || vec![Box::new(AuthCore::new()), Box::new(Password::new())],
        move |ports| {
            ports.config = common::config_with(extra.clone());
        },
    )
}

fn spy_kits(spy: &EventSpy) -> Vec<TestHarness> {
    let spy = spy.clone();
    TestHarness::all_dialects_with_ports(
        move || {
            vec![
                Box::new(AuthCore::new()),
                Box::new(Password::new()),
                Box::new(spy.clone()),
            ]
        },
        |ports| {
            ports.config = common::config_with(Vec::new());
        },
    )
}

/// Registers with the suite's happy-path password, and runs the mail the
/// request deferred so the mailbox is settled before the caller looks.
async fn register(kit: &TestHarness, email: &str) -> Res {
    let response = common::register(kit, email, GOOD).await;
    settle(kit).await;
    response
}

async fn resend(kit: &TestHarness, email: &str) -> Res {
    let response = post_json(kit, RESEND, json!({ "email": email })).await;
    settle(kit).await;
    response
}

async fn request_reset(kit: &TestHarness, email: &str) -> Res {
    let response = post_json(kit, RESET_REQUEST, json!({ "email": email })).await;
    settle(kit).await;
    response
}

/// Runs whatever a request deferred. In production the answer never waits
/// on the mailer (the work runs in `wait_until`); here the harness's defer
/// collects it, and this is what runs it.
async fn settle(kit: &TestHarness) {
    kit.defer.drain().await;
}

/// The token out of the link in the newest mail whose text carries
/// `marker`, the way a person would read it.
fn token_from(kit: &TestHarness, marker: &str) -> String {
    let message = kit
        .mailer
        .sent()
        .into_iter()
        .rev()
        .find(|message| message.text.contains(marker))
        .unwrap_or_else(|| panic!("no mail carrying {marker}"));
    let start = message.text.find(marker).expect("marker") + marker.len();
    let rest = &message.text[start..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    rest[..end].to_owned()
}

fn event_names(spy: &EventSpy) -> Vec<String> {
    spy.seen
        .read()
        .expect("lock")
        .iter()
        .map(|(name, _)| name.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Neutral answers: a taken address and a free one are indistinguishable

#[test]
fn register_verify_resend_and_reset_request_answer_neutrally() {
    for kit in kits() {
        pollster::block_on(async {
            // A taken address and a free one answer byte for byte the same
            // at register, even though one mails a duplicate notice and
            // the other a verification link.
            let taken = register(&kit, "ada@example.com").await;
            let again = register(&kit, "ada@example.com").await;
            let fresh = register(&kit, "grace@example.com").await;
            assert_eq!(taken.status, StatusCode::ACCEPTED);
            assert_eq!(taken.json()["status"], "accepted");
            assert_eq!(taken.body, again.body, "the bodies differ");
            assert_eq!(taken.body, fresh.body, "the bodies differ");

            // /verify/resend: a known address, an unknown one and a
            // verified one are one answer.
            let known = resend(&kit, "ada@example.com").await;
            let unknown = resend(&kit, "nobody@example.com").await;
            let unshaped = resend(&kit, "not an address").await;
            assert_eq!(known.status, StatusCode::ACCEPTED);
            assert_eq!(known.body, unknown.body);
            assert_eq!(known.body, unshaped.body);

            // /reset/request: the same.
            let known = request_reset(&kit, "ada@example.com").await;
            let unknown = request_reset(&kit, "nobody@example.com").await;
            assert_eq!(known.status, StatusCode::ACCEPTED);
            assert_eq!(known.body, unknown.body);
        });
    }
}

#[test]
fn the_duplicate_notice_goes_only_to_the_existing_address() {
    for kit in kits() {
        pollster::block_on(async {
            let first = register(&kit, "ada@example.com").await;
            assert_eq!(first.status, StatusCode::ACCEPTED);
            // A new account gets a verification mail, and nothing else.
            let after_new = kit.mailer.sent();
            assert_eq!(after_new.len(), 1, "one mail for a new account");
            assert!(
                after_new[0].text.contains("Confirm your address"),
                "{}",
                after_new[0].text
            );

            // Registering it again mails the *owner* a duplicate notice.
            register(&kit, "ada@example.com").await;
            let after_duplicate = kit.mailer.sent();
            assert_eq!(after_duplicate.len(), 2);
            let notice = &after_duplicate[1];
            assert_eq!(notice.to, "ada@example.com");
            assert!(notice.text.contains("already has one"), "{}", notice.text);
            // And it points at the hosted reset-request page.
            assert!(
                notice
                    .text
                    .contains(&format!("{BASE}/v1/auth-password/reset/request")),
                "{}",
                notice.text
            );
            assert_eq!(notice.tags, vec!["auth-password".to_owned()]);
        });
    }
}

#[test]
fn a_reset_link_goes_only_to_an_account_with_a_password() {
    for kit in kits() {
        pollster::block_on(async {
            // An account with no password credential (a magic-link-only
            // account, say) is never mailed a way past a password it does
            // not have.
            let passwordless = UserRow {
                id: "passwordless-1".to_owned(),
                display_name: None,
                primary_email: Some("link-only@example.com".to_owned()),
                primary_email_verified: true,
                status: STATUS_ACTIVE.to_owned(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                updated_at: "2026-01-01T00:00:00Z".to_owned(),
            };
            insert_user(&*kit.db, &passwordless).await.expect("insert");

            let before = kit.mailer.sent().len();
            let response = request_reset(&kit, "link-only@example.com").await;
            assert_eq!(response.status, StatusCode::ACCEPTED);
            assert_eq!(
                kit.mailer.sent().len(),
                before,
                "a passwordless account was mailed a reset link"
            );

            // An account with a password does get one.
            register(&kit, "ada@example.com").await;
            let before = kit.mailer.sent().len();
            request_reset(&kit, "ada@example.com").await;
            let sent = kit.mailer.sent();
            assert_eq!(sent.len(), before + 1);
            assert!(
                sent.last()
                    .expect("sent")
                    .text
                    .contains("Reset your password")
            );
        });
    }
}

#[test]
fn an_address_that_is_not_an_address_is_never_mailed() {
    for kit in kits() {
        pollster::block_on(async {
            // A control character in the domain passes the shape guard the
            // module applies to decide whether to look an address up, and
            // is refused by `is_valid` where the mail is decided. The
            // answer is the neutral one either way; nothing is sent.
            let before = kit.mailer.sent().len();
            let response = register(&kit, "grace@example.com\u{7}").await;
            assert_eq!(response.status, StatusCode::ACCEPTED);
            assert_eq!(
                kit.mailer.sent().len(),
                before,
                "an invalid address was mailed"
            );
        });
    }
}

// ---------------------------------------------------------------------------
// The hosted pages

#[test]
fn the_hosted_request_forms_mail_the_link() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;

            // The hosted pages post `application/x-www-form-urlencoded`, so
            // a handler that reads only a JSON body would answer the
            // neutral `202` and mail nothing: the page would appear to
            // work and do nothing at all.
            let before = kit.mailer.sent().len();
            let resent = post_form_fields(&kit, RESEND, &[("email", "ada@example.com")]).await;
            settle(&kit).await;
            assert_eq!(resent.status, StatusCode::ACCEPTED, "{}", resent.text());
            assert_eq!(
                kit.mailer.sent().len(),
                before + 1,
                "the hosted resend form sent nothing"
            );
            assert!(
                kit.mailer
                    .sent()
                    .last()
                    .expect("sent")
                    .text
                    .contains("Confirm your address")
            );

            let before = kit.mailer.sent().len();
            let asked =
                post_form_fields(&kit, RESET_REQUEST, &[("email", "ada@example.com")]).await;
            settle(&kit).await;
            assert_eq!(asked.status, StatusCode::ACCEPTED, "{}", asked.text());
            // And the answer is a page, not a JSON object in a browser.
            assert!(
                asked
                    .header("content-type")
                    .is_some_and(|value| value.starts_with("text/html")),
                "{:?}",
                asked.header("content-type")
            );
            let sent = kit.mailer.sent();
            assert_eq!(sent.len(), before + 1, "the hosted reset form sent nothing");
            assert_eq!(sent.last().expect("sent").to, "ada@example.com");
            assert!(
                sent.last()
                    .expect("sent")
                    .text
                    .contains("Reset your password")
            );
        });
    }
}

#[test]
fn the_hosted_pages_are_not_stored_or_referrer_leaked() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            let verify_token = token_from(&kit, VERIFY_LINK);
            request_reset(&kit, "ada@example.com").await;
            let reset_token = token_from(&kit, RESET_LINK);

            // The two token pages, the request form, and the pages a form
            // post answers with. A token in a URL is exactly what must not
            // sit in a shared cache or ride along as a `Referer`.
            let pages = vec![
                get(&kit, &format!("{VERIFY}?token={verify_token}")).await,
                get(&kit, &format!("{RESET}?token={reset_token}")).await,
                get(&kit, RESET_REQUEST).await,
                post_form_fields(&kit, VERIFY, &[("token", &verify_token)]).await,
                post_form_fields(&kit, RESEND, &[("email", "ada@example.com")]).await,
            ];
            for page in pages {
                assert_eq!(
                    page.header("cache-control"),
                    Some("no-store"),
                    "{}",
                    page.text()
                );
                assert_eq!(
                    page.header("referrer-policy"),
                    Some("no-referrer"),
                    "{}",
                    page.text()
                );
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Verification

#[test]
fn verifying_marks_the_address_and_works_once() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            assert!(!verified(&kit, "ada@example.com"), "unverified to start");
            let token = token_from(&kit, VERIFY_LINK);

            let first = post_json(&kit, VERIFY, json!({ "token": token })).await;
            assert_eq!(first.status, StatusCode::OK, "{}", first.text());
            assert!(verified(&kit, "ada@example.com"));

            // The same token again is refused, and the refusal is the one
            // answer for every bad token.
            let second = post_json(&kit, VERIFY, json!({ "token": token })).await;
            assert_eq!(second.status, StatusCode::BAD_REQUEST);
            let bogus = post_json(&kit, VERIFY, json!({ "token": "a".repeat(43) })).await;
            assert_eq!(bogus.status, StatusCode::BAD_REQUEST);
            assert_eq!(second.body, bogus.body, "the refusals differ");
        });
    }
}

#[test]
fn an_expired_token_is_refused() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            let token = token_from(&kit, VERIFY_LINK);
            exec(
                &kit,
                "UPDATE single_use_tokens SET expires_at = '2000-01-01T00:00:00Z' \
                 WHERE kind = 'email_verification'",
            );
            let response = post_json(&kit, VERIFY, json!({ "token": token })).await;
            assert_eq!(response.status, StatusCode::BAD_REQUEST);
            assert!(!verified(&kit, "ada@example.com"));
        });
    }
}

#[test]
fn a_get_never_consumes_the_token() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            let token = token_from(&kit, VERIFY_LINK);

            // The confirm page, exactly as a mail scanner would fetch it.
            let page = get(&kit, &format!("{VERIFY}?token={token}")).await;
            assert_eq!(page.status, StatusCode::OK);
            assert!(page.text().contains("Confirm"), "{}", page.text());
            assert!(
                !verified(&kit, "ada@example.com"),
                "a GET verified the address"
            );

            // The button still works afterwards.
            let done = post_json(&kit, VERIFY, json!({ "token": token })).await;
            assert_eq!(done.status, StatusCode::OK, "{}", done.text());
            assert!(verified(&kit, "ada@example.com"));
        });
    }
}

#[test]
fn the_hosted_form_posts_the_token_and_a_cross_site_post_is_refused() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            let token = token_from(&kit, VERIFY_LINK);

            // A cross-site POST is turned away before anything is spent.
            let cross = send(
                &kit,
                Method::POST,
                VERIFY,
                Some(FORM),
                &format!("token={token}"),
                &[
                    ("origin", "https://evil.example"),
                    ("host", "auth.example.test"),
                ],
            )
            .await;
            assert_eq!(cross.status, StatusCode::FORBIDDEN);
            assert!(!verified(&kit, "ada@example.com"));

            // The hosted page's own form POST does the work, answering
            // with a page rather than JSON.
            let posted = post_form_fields(&kit, VERIFY, &[("token", &token)]).await;
            assert_eq!(posted.status, StatusCode::OK, "{}", posted.text());
            assert!(
                posted
                    .header("content-type")
                    .is_some_and(|value| value.starts_with("text/html")),
                "{:?}",
                posted.header("content-type")
            );
            assert!(posted.text().contains("<!doctype"));
            assert!(verified(&kit, "ada@example.com"));
        });
    }
}

#[test]
fn verifying_announces_only_the_flip() {
    let spy = EventSpy::new(EVENTS);
    for kit in spy_kits(&spy) {
        spy.seen.write().expect("lock").clear();
        pollster::block_on(async {
            // An address that is already verified (it walked the magic-link
            // path first, say): confirming spends the token and changes
            // nothing, so nothing is announced.
            register(&kit, "ada@example.com").await;
            let token = token_from(&kit, VERIFY_LINK);
            exec(
                &kit,
                "UPDATE users SET primary_email_verified = 1 \
                 WHERE primary_email = 'ada@example.com'",
            );
            let confirmed = post_json(&kit, VERIFY, json!({ "token": token })).await;
            assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.text());
            assert!(
                !event_names(&spy).contains(&"auth-password.email_verified".to_owned()),
                "a token that changed nothing was announced"
            );

            // An address that was not verified: the flip is announced.
            register(&kit, "grace@example.com").await;
            let token = token_from(&kit, VERIFY_LINK);
            let confirmed = post_json(&kit, VERIFY, json!({ "token": token })).await;
            assert_eq!(confirmed.status, StatusCode::OK);
            assert!(
                event_names(&spy).contains(&"auth-password.email_verified".to_owned()),
                "the flip was not announced: {:?}",
                event_names(&spy)
            );
        });
    }
}

// ---------------------------------------------------------------------------
// Reset

#[test]
fn resetting_changes_the_password_and_revokes_every_way_in() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            let user_id = user_id_of(&kit, "ada@example.com");

            // A live session, and a refresh token, to be revoked.
            let login = post_json(
                &kit,
                LOGIN,
                json!({ "email": "ada@example.com", "password": GOOD }),
            )
            .await;
            assert_eq!(login.status, StatusCode::OK);
            assert_eq!(
                scalar(
                    &kit,
                    "SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL"
                ),
                1
            );
            insert_single_use_token(
                &*kit.db,
                &SingleUseTokenRow {
                    id: "refresh-1".to_owned(),
                    kind: TOKEN_REFRESH.to_owned(),
                    token_hash: Redacted(vec![7; 32]),
                    user_id: Some(user_id.clone()),
                    client_id: None,
                    payload: None,
                    expires_at: "2999-01-01T00:00:00Z".to_owned(),
                    consumed_at: None,
                },
            )
            .await
            .expect("insert refresh token");

            // Ask for a reset, read the link, spend it.
            request_reset(&kit, "ada@example.com").await;
            let token = token_from(&kit, RESET_LINK);
            let done = post_json(&kit, RESET, json!({ "token": token, "new_password": NEW })).await;
            assert_eq!(done.status, StatusCode::OK, "{}", done.text());

            // The old password no longer works.
            let old = post_json(
                &kit,
                LOGIN,
                json!({ "email": "ada@example.com", "password": GOOD }),
            )
            .await;
            assert_eq!(old.status, StatusCode::UNAUTHORIZED);

            // Every session and every refresh token is gone. Checked
            // before signing in again, which would mint a new one.
            assert_eq!(
                scalar(
                    &kit,
                    "SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL"
                ),
                0,
                "a session survived the reset"
            );
            assert_eq!(
                scalar(
                    &kit,
                    "SELECT COUNT(*) AS n FROM single_use_tokens \
                     WHERE kind = 'refresh_token' AND consumed_at IS NULL"
                ),
                0,
                "a refresh token survived the reset"
            );

            // And the new password does work — the reset did not lock
            // anybody out.
            let fresh = post_json(
                &kit,
                LOGIN,
                json!({ "email": "ada@example.com", "password": NEW }),
            )
            .await;
            assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text());
        });
    }
}

#[test]
fn a_password_change_retires_an_outstanding_reset_link() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            // A reset link the account asked for and has not used.
            request_reset(&kit, "ada@example.com").await;
            let stale = token_from(&kit, RESET_LINK);

            // Sign in and change the password.
            let login = post_json(
                &kit,
                LOGIN,
                json!({ "email": "ada@example.com", "password": GOOD }),
            )
            .await;
            let cookie = login.cookie("__Host-fz_session").expect("a session cookie");
            let changed = post_json_with(
                &kit,
                CHANGE,
                json!({ "current_password": GOOD, "new_password": NEW }),
                &[("cookie", &format!("__Host-fz_session={cookie}"))],
            )
            .await;
            assert_eq!(changed.status, StatusCode::OK, "{}", changed.text());

            // The link that was out no longer works: the change is the
            // whole remediation, and a link somebody else asked for would
            // undo it.
            let stale_use = post_json(
                &kit,
                RESET,
                json!({ "token": stale, "new_password": "yet another long password" }),
            )
            .await;
            assert_eq!(
                stale_use.status,
                StatusCode::BAD_REQUEST,
                "a reset link outlived the password change"
            );

            // And the change itself took.
            let fresh = post_json(
                &kit,
                LOGIN,
                json!({ "email": "ada@example.com", "password": NEW }),
            )
            .await;
            assert_eq!(fresh.status, StatusCode::OK);
        });
    }
}

#[test]
fn a_reset_clears_the_lockout() {
    for kit in kits_with_pairs(vec![(
        "AUTH_PASSWORD_LOCKOUT_THRESHOLD".to_owned(),
        "2".to_owned(),
    )]) {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            // Two wrong passwords lock the credential.
            for _ in 0..2 {
                post_json(
                    &kit,
                    LOGIN,
                    json!({ "email": "ada@example.com", "password": "wrong password" }),
                )
                .await;
            }
            assert_eq!(
                scalar(
                    &kit,
                    "SELECT COUNT(*) AS n FROM credentials WHERE locked_until IS NOT NULL"
                ),
                1,
                "the credential was not locked"
            );

            request_reset(&kit, "ada@example.com").await;
            let token = token_from(&kit, RESET_LINK);
            let done = post_json(&kit, RESET, json!({ "token": token, "new_password": NEW })).await;
            assert_eq!(done.status, StatusCode::OK);

            // A proven reset is proof the person holds the credential, so
            // the lockout is gone with the old password.
            let fresh = post_json(
                &kit,
                LOGIN,
                json!({ "email": "ada@example.com", "password": NEW }),
            )
            .await;
            assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text());
        });
    }
}

#[test]
fn a_reset_link_works_once_and_a_rejected_password_does_not_spend_it() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            request_reset(&kit, "ada@example.com").await;
            let token = token_from(&kit, RESET_LINK);

            // A password the policy refuses does not cost the link.
            let short = post_json(
                &kit,
                RESET,
                json!({ "token": token, "new_password": "short" }),
            )
            .await;
            assert_eq!(short.status, StatusCode::BAD_REQUEST);

            let done = post_json(&kit, RESET, json!({ "token": token, "new_password": NEW })).await;
            assert_eq!(done.status, StatusCode::OK, "{}", done.text());

            // And it is single-use.
            let again = post_json(
                &kit,
                RESET,
                json!({ "token": token, "new_password": "yet another password" }),
            )
            .await;
            assert_eq!(again.status, StatusCode::BAD_REQUEST);
        });
    }
}

#[test]
fn a_get_never_consumes_a_reset_token() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            request_reset(&kit, "ada@example.com").await;
            let token = token_from(&kit, RESET_LINK);

            let page = get(&kit, &format!("{RESET}?token={token}")).await;
            assert_eq!(page.status, StatusCode::OK);
            assert!(page.text().contains("new_password"), "{}", page.text());

            let done = post_json(&kit, RESET, json!({ "token": token, "new_password": NEW })).await;
            assert_eq!(done.status, StatusCode::OK, "{}", done.text());
        });
    }
}

#[test]
fn a_reissued_link_retires_the_previous_one() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            let first = token_from(&kit, VERIFY_LINK);
            // Ask again: the newest link wins, the older one stops working.
            resend(&kit, "ada@example.com").await;
            let second = token_from(&kit, VERIFY_LINK);
            assert_ne!(first, second);

            let stale = post_json(&kit, VERIFY, json!({ "token": first })).await;
            assert_eq!(stale.status, StatusCode::BAD_REQUEST);
            let live = post_json(&kit, VERIFY, json!({ "token": second })).await;
            assert_eq!(live.status, StatusCode::OK, "{}", live.text());
        });
    }
}

#[test]
fn a_ticket_addressed_to_a_different_kind_is_refused() {
    for kit in kits() {
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            // A verification token presented to /reset must not set a
            // password, and a reset token to /verify must not verify.
            let verify_token = token_from(&kit, VERIFY_LINK);
            let wrong = post_json(
                &kit,
                RESET,
                json!({ "token": verify_token, "new_password": NEW }),
            )
            .await;
            assert_eq!(wrong.status, StatusCode::BAD_REQUEST);

            request_reset(&kit, "ada@example.com").await;
            let reset_token = token_from(&kit, RESET_LINK);
            let wrong = post_json(&kit, VERIFY, json!({ "token": reset_token })).await;
            assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
            assert!(!verified(&kit, "ada@example.com"));
        });
    }
}

// ---------------------------------------------------------------------------
// Events

#[test]
fn no_recovery_event_carries_an_address() {
    let spy = EventSpy::new(EVENTS);
    for kit in spy_kits(&spy) {
        spy.seen.write().expect("lock").clear();
        pollster::block_on(async {
            register(&kit, "ada@example.com").await;
            let token = token_from(&kit, VERIFY_LINK);
            post_json(&kit, VERIFY, json!({ "token": token })).await;

            request_reset(&kit, "ada@example.com").await;
            let token = token_from(&kit, RESET_LINK);
            post_json(&kit, RESET, json!({ "token": token, "new_password": NEW })).await;
        });

        let seen = spy.seen.read().expect("lock").clone();
        let names: Vec<&str> = seen.iter().map(|(name, _)| name.as_str()).collect();
        assert!(names.contains(&"auth-password.email_verified"), "{names:?}");
        assert!(names.contains(&"auth-password.reset"), "{names:?}");
        for (name, payload) in &seen {
            let rendered = payload.to_string();
            assert!(
                !rendered.contains('@'),
                "event {name} carried an address: {rendered}"
            );
            assert!(
                payload.get("user_id").and_then(Value::as_str).is_some(),
                "event {name} does not name anybody: {rendered}"
            );
        }
    }
}
