//! Issue #854 acceptance: the account on/off switch behind the admin
//! guard — the guard itself (401 without a token, 403 with the wrong
//! one), the 404 an unknown sub sees, disable flipping the flag and
//! revoking every live session and refresh token, the idempotent repeat,
//! the audit row every call writes, and enable restoring sign-in without
//! restoring anything disable took away.

use axum::http::{Method, StatusCode, header};
use axum::response::Response;
use cratefield_auth_core::{
    AuthCore, DEFAULT_REFRESH_REUSE_GRACE_MAX_USES, Login, RefreshOutcome, RefreshReuseGrace,
    SessionError, UserRow, exchange_refresh_token, issue, mint_refresh_token,
    session_by_token_hash,
};
use cratefield_core::{Statement, UlidIdGen};
use cratefield_testing::{FixedClock, TestHarness};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const ADMIN: &str = "test-admin-token-0123456789abcdef";
const BASE: &str = "/v1/auth-core";
const EPOCH: i64 = 1_800_000_000;
const NO_GRACE: RefreshReuseGrace = RefreshReuseGrace {
    seconds: 0,
    max_uses: DEFAULT_REFRESH_REUSE_GRACE_MAX_USES,
};

struct Reply {
    status: StatusCode,
    json: Value,
}

async fn reply(response: Response) -> Reply {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    Reply { status, json }
}

async fn post(kit: &TestHarness, path: &str, token: Option<&str>) -> Reply {
    let mut builder = axum::http::Request::builder()
        .method(Method::POST)
        .uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder
        .body(axum::body::Body::empty())
        .expect("request builds");
    reply(kit.router.clone().oneshot(request).await.expect("answers")).await
}

async fn admin(kit: &TestHarness, path: &str) -> Reply {
    post(kit, path, Some(ADMIN)).await
}

fn kit() -> TestHarness {
    TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(cratefield_core::MapConfig::from_pairs([(
            "ADMIN_TOKEN",
            ADMIN,
        )]));
    })
}

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
}

async fn seed_user(kit: &TestHarness, id: &str) {
    cratefield_auth_core::insert_user(
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
        .expect("epoch in range")
        .replace_nanosecond(0)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

/// A live session for `user`, so disable has something to revoke.
async fn seed_session(kit: &TestHarness, user: &str) -> cratefield_auth_core::IssuedSession {
    issue(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        Login {
            user_id: user,
            ip: Some("203.0.113.7"),
            user_agent: Some("Mozilla/5.0 Macintosh Safari/605.1.15"),
            presented_cookie: None,
            presented_session_id: None,
            amr: &["passkey"],
        },
    )
    .await
    .expect("session")
}

/// One exchange of `value` at `secs`.
async fn exchange(
    kit: &TestHarness,
    secs: i64,
    value: &str,
) -> (RefreshOutcome, Option<cratefield_auth_core::RefreshGrant>) {
    exchange_refresh_token(&*kit.db, &at(secs), &UlidIdGen, NO_GRACE, value, "app")
        .await
        .expect("exchange")
}

/// The `user_admin_audit` rows for one user, newest last.
async fn audit_rows(kit: &TestHarness, user: &str) -> Vec<String> {
    let rows = kit
        .db
        .query(&Statement::with_values(
            "SELECT action FROM user_admin_audit WHERE user_id = ? ORDER BY at, id",
            vec![user.into()],
        ))
        .await
        .expect("audit query");
    rows.rows
        .iter()
        .map(|row| row.get::<String>("action").unwrap_or_default())
        .collect()
}

#[pollster::test]
async fn the_switch_answers_only_behind_the_admin_guard() {
    let kit = kit();
    for path in [
        format!("{BASE}/admin/users/u1/disable"),
        format!("{BASE}/admin/users/u1/enable"),
    ] {
        let Reply { status, json } = post(&kit, &path, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            json["type"],
            "https://test.example/problems/admin-unauthorized"
        );

        let Reply { status, json } = post(&kit, &path, Some("definitely-wrong")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(
            json["type"],
            "https://test.example/problems/admin-forbidden"
        );
    }
    // The guard runs before the handler: an unauthenticated request never
    // learns whether the sub exists.
    assert_eq!(count_users(&kit).await, 0);
}

#[pollster::test]
async fn an_unknown_sub_is_a_404_on_both_routes() {
    let kit = kit();
    for path in [
        format!("{BASE}/admin/users/nobody/disable"),
        format!("{BASE}/admin/users/nobody/enable"),
    ] {
        let Reply { status, json } = admin(&kit, &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(json["type"], "https://test.example/problems/not-found");
    }
    assert!(audit_rows(&kit, "nobody").await.is_empty());
}

#[pollster::test]
async fn disable_flips_the_flag_and_pulls_every_live_access_path() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let session = seed_session(&kit, "u1").await;
    let refresh = mint_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        &session.session_id,
        "u1",
        "app",
    )
    .await
    .expect("mint");

    let Reply { status, json } = admin(&kit, &format!("{BASE}/admin/users/u1/disable")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["sub"], "u1");
    assert_eq!(json["status"], "disabled");
    assert_eq!(json["sessions_revoked"], 1);
    assert_eq!(json["refresh_tokens_revoked"], 1);

    // The flag is what refuses everything that races the revocations.
    let user = cratefield_auth_core::user_by_id(&*kit.db, "u1")
        .await
        .expect("query")
        .expect("user");
    assert_eq!(user.status, "disabled");

    // The session is revoked server-side, not just unissuable.
    let row = session_by_token_hash(&*kit.db, &Sha256::digest(session.value.as_bytes()))
        .await
        .expect("query")
        .expect("session");
    assert!(row.revoked_at.is_some(), "the live session survived");

    // A refresh grant afterwards is refused: the token was retired and the
    // account is not active besides.
    let (outcome, grant) = exchange(&kit, EPOCH + 10, &refresh).await;
    assert_eq!(outcome, RefreshOutcome::Refused);
    assert!(grant.is_none());

    // And no login method can issue the account a session.
    let refused = issue(
        &*kit.db,
        &at(EPOCH + 20),
        &UlidIdGen,
        Login {
            user_id: "u1",
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &["passkey"],
        },
    )
    .await;
    assert!(matches!(refused, Err(SessionError::NotActive)));

    assert_eq!(audit_rows(&kit, "u1").await, vec!["user.disable"]);
}

/// The same call again answers the same shape with nothing left to take:
/// the counts are how a repeat is told from a first disable.
#[pollster::test]
async fn disable_is_idempotent_and_every_call_is_audited() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let first = admin(&kit, &format!("{BASE}/admin/users/u1/disable")).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json["sessions_revoked"], 0, "nothing was live");
    assert_eq!(first.json["refresh_tokens_revoked"], 0);

    let second = admin(&kit, &format!("{BASE}/admin/users/u1/disable")).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(second.json, first.json, "a repeat reads like the first");

    // Each call is an action worth a row, even the one that changed
    // nothing.
    assert_eq!(
        audit_rows(&kit, "u1").await,
        vec!["user.disable", "user.disable"]
    );
}

#[pollster::test]
async fn enable_restores_sign_in_but_not_what_disable_took_away() {
    let kit = kit();
    seed_user(&kit, "u1").await;
    let session = seed_session(&kit, "u1").await;
    let refresh = mint_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        &session.session_id,
        "u1",
        "app",
    )
    .await
    .expect("mint");
    let disabled = admin(&kit, &format!("{BASE}/admin/users/u1/disable")).await;
    assert_eq!(disabled.status, StatusCode::OK);

    let Reply { status, json } = admin(&kit, &format!("{BASE}/admin/users/u1/enable")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["sub"], "u1");
    assert_eq!(json["status"], "active");
    assert_eq!(json["sessions_revoked"], 0, "enable revokes nothing");
    assert_eq!(json["refresh_tokens_revoked"], 0);

    // Sign-in works again…
    let reissued = issue(
        &*kit.db,
        &at(EPOCH + 30),
        &UlidIdGen,
        Login {
            user_id: "u1",
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &["passkey"],
        },
    )
    .await
    .expect("the account is active again");
    assert_ne!(reissued.session_id, session.session_id);

    // …but what disable took away stays taken: the old session is still
    // revoked and the retired refresh token still spends to nothing.
    let old = session_by_token_hash(&*kit.db, &Sha256::digest(session.value.as_bytes()))
        .await
        .expect("query")
        .expect("session");
    assert!(old.revoked_at.is_some(), "enable restored a session");
    let (outcome, grant) = exchange(&kit, EPOCH + 40, &refresh).await;
    assert_eq!(outcome, RefreshOutcome::Refused);
    assert!(grant.is_none());

    assert_eq!(
        audit_rows(&kit, "u1").await,
        vec!["user.disable", "user.enable"]
    );
}

/// The audit insert draws its `user_id` from the users row itself, so a
/// status set that loses a race with an erasure writes nothing — on every
/// dialect, not only where the adapters enforce the foreign key.
#[pollster::test]
async fn a_status_set_that_races_an_erasure_writes_no_audit_row() {
    let kit = kit();
    // No `seed_user`: the account is gone before the call lands, which is
    // exactly the state an erasure between the route's check and the batch
    // produces.
    cratefield_auth_core::set_user_status(
        &*kit.db,
        "u1",
        "disabled",
        &cratefield_auth_core::UserAdminAuditRow {
            id: "audit-gone".to_owned(),
            user_id: "u1".to_owned(),
            action: "user.disable".to_owned(),
            at: iso(EPOCH),
        },
        &iso(EPOCH),
    )
    .await
    .expect("the batch succeeds either way");
    assert!(
        audit_rows(&kit, "u1").await.is_empty(),
        "a dangling audit row survived its account"
    );
}

async fn count_users(kit: &TestHarness) -> i64 {
    let rows = kit
        .db
        .query(&Statement::new("SELECT COUNT(*) AS n FROM users"))
        .await
        .expect("count");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(-1)
}
