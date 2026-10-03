//! Issue #9 acceptance, integration half: the discovery endpoints
//! under `/.well-known` (public keys only, cache headers, rotation
//! overlap), access tokens carrying the recommended claims, and
//! refresh tokens that are single-use with reuse detection revoking
//! the session — against the sqlite adapter through the `Clock` port.
//!
//! Signing keys are throwaway P-256 keys generated inside each test;
//! no real key is ever committed.

use axum::http::{Method, StatusCode, header};
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_core::{Database, DbError, MapConfig, Rows, Statement, UlidIdGen};
use cratefield_testing::{FixedClock, TestHarness};
use factory0_auth_core::{
    AuthCore, DEFAULT_REFRESH_REUSE_GRACE_MAX_USES, Login, REFRESH_TOKEN_DAYS, RefreshGrant,
    RefreshOutcome, RefreshReuseGrace, SLIDE_WINDOW_DAYS, SigningKeys, UserRow,
    exchange_refresh_token, issue, mint_access_token, mint_refresh_token, session_by_token_hash,
};
use p256::ecdsa::{self, signature::Verifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const DAY: i64 = 86_400;
const ISSUER: &str = "https://auth.test.example";

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

/// The default configuration: no grace, any reuse revokes (issue #655).
const NO_GRACE: RefreshReuseGrace = RefreshReuseGrace {
    seconds: 0,
    max_uses: DEFAULT_REFRESH_REUSE_GRACE_MAX_USES,
};

fn grace(seconds: u32, max_uses: u32) -> RefreshReuseGrace {
    RefreshReuseGrace { seconds, max_uses }
}

/// Is the session behind `value` (the raw session cookie value) revoked?
async fn session_revoked(kit: &TestHarness, value: &str) -> bool {
    session_by_token_hash(&*kit.db, &Sha256::digest(value.as_bytes()))
        .await
        .expect("query")
        .expect("session")
        .revoked_at
        .is_some()
}

/// How many `single_use_tokens` rows name `session_id`: the presented token
/// plus any successor minted for it (issue #655).
async fn rows_for_session(kit: &TestHarness, session_id: &str) -> usize {
    let statement = Statement::new(format!(
        "SELECT id FROM single_use_tokens WHERE payload LIKE '%{session_id}%'"
    ));
    let rows: Rows = kit.db.query(&statement).await.expect("count");
    rows.len()
}

/// A throwaway P-256 keypair generated in the test: the private JWK
/// for the config, the signer for signature assertions.
fn dummy_key(kid: &str) -> (Value, ecdsa::SigningKey) {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("entropy");
    bytes[0] = 1; // keep the scalar valid while staying obviously fake
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let signing = ecdsa::SigningKey::from(&secret);
    let d = Base64UrlUnpadded::encode_string(&secret.to_bytes());
    (
        json!({ "kty": "EC", "crv": "P-256", "kid": kid, "d": d }),
        signing,
    )
}

/// One signed test environment: the harness (whose router resolves
/// keys from the same config), the parsed keys for direct minting, and
/// the raw signers so tests can verify signatures independently.
struct SignedKit {
    kit: TestHarness,
    keys: Arc<SigningKeys>,
    signers: Vec<ecdsa::SigningKey>,
}

fn signed_kit(active: &str, pairs: Vec<(Value, ecdsa::SigningKey)>) -> SignedKit {
    let jwks: Vec<Value> = pairs.iter().map(|(jwk, _)| jwk.clone()).collect();
    let signers: Vec<ecdsa::SigningKey> = pairs.into_iter().map(|(_, signing)| signing).collect();
    let config = MapConfig::from_pairs([
        (
            "AUTH_CORE_SIGNING_KEYS",
            serde_json::to_string(&jwks).expect("keys json"),
        ),
        ("AUTH_CORE_SIGNING_KEY_ACTIVE", active.to_owned()),
        ("AUTH_CORE_ISSUER", ISSUER.to_owned()),
    ]);
    let keys = Arc::new(
        SigningKeys::from_config(&config)
            .expect("config parses")
            .expect("keys configured"),
    );
    let kit = TestHarness::with_ports(vec![Box::new(AuthCore::new())], |ports| {
        ports.config = Arc::new(config);
    });
    SignedKit { kit, keys, signers }
}

fn plain_kit() -> TestHarness {
    TestHarness::new(vec![Box::new(AuthCore::new())])
}

async fn seed_user(kit: &TestHarness, id: &str, email: Option<&str>, verified: bool) {
    factory0_auth_core::insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: email.map(str::to_owned),
            primary_email_verified: verified,
            status: "active".to_owned(),
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
}

async fn seed_session(
    kit: &TestHarness,
    user_id: &str,
    amr: &[&str],
) -> factory0_auth_core::IssuedSession {
    issue(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        Login {
            user_id,
            ip: Some("203.0.113.7"),
            user_agent: Some("Mozilla/5.0 Macintosh Safari/605.1.15"),
            presented_cookie: None,
            presented_session_id: None,
            amr,
        },
    )
    .await
    .expect("session")
}

async fn get(kit: &TestHarness, path: &str) -> (StatusCode, Option<String>, Value, Vec<u8>) {
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(axum::body::Body::empty())
        .expect("builds");
    let response = kit.router.clone().oneshot(request).await.expect("answers");
    let status = response.status();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, cache, json, body.to_vec())
}

fn b64url_json(part: &str) -> Value {
    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(part).expect("b64url")).expect("json")
}

fn header_of(token: &str) -> Value {
    b64url_json(token.split('.').next().expect("header"))
}

fn claims_of(token: &str) -> Value {
    b64url_json(token.split('.').nth(1).expect("claims"))
}

fn verify_signature(token: &str, signer: &ecdsa::SigningKey) {
    let mut parts = token.split('.');
    let head = parts.next().expect("header");
    let claims = parts.next().expect("claims");
    let raw = Base64UrlUnpadded::decode_vec(parts.next().expect("signature")).expect("b64url");
    let signature = ecdsa::Signature::from_slice(&raw).expect("r||s");
    signer
        .verifying_key()
        .verify(format!("{head}.{claims}").as_bytes(), &signature)
        .expect("signature verifies");
}

#[pollster::test]
async fn jwks_publishes_public_parts_of_every_configured_key() {
    let signed = signed_kit("k-new", vec![dummy_key("k-old"), dummy_key("k-new")]);
    let (status, cache, body, raw) = get(&signed.kit, "/.well-known/jwks.json").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("public, max-age=300"));
    let keys = body["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2, "current and previous keys are published");
    let kids: Vec<&str> = keys
        .iter()
        .map(|key| key["kid"].as_str().expect("kid"))
        .collect();
    assert_eq!(kids, ["k-old", "k-new"]);
    for key in keys {
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["use"], "sig");
        assert!(key["x"].as_str().is_some_and(|x| x.len() == 43));
        assert!(key["y"].as_str().is_some_and(|y| y.len() == 43));
    }
    assert!(
        !raw.windows(3).any(|window| window == b"\"d\""),
        "the JWKS response must never contain the private `d` field"
    );
}

#[pollster::test]
async fn openid_configuration_advertises_the_issuer_endpoints_and_algorithms() {
    let signed = signed_kit("k", vec![dummy_key("k")]);
    let (status, cache, body, _) = get(&signed.kit, "/.well-known/openid-configuration").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("public, max-age=3600"));
    assert_eq!(body["issuer"], ISSUER);
    assert_eq!(body["jwks_uri"], format!("{ISSUER}/.well-known/jwks.json"));
    assert_eq!(
        body["authorization_endpoint"],
        format!("{ISSUER}/v1/auth-core/authorize")
    );
    assert_eq!(
        body["token_endpoint"],
        format!("{ISSUER}/v1/auth-core/token")
    );
    assert_eq!(
        body["end_session_endpoint"],
        format!("{ISSUER}/v1/auth-core/logout")
    );
    assert_eq!(body["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        body["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(body["response_types_supported"], json!(["code"]));
    assert!(
        !body.to_string().contains("implicit"),
        "no implicit flow, no password grant is advertised"
    );
}

#[pollster::test]
async fn unconfigured_keys_answer_the_stable_problem_on_both_documents() {
    let kit = plain_kit();
    let (status, _, body, _) = get(&kit, "/.well-known/jwks.json").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body["type"],
        "https://test.example/problems/auth/tokens-unconfigured"
    );

    let (status, _, body, _) = get(&kit, "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body["type"],
        "https://test.example/problems/auth/tokens-unconfigured"
    );
}

#[pollster::test]
async fn access_tokens_carry_the_recommended_claims_and_verify() {
    let signed = signed_kit("k", vec![dummy_key("k")]);
    seed_user(&signed.kit, "u1", Some("u1@example.com"), true).await;
    let session = seed_session(&signed.kit, "u1", &["user", "passkey"]).await;

    let token = mint_access_token(
        &signed.keys,
        &at(EPOCH + 60),
        &session.session_id,
        "u1",
        Some(("u1@example.com", true)),
        "client_1",
        &["user".to_owned(), "passkey".to_owned()],
    )
    .expect("mint");

    let header = header_of(&token);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["kid"], "k");
    verify_signature(&token, &signed.signers[0]);

    let claims = claims_of(&token);
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], "u1");
    assert_eq!(claims["aud"], "client_1");
    assert_eq!(claims["sid"], session.session_id);
    assert_eq!(claims["iat"], EPOCH + 60);
    assert_eq!(claims["exp"], EPOCH + 60 + 600);
    assert_eq!(claims["email"], "u1@example.com");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["amr"], json!(["user", "passkey"]));
}

#[pollster::test]
async fn rotation_overlaps_both_keys_and_signs_with_the_active_one() {
    let signed = signed_kit("k-new", vec![dummy_key("k-old"), dummy_key("k-new")]);
    let (status, _, body, _) = get(&signed.kit, "/.well-known/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["keys"].as_array().expect("keys").len(),
        2,
        "the previous key keeps verifying during the overlap"
    );

    assert_eq!(signed.keys.active_kid(), "k-new");
    let token =
        mint_access_token(&signed.keys, &at(EPOCH), "s", "u", None, "c", &[]).expect("mint");
    assert_eq!(header_of(&token)["kid"], "k-new");
    verify_signature(&token, &signed.signers[1]);
}

#[pollster::test]
async fn refresh_tokens_are_single_use_and_reuse_revokes_the_session() {
    let kit = plain_kit();
    seed_user(&kit, "u1", None, false).await;
    let session = seed_session(&kit, "u1", &[]).await;

    let value = mint_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        &session.session_id,
        "u1",
        "client_1",
    )
    .await
    .expect("mint");
    assert_eq!(value.len(), 43);

    // Only the hash is stored, bound to the session, 30-day expiry.
    let hash = Sha256::digest(value.as_bytes()).to_vec();
    let row = factory0_auth_core::single_use_token_by_hash(&*kit.db, &hash)
        .await
        .expect("query")
        .expect("stored");
    assert_eq!(row.kind, "refresh_token");
    assert_eq!(row.client_id.as_deref(), Some("client_1"));
    assert_eq!(row.expires_at, iso(EPOCH + SLIDE_WINDOW_DAYS * DAY));

    // First exchange wins.
    let (outcome, grant) = exchange_refresh_token(
        &*kit.db,
        &at(EPOCH + 10),
        &UlidIdGen,
        NO_GRACE,
        &value,
        "client_1",
    )
    .await
    .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Granted);
    let grant = grant.expect("grant");
    assert_eq!(grant.session_id, session.session_id);
    assert_eq!(grant.user_id, "u1");
    assert_eq!(grant.client_id, "client_1");
    assert_eq!(
        grant.refresh_token.len(),
        43,
        "the exchange mints the successor"
    );

    // Reuse: refused, and the session is revoked.
    let (outcome, grant) = exchange_refresh_token(
        &*kit.db,
        &at(EPOCH + 20),
        &UlidIdGen,
        NO_GRACE,
        &value,
        "client_1",
    )
    .await
    .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Refused);
    assert!(grant.is_none());
    assert!(
        session_revoked(&kit, &session.value).await,
        "reuse revoked the session"
    );
}

#[pollster::test]
async fn a_refresh_token_presented_for_the_wrong_client_is_not_consumed() {
    let kit = plain_kit();
    seed_user(&kit, "u1", None, false).await;
    let session = seed_session(&kit, "u1", &[]).await;

    let value = mint_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        &session.session_id,
        "u1",
        "client_1",
    )
    .await
    .expect("mint");

    let (outcome, _) = exchange_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        NO_GRACE,
        &value,
        "client_other",
    )
    .await
    .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Refused);

    // The rightful client can still use it, and the session lives on.
    let (outcome, _) = exchange_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        NO_GRACE,
        &value,
        "client_1",
    )
    .await
    .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Granted);
    assert!(!session_revoked(&kit, &session.value).await);
}

#[pollster::test]
async fn an_unknown_refresh_token_is_refused_without_side_effects() {
    let kit = plain_kit();
    let (outcome, grant) = exchange_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        NO_GRACE,
        "not-a-real-token-at-all-just-43-chars-xxxx",
        "client_1",
    )
    .await
    .expect("exchange");
    assert_eq!(outcome, RefreshOutcome::Refused);
    assert!(grant.is_none());
}

/// Issues a fresh session and a refresh token bound to it: the shared
/// setup of the grace tests (issue #655).
async fn mint_for_session(
    kit: &TestHarness,
    client_id: &str,
) -> (factory0_auth_core::IssuedSession, String) {
    seed_user(kit, "u1", None, false).await;
    let session = seed_session(kit, "u1", &[]).await;
    let value = mint_refresh_token(
        &*kit.db,
        &at(EPOCH),
        &UlidIdGen,
        &session.session_id,
        "u1",
        client_id,
    )
    .await
    .expect("mint");
    (session, value)
}

/// One kit per available dialect — SQLite always, Postgres when
/// `FZ_TEST_POSTGRES_URL` names a server — so the sibling bookkeeping and
/// its compare-and-swap run on both engines.
fn grace_kits() -> Vec<TestHarness> {
    TestHarness::all_dialects(|| vec![Box::new(AuthCore::new())])
}

/// One exchange of `value` at `secs`, asserted to have answered.
async fn exchange(
    kit: &TestHarness,
    secs: i64,
    grace: RefreshReuseGrace,
    value: &str,
    client: &str,
) -> (RefreshOutcome, Option<RefreshGrant>) {
    exchange_refresh_token(&*kit.db, &at(secs), &UlidIdGen, grace, value, client)
        .await
        .expect("exchange")
}

/// A `Database` that yields to the executor once per call, so two
/// exchanges driven together genuinely interleave: each reads the row
/// before either consumes it — the guarded-consume race of issue #655.
/// The SQLite adapter answers on the first poll, so without this the two
/// legs serialize and the loser reads an already-consumed row (the reuse
/// path) rather than losing the consume.
struct YieldingDatabase {
    inner: Arc<dyn Database>,
}

#[async_trait::async_trait]
impl Database for YieldingDatabase {
    async fn execute(&self, statement: &Statement) -> Result<u64, DbError> {
        yield_once().await;
        self.inner.execute(statement).await
    }

    async fn query(&self, statement: &Statement) -> Result<Rows, DbError> {
        yield_once().await;
        self.inner.query(statement).await
    }

    async fn batch_atomic(&self, statements: &[Statement]) -> Result<(), DbError> {
        yield_once().await;
        self.inner.batch_atomic(statements).await
    }
}

/// Gives the executor exactly one turn: `Pending` once (after waking),
/// then `Ready`.
async fn yield_once() {
    struct YieldOnce(bool);
    impl std::future::Future for YieldOnce {
        type Output = ();
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.0 {
                std::task::Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }
    YieldOnce(false).await;
}

/// The cookie race set up: P rotates to S1, a graced re-presentation at
/// +20s mints the sibling S2, and both live until one is used.
async fn two_siblings(kit: &TestHarness) -> (factory0_auth_core::IssuedSession, String, String) {
    let (session, value) = mint_for_session(kit, "client_1").await;
    let grace = grace(30, 3);
    let (outcome, grant) = exchange(kit, EPOCH + 10, grace, &value, "client_1").await;
    assert_eq!(outcome, RefreshOutcome::Granted, "rotation");
    let first = grant.expect("grant").refresh_token;
    let (outcome, grant) = exchange(kit, EPOCH + 20, grace, &value, "client_1").await;
    assert_eq!(outcome, RefreshOutcome::Granted, "graced sibling");
    let second = grant.expect("grant").refresh_token;
    assert_ne!(first, second, "a distinct sibling");
    (session, first, second)
}

/// First use wins — S1 used first retires S2, whose later presentation is
/// plain reuse; the session survives.
#[pollster::test]
async fn first_use_wins_between_siblings() {
    for kit in grace_kits() {
        let dialect = kit.dialect;
        let (session, first, second) = two_siblings(&kit).await;
        let (outcome, _) = exchange(&kit, EPOCH + 41, grace(30, 3), &first, "client_1").await;
        assert_eq!(outcome, RefreshOutcome::Granted, "{dialect}: first use");
        assert!(
            !session_revoked(&kit, &session.value).await,
            "{dialect}: the session lives"
        );
        let (outcome, _) = exchange(&kit, EPOCH + 42, grace(30, 3), &second, "client_1").await;
        assert_eq!(
            outcome,
            RefreshOutcome::Refused,
            "{dialect}: retired sibling"
        );
    }
}

/// The mirror: S2 used first retires S1.
#[pollster::test]
async fn the_second_sibling_used_first_retires_the_first() {
    for kit in grace_kits() {
        let dialect = kit.dialect;
        let (_session, first, second) = two_siblings(&kit).await;
        let (outcome, _) = exchange(&kit, EPOCH + 25, grace(30, 3), &second, "client_1").await;
        assert_eq!(outcome, RefreshOutcome::Granted, "{dialect}: sibling use");
        let (outcome, _) = exchange(&kit, EPOCH + 26, grace(30, 3), &first, "client_1").await;
        assert_eq!(
            outcome,
            RefreshOutcome::Refused,
            "{dialect}: retired sibling"
        );
    }
}

/// The harness database wrapped so every call yields to the executor: two
/// exchanges driven together then genuinely interleave (see
/// [`YieldingDatabase`]).
fn yielding(kit: &TestHarness) -> YieldingDatabase {
    YieldingDatabase {
        inner: Arc::clone(&kit.db),
    }
}

/// Two exchanges of the same token at the same instant: both Granted,
/// each with its own sibling, and the session survives.
#[pollster::test]
async fn concurrent_refreshes_inside_the_grace_window_both_succeed() {
    for kit in grace_kits() {
        let dialect = kit.dialect;
        let (session, value) = mint_for_session(&kit, "client_1").await;
        let db = yielding(&kit);

        let (a, b) = pollster::block_on(futures_util::future::join(
            exchange_refresh_token(
                &db,
                &at(EPOCH + 5),
                &UlidIdGen,
                grace(30, 3),
                &value,
                "client_1",
            ),
            exchange_refresh_token(
                &db,
                &at(EPOCH + 5),
                &UlidIdGen,
                grace(30, 3),
                &value,
                "client_1",
            ),
        ));
        let (a, a_grant) = a.expect("exchange");
        let (b, b_grant) = b.expect("exchange");
        assert_eq!(a, RefreshOutcome::Granted, "{dialect}: first leg");
        assert_eq!(b, RefreshOutcome::Granted, "{dialect}: second leg");
        assert_ne!(
            a_grant.expect("grant").refresh_token,
            b_grant.expect("grant").refresh_token,
            "{dialect}: each leg gets its own sibling"
        );
        assert!(
            !session_revoked(&kit, &session.value).await,
            "{dialect}: the race did not revoke the session"
        );
    }
}

/// The default (grace off) race: two exchanges of the same token at once,
/// one wins and one is refused, and — because the loser lost the guarded
/// consume rather than presenting a consumed token — its refusal does NOT
/// revoke the session, and the winner's refresh token still works.
#[pollster::test]
async fn concurrent_refreshes_without_grace_refuse_without_revoking() {
    for kit in grace_kits() {
        let dialect = kit.dialect;
        let (session, value) = mint_for_session(&kit, "client_1").await;
        let db = yielding(&kit);

        let (a, b) = pollster::block_on(futures_util::future::join(
            exchange_refresh_token(
                &db,
                &at(EPOCH + 5),
                &UlidIdGen,
                NO_GRACE,
                &value,
                "client_1",
            ),
            exchange_refresh_token(
                &db,
                &at(EPOCH + 5),
                &UlidIdGen,
                NO_GRACE,
                &value,
                "client_1",
            ),
        ));
        let (a, a_grant) = a.expect("exchange");
        let (b, b_grant) = b.expect("exchange");
        let winner = match (a, b) {
            (RefreshOutcome::Granted, RefreshOutcome::Refused) => a_grant,
            (RefreshOutcome::Refused, RefreshOutcome::Granted) => b_grant,
            (a, b) => panic!("{dialect}: exactly one leg wins, got {a:?}/{b:?}"),
        };
        assert!(
            !session_revoked(&kit, &session.value).await,
            "{dialect}: losing the race must not revoke the session"
        );
        let (outcome, _) = exchange(
            &kit,
            EPOCH + 10,
            NO_GRACE,
            &winner.expect("grant").refresh_token,
            "client_1",
        )
        .await;
        assert_eq!(
            outcome,
            RefreshOutcome::Granted,
            "{dialect}: the winner's refresh token still works"
        );
    }
}

/// Reuse after the window is the ordinary alarm.
#[pollster::test]
async fn reuse_after_the_grace_window_revokes_the_session() {
    for kit in grace_kits() {
        let dialect = kit.dialect;
        let (session, value) = mint_for_session(&kit, "client_1").await;

        let (outcome, _) = exchange(&kit, EPOCH + 1, grace(30, 3), &value, "client_1").await;
        assert_eq!(outcome, RefreshOutcome::Granted, "{dialect}: rotation");
        let (outcome, _) = exchange(&kit, EPOCH + 41, grace(30, 3), &value, "client_1").await;
        assert_eq!(
            outcome,
            RefreshOutcome::Refused,
            "{dialect}: past the window"
        );
        assert!(
            session_revoked(&kit, &session.value).await,
            "{dialect}: reuse after the window is not graced"
        );
    }
}

/// A consumed token presented by another client is refused at the client
/// check, gets no grace, and — as today — does not revoke the session.
#[pollster::test]
async fn a_consumed_token_for_another_client_gets_no_grace() {
    for kit in grace_kits() {
        let dialect = kit.dialect;
        let (session, value) = mint_for_session(&kit, "client_1").await;
        let grace = grace(30, 3);

        let (outcome, _) = exchange(&kit, EPOCH + 1, grace, &value, "client_1").await;
        assert_eq!(outcome, RefreshOutcome::Granted, "{dialect}: rotation");
        let (outcome, grant) = exchange(&kit, EPOCH + 2, grace, &value, "client_other").await;
        assert_eq!(outcome, RefreshOutcome::Refused, "{dialect}: wrong client");
        assert!(grant.is_none());
        assert!(
            !session_revoked(&kit, &session.value).await,
            "{dialect}: the wrong client neither burned the token nor revoked the session"
        );
    }
}

/// The grace count is enforced: the `max_uses + 1`-th reuse revokes.
#[pollster::test]
async fn the_grace_use_count_is_enforced() {
    for kit in grace_kits() {
        let dialect = kit.dialect;
        let (session, value) = mint_for_session(&kit, "client_1").await;
        let grace = grace(60, 2);

        let (outcome, _) = exchange(&kit, EPOCH + 1, grace, &value, "client_1").await;
        assert_eq!(outcome, RefreshOutcome::Granted, "{dialect}: rotation");
        for step in 2..=3 {
            let (outcome, _) = exchange(&kit, EPOCH + step, grace, &value, "client_1").await;
            assert_eq!(
                outcome,
                RefreshOutcome::Granted,
                "{dialect}: grace use {step} is within the cap"
            );
        }
        assert!(!session_revoked(&kit, &session.value).await);
        let (outcome, _) = exchange(&kit, EPOCH + 4, grace, &value, "client_1").await;
        assert_eq!(outcome, RefreshOutcome::Refused, "{dialect}: count cap");
        assert!(
            session_revoked(&kit, &session.value).await,
            "{dialect}: the max_uses + 1-th reuse revokes"
        );
    }
}

/// A refresh token whose row has expired is refused like any stale
/// token, not treated as reuse: it is refused before anything is minted,
/// so replaying an expired token cannot grow the table.
#[pollster::test]
async fn an_expired_refresh_token_is_refused_without_revoking() {
    for kit in grace_kits() {
        let dialect = kit.dialect;
        let (session, value) = mint_for_session(&kit, "client_1").await;
        let rows_before = rows_for_session(&kit, &session.session_id).await;

        let (outcome, grant) = exchange(
            &kit,
            EPOCH + REFRESH_TOKEN_DAYS * DAY + 1,
            NO_GRACE,
            &value,
            "client_1",
        )
        .await;
        assert_eq!(outcome, RefreshOutcome::Refused, "{dialect}: expired token");
        assert!(grant.is_none());
        assert!(
            !session_revoked(&kit, &session.value).await,
            "{dialect}: an expired token does not revoke the session"
        );
        assert_eq!(
            rows_for_session(&kit, &session.session_id).await,
            rows_before,
            "{dialect}: refusing an expired token mints no successor"
        );
    }
}
