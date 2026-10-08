//! Test doubles, wallet fixtures and request helpers for the wallets suite.
//!
//! Everything here is deterministic and offline: the entropy is a counter,
//! the clock is one a test moves by hand, and every signature is produced
//! in-process from a fixed seed. Nothing reaches a chain, and nothing about
//! a test depends on the wall clock.
//!
//! The signing helpers are the interesting half. A wallet-connect test that
//! pastes a canned signature proves nothing about the verifier — it proves
//! the verifier accepts a hex string it has seen before. So each fixture
//! holds a real secp256k1 or ed25519 key, derives its own address the way
//! the module does, and signs the exact message the route asked for.

// A test-support module, included with `mod support;` into each test binary
// in this crate. `pub` is how a helper reads here, and the lint is right
// that nothing outside can reach it — the module is private to every binary
// that includes it. Saying so once beats `pub(crate)` on every helper.
#![allow(unreachable_pub)]
#![allow(dead_code)]
// A recording test double below keeps the calls a verifier was asked about;
// interior mutability is the point of that double and not request state.
#![allow(clippy::disallowed_types)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use cratefield_core::{Clock, RandomBytes, RandomError};
use cratefield_module_wallets::{ContractSignatureVerifier, ContractVerifierError, Wallets};
use cratefield_testing::{FakeAuth, ManualClock, TestHarness};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

// ---------------------------------------------------------------------------
// The venture under test

/// The domain every message in this suite is bound to. A message naming
/// anything else is the phishing case, and there is a test for it.
pub const DOMAIN: &str = "wallet.test";

/// The line a person reads before signing.
pub const STATEMENT: &str = "Link this wallet to your account.";

/// The instant the manual clock starts at — a fixed epoch well before the
/// hard-coded past and future timestamps the expiry tests use.
pub const BASE_EPOCH: i64 = 1_800_000_000;

/// Two people, so "only your own wallets" has a `B` to mean.
pub const ALICE: &str = "alice";
pub const BOB: &str = "bob";

// ---------------------------------------------------------------------------
// The entropy source

/// A deterministic [`RandomBytes`]: every draw is a fresh sequence derived
/// from a counter, so two calls never collide but every run is identical.
#[derive(Clone)]
pub struct SeqRandom(Arc<AtomicUsize>);

impl SeqRandom {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(1)))
    }
}

impl Default for SeqRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomBytes for SeqRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        let base = self.0.fetch_add(1, Ordering::SeqCst);
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = u8::try_from((base.wrapping_mul(31) + index * 7 + 13) % 256)
                .expect("modulo 256 fits a byte");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The clock

/// A clock a test moves: nonce and message expiry only mean something if
/// time can pass. [`ManualClock`] already shares its instant across clones,
/// so this is the same clock the module reads through the `Clock` port.
pub type TestClock = ManualClock;

/// A clock stopped at [`BASE_EPOCH`].
#[must_use]
pub fn test_clock() -> TestClock {
    ManualClock::new(OffsetDateTime::from_unix_timestamp(BASE_EPOCH).expect("in range"))
}

/// Moves `clock` forward by `secs`.
pub fn advance(clock: &TestClock, secs: u64) {
    clock.advance(std::time::Duration::from_secs(secs));
}

/// The instant `clock` currently reads — the same one the module sees
/// through the `Clock` port.
#[must_use]
pub fn now(clock: &TestClock) -> OffsetDateTime {
    clock.now()
}

/// RFC 3339 UTC, whole seconds — the form the module's messages carry.
#[must_use]
pub fn stamp(at: OffsetDateTime) -> String {
    use time::format_description::well_known::Rfc3339;
    at.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Wallets

/// An EVM test wallet: a real secp256k1 key, the address that key owns,
/// and an EIP-191 `personal_sign` over whatever message it is handed.
pub struct EvmWallet {
    key: k256::ecdsa::SigningKey,
    address: String,
}

impl EvmWallet {
    /// A wallet whose private key is the seed repeated to 32 bytes — the
    /// same key every run, so a failure is reproducible.
    #[must_use]
    pub fn from_seed(seed: u8) -> Self {
        let key = k256::ecdsa::SigningKey::from_bytes(&[seed; 32].into())
            .expect("32 bytes is a valid scalar");
        let address = eth_address(&key);
        Self { key, address }
    }

    /// The address this wallet controls, lowercase and `0x`-prefixed — the
    /// form a SIWE message carries and the form the module normalises.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The `r || s || v` signature over `message`, hex with no prefix. This
    /// is what a browser wallet returns from `personal_sign`.
    #[must_use]
    pub fn sign_personal(&self, message: &str) -> String {
        let (sig, recovery) = self
            .key
            .sign_prehash_recoverable(&eip191_hash(message))
            .expect("a secp256k1 key signs its own prehash");
        let mut bytes = sig.to_bytes().to_vec();
        // Ethereum's `v` is the recovery id biased by 27; the module reads
        // both 0/1 and 27/28.
        bytes.push(u8::from(recovery) + 27);
        hex::encode(bytes)
    }
}

/// The Ethereum address of a secp256k1 public key: the last 20 bytes of
/// the keccak-256 of the uncompressed point without its `0x04` tag. The
/// same derivation the module performs on a recovered key.
#[must_use]
pub fn eth_address(key: &k256::ecdsa::SigningKey) -> String {
    let verifying = k256::ecdsa::VerifyingKey::from(key);
    let point = verifying.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// The EIP-191 personal-sign hash: keccak-256 of the prefixed message.
#[must_use]
pub fn eip191_hash(message: &str) -> [u8; 32] {
    let mut data = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    data.extend_from_slice(message.as_bytes());
    keccak256(&data)
}

/// The raw keccak-256 of `message` — what the EIP-191 hash is *not*. A test
/// that wants to prove the module hashes the message the personal-sign way
/// needs the wrong digest to compare against.
#[must_use]
pub fn raw_keccak(message: &str) -> [u8; 32] {
    keccak256(message.as_bytes())
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(data).into()
}

/// A Solana test wallet: a real ed25519 key, the base58 address that key
/// owns, and a signature over the exact message bytes — SIWS signs the
/// message verbatim, with no EIP-191 prefix in front of it.
pub struct SolanaWallet {
    key: ed25519_dalek::SigningKey,
    address: String,
}

impl SolanaWallet {
    /// A wallet whose seed is `seed` repeated to 32 bytes.
    #[must_use]
    pub fn from_seed(seed: u8) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let address = bs58::encode(key.verifying_key().to_bytes()).into_string();
        Self { key, address }
    }

    /// The base58 address this wallet controls.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The 64-byte ed25519 signature over `message`, base58 — what a
    /// Phantom or Backpack wallet returns.
    #[must_use]
    pub fn sign(&self, message: &str) -> String {
        use ed25519_dalek::Signer as _;
        bs58::encode(self.key.sign(message.as_bytes()).to_bytes()).into_string()
    }
}

// ---------------------------------------------------------------------------
// The EIP-1271 recording verifier

/// One question the module asked an EIP-1271 verifier, kept whole so a test
/// can assert on the hash it was handed and the chain it was told to ask
/// about — the two things a cross-chain message could otherwise choose.
#[derive(Debug, Clone)]
pub struct VerifierCall {
    pub chain_id: String,
    pub address: String,
    pub message_hash: [u8; 32],
    pub signature: Vec<u8>,
}

/// An EIP-1271 verifier that records every question and approves exactly the
/// `address` it was built for. Unlike `StaticContractVerifier::approving`,
/// which throws the hash away, this one keeps it — so a test can prove the
/// module asked about the EIP-191 hash of the message it verified rather
/// than some other digest of the same bytes.
#[derive(Clone)]
pub struct RecordingVerifier {
    address: String,
    calls: Arc<Mutex<Vec<VerifierCall>>>,
}

impl RecordingVerifier {
    /// A verifier that approves `address` and remembers every call.
    #[must_use]
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Every call this verifier was asked about, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<VerifierCall> {
        self.calls
            .lock()
            .expect("the recorder is not poisoned")
            .clone()
    }

    /// The single call this verifier was asked about.
    ///
    /// # Panics
    ///
    /// Panics unless exactly one call was made, which is what a test that
    /// wants to read the call means.
    #[must_use]
    pub fn only_call(&self) -> VerifierCall {
        let calls = self.calls();
        assert_eq!(
            calls.len(),
            1,
            "expected exactly one verifier call: {calls:?}"
        );
        calls.into_iter().next().expect("checked length")
    }
}

#[async_trait::async_trait]
impl ContractSignatureVerifier for RecordingVerifier {
    async fn is_valid_signature(
        &self,
        chain_id: &str,
        address: &str,
        message_hash: [u8; 32],
        signature: &[u8],
    ) -> Result<bool, ContractVerifierError> {
        self.calls
            .lock()
            .expect("the recorder is not poisoned")
            .push(VerifierCall {
                chain_id: chain_id.to_owned(),
                address: address.to_owned(),
                message_hash,
                signature: signature.to_vec(),
            });
        Ok(address == self.address)
    }
}

/// Hands an `Arc<dyn ContractSignatureVerifier>` to the builder, which
/// wants an owned `impl ContractSignatureVerifier` — a `Spec` holds a trait
/// object so a test can choose either double at the call site.
struct VerifierRef(Arc<dyn ContractSignatureVerifier>);

#[async_trait::async_trait]
impl ContractSignatureVerifier for VerifierRef {
    async fn is_valid_signature(
        &self,
        chain_id: &str,
        address: &str,
        message_hash: [u8; 32],
        signature: &[u8],
    ) -> Result<bool, ContractVerifierError> {
        self.0
            .is_valid_signature(chain_id, address, message_hash, signature)
            .await
    }
}

// ---------------------------------------------------------------------------
// Messages

/// The fields of a SIWE/SIWS message, as the `/nonce` route hands them
/// back. A client wraps these around its own address and signs.
#[derive(Debug, Clone)]
pub struct Fields {
    pub domain: String,
    pub uri: String,
    pub version: String,
    pub chain_id: String,
    pub nonce: String,
    pub statement: Option<String>,
    pub issued_at: String,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
}

impl Fields {
    /// The fields a `/nonce` response carries, read verbatim.
    #[must_use]
    pub fn from_nonce(body: &Value, chain_id: &str) -> Self {
        Self {
            domain: body["domain"].as_str().expect("domain").to_owned(),
            uri: body["uri"].as_str().expect("uri").to_owned(),
            version: body["version"].as_str().expect("version").to_owned(),
            chain_id: chain_id.to_owned(),
            nonce: body["nonce"].as_str().expect("nonce").to_owned(),
            statement: body["statement"].as_str().map(str::to_owned),
            issued_at: body["issued_at"].as_str().expect("issued_at").to_owned(),
            expiration_time: body["expiration_time"].as_str().map(str::to_owned),
            not_before: None,
        }
    }

    /// Renders the EIP-4361 (SIWE) message for `address`.
    #[must_use]
    pub fn siwe(&self, address: &str) -> String {
        let mut message = format!(
            "{} wants you to sign in with your Ethereum account:\n{address}\n\n",
            self.domain
        );
        if let Some(statement) = &self.statement {
            message.push_str(statement);
            message.push('\n');
        }
        message.push_str(&self.tail());
        message
    }

    /// Renders the SIWS message for `address` — same shape, Solana's
    /// header line.
    #[must_use]
    pub fn siws(&self, address: &str) -> String {
        let mut message = format!(
            "{} wants you to sign in with your Solana account:\n{address}\n\n",
            self.domain
        );
        if let Some(statement) = &self.statement {
            message.push_str(statement);
            message.push('\n');
        }
        message.push_str(&self.tail());
        message
    }

    /// The `URI:`-onward half, shared by both headers.
    fn tail(&self) -> String {
        let mut out = format!(
            "URI: {}\nVersion: {}\nChain ID: {}\nNonce: {}\nIssued At: {}",
            self.uri, self.version, self.chain_id, self.nonce, self.issued_at
        );
        if let Some(expiry) = &self.expiration_time {
            out.push_str("\nExpiration Time: ");
            out.push_str(expiry);
        }
        if let Some(not_before) = &self.not_before {
            out.push_str("\nNot Before: ");
            out.push_str(not_before);
        }
        out
    }

    /// The same message bound to a different domain — the phishing shape.
    #[must_use]
    pub fn with_domain(mut self, domain: &str) -> Self {
        domain.clone_into(&mut self.domain);
        self
    }

    /// The same message naming a different chain id — the cross-chain shape,
    /// where a message minted for one chain is presented to another.
    #[must_use]
    pub fn with_chain_id(mut self, chain_id: &str) -> Self {
        chain_id.clone_into(&mut self.chain_id);
        self
    }

    /// The same message that expired an hour ago.
    #[must_use]
    pub fn expired_at(mut self, at: OffsetDateTime) -> Self {
        self.expiration_time = Some(stamp(at));
        self
    }

    /// The same message, which does not become valid until `at`.
    #[must_use]
    pub fn valid_from(mut self, at: OffsetDateTime) -> Self {
        self.not_before = Some(stamp(at));
        self
    }
}

// ---------------------------------------------------------------------------
// The kits

/// How to compose the module under test. Every field has a default, so a
/// test names only what it is actually about.
#[derive(Default, Clone)]
pub struct Spec {
    pub domain: String,
    pub chain_id: String,
    pub nonce_ttl: Option<Duration>,
    /// The EIP-1271 verifier to compose, if any. Any trait object works, so
    /// a test can compose the crate's `StaticContractVerifier` or its own
    /// recording double.
    pub contract_verifier: Option<Arc<dyn ContractSignatureVerifier>>,
    /// The `Auth` fake's mode: `TokenIsTheSubject` by default, so a bearer
    /// token names the caller and no header means anonymous.
    pub anonymous: bool,
}

impl Spec {
    /// A spec for the default composition: `wallet.test`, Ethereum
    /// mainnet, EOAs only, everyone anonymous unless they say otherwise.
    #[must_use]
    pub fn new() -> Self {
        Self {
            domain: DOMAIN.to_owned(),
            chain_id: "1".to_owned(),
            nonce_ttl: Some(Duration::seconds(600)),
            contract_verifier: None,
            anonymous: false,
        }
    }
}

/// Builds a harness over one module built to `spec`, with a `FakeAuth` that
/// reads the bearer token as the subject and a clock the test owns.
///
/// # Panics
///
/// Panics like the harness does when a migration or the build fails.
#[must_use]
pub fn kit(spec: &Spec, clock: &TestClock) -> TestHarness {
    let mut builder = Wallets::builder()
        .domain(&spec.domain)
        .statement(STATEMENT)
        .chain_id(&spec.chain_id)
        .random(SeqRandom::new());
    if let Some(ttl) = spec.nonce_ttl {
        builder = builder.nonce_ttl(ttl);
    }
    if let Some(verifier) = &spec.contract_verifier {
        builder = builder.contract_verifier(VerifierRef(Arc::clone(verifier)));
    }
    let clock = clock.clone();
    let anonymous = spec.anonymous;
    TestHarness::with_ports(vec![Box::new(builder.build())], move |ports| {
        ports.auth = Some(Arc::new(if anonymous {
            FakeAuth::new(cratefield_testing::AuthMode::Anonymous)
        } else {
            FakeAuth::subjects()
        }));
        ports.clock = Some(Arc::new(clock.clone()) as Arc<dyn Clock>);
    })
}

/// A harness over the default composition and its own clock.
#[must_use]
pub fn fixture() -> (TestHarness, TestClock) {
    let clock = test_clock();
    (kit(&Spec::new(), &clock), clock)
}

// ---------------------------------------------------------------------------
// Requests

/// A fully-buffered response.
pub struct Res {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl Res {
    /// The body as JSON, panicking with the text when it is not.
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| {
            panic!(
                "body is not JSON ({err}): {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    /// The `type` member of an RFC 9457 problem — the venture's base
    /// followed by the module's stable slug.
    #[must_use]
    pub fn problem(&self) -> String {
        self.json()["type"]
            .as_str()
            .unwrap_or_else(|| panic!("no problem type: {}", self.text()))
            .to_owned()
    }

    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Sends a request through the harness router, signed in as `subject`.
///
/// # Panics
///
/// Panics when the router itself fails (never for ordinary responses).
pub async fn send_as(
    kit: &TestHarness,
    subject: &str,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Res {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {subject}"));
    let body = match body {
        Some(body) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let request = builder.body(body).expect("request builds");
    dispatch(kit, request).await
}

/// [`send_as`] with no `Authorization` header at all — the anonymous
/// caller every route here refuses.
pub async fn send_anonymous(
    kit: &TestHarness,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Res {
    let mut builder = Request::builder().method(method).uri(path);
    let body = match body {
        Some(body) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let request = builder.body(body).expect("request builds");
    dispatch(kit, request).await
}

async fn dispatch(kit: &TestHarness, request: Request<Body>) -> Res {
    use tower::ServiceExt;
    let response = kit
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        body: bytes.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Flow helpers

/// `POST /v1/wallets/nonce` for `chain`, asserting the `200` the way a
/// client would see it.
pub async fn nonce(kit: &TestHarness, subject: &str, chain: &str) -> Fields {
    let response = send_as(
        kit,
        subject,
        Method::POST,
        "/v1/wallets/nonce",
        Some(&json!({ "chain": chain })),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "nonce: {}",
        response.text()
    );
    let body = response.json();
    Fields::from_nonce(&body, body["chain_id"].as_str().expect("chain_id"))
}

/// The `/verify` body for a chain, a message and its signature.
#[must_use]
pub fn verify_body(chain: &str, message: &str, signature: &str) -> Value {
    json!({ "chain": chain, "message": message, "signature": signature })
}

/// `POST /v1/wallets/verify`.
pub async fn verify(kit: &TestHarness, subject: &str, body: &Value) -> Res {
    send_as(kit, subject, Method::POST, "/v1/wallets/verify", Some(body)).await
}

/// Fires `body` at `/verify` from `n` callers at once and returns every
/// answer, so a test can watch the single-use nonce under real concurrency
/// rather than one call after another. The futures are joined on one thread,
/// which is enough: the store's consume is a guarded `UPDATE`, and what is
/// being proved is that the loser of the race is refused.
pub async fn verify_concurrently(
    kit: &TestHarness,
    subject: &str,
    body: &Value,
    n: usize,
) -> Vec<Res> {
    let calls = (0..n).map(|_| verify(kit, subject, body));
    futures_util::future::join_all(calls).await
}

/// `GET /v1/wallets`.
pub async fn list(kit: &TestHarness, subject: &str) -> Res {
    send_as(kit, subject, Method::GET, "/v1/wallets", None).await
}

/// `DELETE /v1/wallets/{id}`.
pub async fn unlink(kit: &TestHarness, subject: &str, id: &str) -> Res {
    send_as(
        kit,
        subject,
        Method::DELETE,
        &format!("/v1/wallets/{id}"),
        None,
    )
    .await
}

/// The linked wallets a caller can see, as `(id, chain, address)`.
#[must_use]
pub fn links(body: &Value) -> Vec<(String, String, String)> {
    body.as_array()
        .expect("the list is an array")
        .iter()
        .map(|row| {
            (
                row["id"].as_str().expect("id").to_owned(),
                row["chain"].as_str().expect("chain").to_owned(),
                row["address"].as_str().expect("address").to_owned(),
            )
        })
        .collect()
}
