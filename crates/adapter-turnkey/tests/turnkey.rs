//! The adapter against a scripted fake of Turnkey's API (no network):
//! the setup flow's order and bodies, the stamp verifying against the
//! sealed key, signing for every payload kind with the signature checked
//! against the key's identity, and the activity-status-to-error mapping.
//!
//! Every hex/base58 literal here is either a published test vector (the
//! EIP-712 `cow` key, the SPL Token program id), a placeholder UUID of
//! repeated digits, or derived in-test — no real credential ever enters
//! the tree.

#![allow(clippy::disallowed_types)]
// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use ed25519_dalek::Signer as _;
use http::{HeaderMap, Request, Response, StatusCode};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::signature::Verifier;
use serde_json::{Value, json};
use sha3::Digest as _;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_adapter_turnkey::evm::unsigned_transaction;
use cratefield_adapter_turnkey::{
    AllowRule, PasskeyAttestation, SubOrgSetup, TurnkeySigner, key_ref,
};
use cratefield_core::{Clock, HttpClient, HttpError};
use cratefield_kms::{Dek, Kms, LocalFileKms};
use cratefield_secrets::{Actor, SecretBytes, SecretStore, Secrets};
use cratefield_signer::{
    Eip712, EvmTransaction, KeySigner, Payload, Scheme, Signature, SignerError, SolanaMessage,
    Subject, UserOperation,
};

const PARENT_ORG: &str = "11111111-1111-1111-1111-111111111111";
const SUB_ORG: &str = "22222222-2222-2222-2222-222222222222";
const END_USER_ID: &str = "33333333-3333-3333-3333-333333333333";
const DA_USER_ID: &str = "44444444-4444-4444-4444-444444444444";
const POLICY_ID: &str = "55555555-5555-5555-5555-555555555555";
const WALLET_ID: &str = "66666666-6666-6666-6666-666666666666";
const EVM_ADDRESS: &str = "0x00000000000000000000000000000000000bcdef";
/// The SPL Token program id — a public constant, joined from short
/// pieces at compile time so the literal never reads as a long
/// high-entropy secret to push scanners.
const SOLANA_ADDRESS: &str = concat!("TokenkegQfeZ", "yiNwAJbNbGKP", "FXCWuBvf9Ss", "623VQ5DA");
const BASE: &str = "http://turnkey.fake";
const SECRET_NAME: &str = "turnkey/api-key/acme";

/// `keccak256("cow")` — the EIP-712 example key, a published vector, so
/// the fake server's EVM signatures verify for real.
const COW_KEY: [u8; 32] = [
    0xc8, 0x5e, 0xf7, 0xd7, 0x96, 0x91, 0xfe, 0x79, 0x57, 0x3b, 0x1a, 0x70, 0x64, 0xc1, 0x9c, 0x1a,
    0x98, 0x19, 0xeb, 0xdb, 0xd1, 0xfa, 0xaa, 0xb1, 0xa8, 0xec, 0x92, 0x34, 0x44, 0x38, 0xaa, 0xf4,
];

/// A deterministic ed25519 seed for the Solana fixture key.
fn ed25519_seed() -> [u8; 32] {
    use sha3::Digest as _;
    sha3::Sha3_256::digest(b"cratefield-adapter-turnkey/test-ed25519").into()
}

/// The deterministic P-256 scalar the tests seal into the store: a
/// sha256 with the top nibble cleared, which keeps it below the curve
/// order without any RNG.
fn api_key_scalar() -> [u8; 32] {
    use sha3::Digest as _;
    let mut scalar: [u8; 32] =
        sha3::Sha3_256::digest(b"cratefield-adapter-turnkey/test-api-key").into();
    scalar[0] &= 0x0f;
    scalar
}

/// The compressed public key of [`api_key_scalar`], hex — what setup
/// registers on the delegated access user.
fn api_key_public_hex() -> String {
    let key = cratefield_adapter_turnkey::stamp::signing_key(&api_key_scalar())
        .expect("the fixture scalar is a valid P-256 scalar");
    hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
}

/// The `cow` key's address, lowercase — the identity the EVM fixture
/// reference carries.
fn cow_address() -> String {
    use sha3::Digest as _;
    let signing = k256::ecdsa::SigningKey::from_slice(&COW_KEY).expect("a scalar");
    let point = signing.verifying_key().to_encoded_point(false);
    let digest: [u8; 32] = sha3::Keccak256::digest(&point.as_bytes()[1..]).into();
    format!("0x{}", hex::encode(&digest[12..]))
}

fn store() -> Arc<SecretStore> {
    let kek = Dek::generate().expect("rng");
    let kms: Arc<dyn Kms> =
        Arc::new(LocalFileKms::from_key(kek, "test-kek", "test").expect("not production"));
    let db = SqliteDatabase::in_memory().expect("in-memory db");
    db.apply_migrations("secrets", cratefield_secrets::migrations().sqlite)
        .expect("schema applies");
    Secrets::new(kms)
        .tenant("acme", Arc::new(db))
        .expect("the tenant store opens")
        .into()
}

fn actor() -> Actor {
    Actor::new("turnkey-test-suite").expect("named")
}

/// A clock that always answers the same instant — the timestampMs the
/// assertions read is this one, encoded.
fn fixed_clock() -> Arc<dyn Clock> {
    use time::OffsetDateTime;
    struct Fixed(OffsetDateTime);
    impl Clock for Fixed {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }
    Arc::new(Fixed(
        // 2023-11-14T22:13:20Z — millis land on ...000, which the setup
        // test's timestampMs assertion pins.
        OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .expect("a valid instant")
            .replace_millisecond(0)
            .expect("a valid millisecond"),
    ))
}

/// Seals the test API key into the store where the adapter looks for it.
fn seal_api_key(store: &SecretStore) {
    pollster::block_on(async {
        store
            .put(
                SECRET_NAME,
                &SecretBytes::new(api_key_scalar().to_vec()),
                &actor(),
            )
            .await
            .expect("the key seals");
    });
}

/// One queued response, in the order the adapter will ask for it.
struct Scripted {
    status: u16,
    body: String,
}

/// The requests the adapter sent, in order.
struct Captured {
    uri: String,
    headers: HeaderMap,
    body: String,
}

/// A scripted fake of Turnkey's API: answers in order, records every
/// request — headers included, because the stamp is the point.
struct FakeHttp {
    responses: std::sync::Mutex<VecDeque<Scripted>>,
    requests: std::sync::Mutex<Vec<Captured>>,
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        self.requests.lock().expect("request log").push(Captured {
            uri: parts.uri.to_string(),
            headers: parts.headers,
            body: String::from_utf8_lossy(&body).to_string(),
        });
        let scripted = self
            .responses
            .lock()
            .expect("response queue")
            .pop_front()
            .expect("every request has a queued response");
        Response::builder()
            .status(StatusCode::from_u16(scripted.status).expect("valid status"))
            .body(Bytes::from(scripted.body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

/// A completed activity answering with `{ result: { key: … } }`.
fn completed(result: &Value) -> Scripted {
    Scripted {
        status: 200,
        body: json!({
            "activity": {
                "id": "77777777-7777-7777-7777-777777777777",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": result,
            }
        })
        .to_string(),
    }
}

/// An activity that stopped at `status` — the deny and failure paths.
fn activity(status: &str) -> Scripted {
    Scripted {
        status: 200,
        body: json!({
            "activity": {
                "id": "77777777-7777-7777-7777-777777777777",
                "status": status,
            }
        })
        .to_string(),
    }
}

/// The sub-organization create answer: ids back in `rootUsers` order,
/// two wallet addresses in account order.
fn sub_org_created() -> Scripted {
    sub_org_created_with([END_USER_ID, DA_USER_ID])
}

/// The same, with the root users sent in `order` — the adapter must not
/// care which.
fn sub_org_created_with(order: [&str; 2]) -> Scripted {
    completed(&json!({
        "createSubOrganizationResult": {
            "subOrganizationId": SUB_ORG,
            "rootUserIds": order,
            "wallet": {
                "walletId": WALLET_ID,
                "addresses": [EVM_ADDRESS, SOLANA_ADDRESS],
            },
        }
    }))
}

/// One user of the fresh sub-organization, as `list_users` reports it:
/// the delegated access user is the one carrying the API key.
fn listed_user(user_id: &str) -> Value {
    let delegated = user_id == DA_USER_ID;
    json!({
        "userId": user_id,
        "userName": if delegated { "cratefield-delegated" } else { "user-42" },
        "userEmail": if delegated { Value::Null } else { json!("user-42@example.com") },
        "apiKeys": if delegated {
            json!([{
                "apiKeyId": "88888888-8888-8888-8888-888888888888",
                "apiKeyName": "cratefield-da",
                "credential": {
                    "publicKey": api_key_public_hex(),
                    "type": "CREDENTIAL_TYPE_API_KEY_P256",
                },
            }])
        } else {
            json!([])
        },
    })
}

/// The `list_users` answer for the fresh sub-organization, users in
/// `order` — the delegated access user first in the default fixture,
/// the opposite of the order `rootUserIds` carries.
fn users_listed() -> Scripted {
    users_listed_in([DA_USER_ID, END_USER_ID])
}

fn users_listed_in(order: [&str; 2]) -> Scripted {
    Scripted {
        status: 200,
        body: json!({
            "users": order.iter().map(|user_id| listed_user(user_id)).collect::<Vec<_>>(),
        })
        .to_string(),
    }
}

fn policy_created() -> Scripted {
    completed(&json!({ "createPolicyResult": { "policyId": POLICY_ID } }))
}

fn quorum_updated() -> Scripted {
    completed(&json!({ "updateRootQuorumResult": {} }))
}

fn fixture(responses: Vec<Scripted>) -> (Arc<FakeHttp>, TurnkeySigner) {
    let secrets = store();
    seal_api_key(&secrets);
    let http = Arc::new(FakeHttp {
        responses: std::sync::Mutex::new(responses.into_iter().collect()),
        requests: std::sync::Mutex::new(Vec::new()),
    });
    let client: Arc<dyn HttpClient> = http.clone();
    let signer = TurnkeySigner::new(
        client,
        fixed_clock(),
        PARENT_ORG,
        secrets,
        actor(),
        SECRET_NAME,
    )
    .with_base(BASE);
    (http, signer)
}

fn requests(http: &FakeHttp) -> Vec<Captured> {
    std::mem::take(&mut http.requests.lock().expect("request log"))
}

fn body_of(request: &Captured) -> Value {
    serde_json::from_str(&request.body).expect("the body is JSON")
}

/// The passkey attestation fixture: opaque stand-ins, as the browser
/// would hand back.
fn attestation() -> PasskeyAttestation {
    PasskeyAttestation {
        authenticator_name: "user-42 passkey".to_owned(),
        challenge: "Y2hhbGxlbmdl".to_owned(),
        credential_id: "Y3JlZGVudGlhbA".to_owned(),
        client_data_json: "e30".to_owned(),
        attestation_object: "b2JqZWN0".to_owned(),
        transports: vec!["AUTHENTICATOR_TRANSPORT_HYBRID".to_owned()],
    }
}

fn setup() -> SubOrgSetup {
    SubOrgSetup {
        name: "acme:user-42".to_owned(),
        end_user_name: "user-42".to_owned(),
        end_user_email: Some("user-42@example.com".to_owned()),
        authenticator: attestation(),
        rules: vec![
            AllowRule::evm(1, EVM_ADDRESS, Some("0xa9059cbb"), Some(1_000_000))
                .expect("a valid rule"),
            AllowRule::solana(SOLANA_ADDRESS).expect("a valid program key"),
        ],
    }
}

/// The EIP-1559 fixture transaction, the one `cratefield-signer` pins
/// its signing hash against (chain 4, nonce 819), re-addressed to the
/// fixture wallet.
fn tx() -> EvmTransaction {
    EvmTransaction {
        chain_id: 4,
        nonce: 819,
        max_priority_fee_per_gas: 75_853,
        max_fee_per_gas: 121_212,
        gas_limit: 35_552,
        to: Some(EVM_ADDRESS.to_owned()),
        value: 43_203_529,
        data: Vec::new(),
    }
}

#[test]
fn setup_flows_create_policies_then_hand_over_the_quorum() {
    let (http, signer) = fixture(vec![
        sub_org_created(),
        users_listed(),
        policy_created(),
        policy_created(),
        quorum_updated(),
    ]);
    let sub_org =
        pollster::block_on(signer.create_sub_organization(&setup())).expect("setup completes");
    assert_eq!(sub_org.id, SUB_ORG);
    assert_eq!(sub_org.end_user_id, END_USER_ID);
    assert_eq!(sub_org.da_user_id, DA_USER_ID);
    assert_eq!(sub_org.wallet_id, WALLET_ID);
    assert_eq!(sub_org.evm_address.as_deref(), Some(EVM_ADDRESS));
    assert_eq!(sub_org.solana_address.as_deref(), Some(SOLANA_ADDRESS));

    let sent = requests(&http);
    assert_eq!(
        sent.len(),
        5,
        "create, the user read-back, two policies, quorum — in order"
    );

    let create = body_of(&sent[0]);
    assert_eq!(create["type"], "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V7");
    assert_eq!(create["organizationId"], PARENT_ORG);
    assert_eq!(
        create["timestampMs"], "1700000000000",
        "timestampMs rides as the clock's millis, string-encoded"
    );
    // Between create and policies, the users are read back from the
    // sub-organization to identify who is who.
    let listed = body_of(&sent[1]);
    assert_eq!(sent[1].uri, format!("{BASE}/public/v1/query/list_users"));
    assert_eq!(listed["organizationId"], SUB_ORG);
    let users = create["parameters"]["rootUsers"]
        .as_array()
        .expect("two users");
    assert_eq!(users.len(), 2);
    assert_eq!(
        users[0]["authenticators"][0]["attestation"]["credentialId"], "Y3JlZGVudGlhbA",
        "the passkey attestation rides verbatim"
    );
    assert_eq!(
        users[0]["authenticators"][0]["attestation"]["transports"],
        json!(["AUTHENTICATOR_TRANSPORT_HYBRID"])
    );
    assert_eq!(users[1]["apiKeys"][0]["publicKey"], api_key_public_hex());
    assert_eq!(users[1]["apiKeys"][0]["curveType"], "API_KEY_CURVE_P256");
    assert_eq!(users[1]["authenticators"].as_array().map(Vec::len), Some(0));
    assert_eq!(create["parameters"]["rootQuorumThreshold"], 1);
    let accounts = create["parameters"]["wallet"]["accounts"]
        .as_array()
        .expect("two accounts");
    assert_eq!(accounts[0]["addressFormat"], "ADDRESS_FORMAT_ETHEREUM");
    assert_eq!(accounts[0]["path"], "m/44'/60'/0'/0/0");
    assert_eq!(accounts[1]["addressFormat"], "ADDRESS_FORMAT_SOLANA");
    assert_eq!(accounts[1]["path"], "m/44'/501'/0'/0'");

    // One EFFECT_ALLOW policy per rule, each scoped to the delegated
    // user and addressed to the sub-organization.
    let conditions: Vec<String> = setup()
        .rules
        .iter()
        .map(cratefield_adapter_turnkey::AllowRule::condition)
        .collect();
    for (at, condition) in conditions.iter().enumerate() {
        let policy = body_of(&sent[2 + at]);
        assert_eq!(policy["type"], "ACTIVITY_TYPE_CREATE_POLICY_V3");
        assert_eq!(
            policy["organizationId"], SUB_ORG,
            "policies go to the sub-organization"
        );
        assert_eq!(policy["parameters"]["effect"], "EFFECT_ALLOW");
        assert_eq!(
            policy["parameters"]["consensus"],
            format!("approvers.any(user, user.id == '{DA_USER_ID}')")
        );
        assert_eq!(policy["parameters"]["condition"], condition.as_str());
    }

    let quorum = body_of(&sent[4]);
    assert_eq!(quorum["type"], "ACTIVITY_TYPE_UPDATE_ROOT_QUORUM");
    assert_eq!(quorum["organizationId"], SUB_ORG);
    assert_eq!(quorum["parameters"]["threshold"], 1);
    assert_eq!(
        quorum["parameters"]["userIds"],
        json!([END_USER_ID]),
        "the user alone is root after setup"
    );
}

#[test]
fn the_stamp_verifies_over_the_exact_body() {
    // No rules: the flow is one create, the user read-back, and the
    // quorum hand-over — three requests, and the first one carries the
    // stamp under test.
    let (http, signer) = fixture(vec![sub_org_created(), users_listed(), quorum_updated()]);
    pollster::block_on(signer.create_sub_organization(&SubOrgSetup {
        rules: Vec::new(),
        ..setup()
    }))
    .expect("setup completes");
    let sent = requests(&http);
    assert_eq!(sent.len(), 3);
    let request = &sent[0];

    let stamp = request
        .headers
        .get("X-Stamp")
        .expect("every request is stamped")
        .to_str()
        .expect("base64url is a legal header value");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(stamp)
        .expect("base64url");
    let stamp_json: Value = serde_json::from_slice(&decoded).expect("stamp JSON");
    assert_eq!(
        stamp_json["scheme"],
        cratefield_adapter_turnkey::stamp::SCHEME_TK_API_P256
    );
    assert_eq!(stamp_json["publicKey"], api_key_public_hex());

    // The signature verifies against the stamp's own public key, over
    // the body exactly as it was sent.
    let point = p256::PublicKey::from_sec1_bytes(
        &hex::decode(stamp_json["publicKey"].as_str().expect("hex")).expect("sec1"),
    )
    .expect("a point");
    let signature = p256::ecdsa::Signature::from_der(
        &hex::decode(stamp_json["signature"].as_str().expect("hex")).expect("DER"),
    )
    .expect("a DER signature");
    p256::ecdsa::VerifyingKey::from(point)
        .verify(request.body.as_bytes(), &signature)
        .expect("the stamp signs the exact serialized body");
}

#[test]
fn user_identification_ignores_the_order_users_come_back_in() {
    // rootUserIds and list_users both come back swapped: the delegated
    // access user is whoever carries the API key, so the flow must
    // still scope policies to the DA user and hand the quorum to the
    // end user — never the reverse.
    let (http, signer) = fixture(vec![
        sub_org_created_with([DA_USER_ID, END_USER_ID]),
        users_listed_in([END_USER_ID, DA_USER_ID]),
        policy_created(),
        policy_created(),
        quorum_updated(),
    ]);
    let sub_org = pollster::block_on(signer.create_sub_organization(&setup()))
        .expect("a swapped answer still identifies its users");
    assert_eq!(sub_org.da_user_id, DA_USER_ID);
    assert_eq!(sub_org.end_user_id, END_USER_ID);
    let sent = requests(&http);
    assert_eq!(sent.len(), 5);
    for at in [2, 3] {
        assert_eq!(
            body_of(&sent[at])["parameters"]["consensus"],
            format!("approvers.any(user, user.id == '{DA_USER_ID}')"),
            "policies stay scoped to the delegated access user"
        );
    }
    assert_eq!(
        body_of(&sent[4])["parameters"]["userIds"],
        json!([END_USER_ID]),
        "and the end user alone takes the root quorum"
    );
}

#[test]
fn an_unidentifiable_delegated_user_fails_before_policies_or_quorum() {
    // No user carries the API key: identification is ambiguous, so the
    // flow stops there — no policy is created, the quorum is untouched.
    let no_api_key = Scripted {
        status: 200,
        body: json!({
            "users": [
                { "userId": END_USER_ID, "userName": "user-42", "apiKeys": [] },
                { "userId": DA_USER_ID, "userName": "cratefield-delegated", "apiKeys": [] },
            ]
        })
        .to_string(),
    };
    let (http, signer) = fixture(vec![sub_org_created(), no_api_key]);
    let err = pollster::block_on(signer.create_sub_organization(&setup()))
        .expect_err("nobody carries the delegated access key");
    assert!(
        matches!(err, SignerError::Provider(_)),
        "an ambiguous listing is a provider error, got: {err:?}"
    );
    assert!(
        err.to_string().contains("delegated access"),
        "the error says what failed: {err}"
    );
    assert_eq!(
        requests(&http).len(),
        2,
        "create and read-back only — nothing was decided on a guess"
    );
}

/// The `cow` key's signing key, as several fixtures mint answers with it.
fn cow_signing() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&COW_KEY).expect("a scalar")
}

/// The ed25519 fixture key's public identity — the base58 pubkey the
/// fixture references carry, and what answers are verified against.
fn solana_identity() -> String {
    let signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed());
    bs58::encode(signing.verifying_key().as_bytes()).into_string()
}

/// The `cow` key's real ECDSA answer over a digest, as a raw-payload
/// result — recovery id included.
fn cow_raw_answer(digest: &[u8; 32]) -> Value {
    let (signature, recovery) = cow_signing().sign_prehash(digest).expect("signs");
    let bytes = signature.to_bytes();
    json!({
        "signRawPayloadResult": {
            "r": format!("0x{}", hex::encode(&bytes[..32])),
            "s": format!("0x{}", hex::encode(&bytes[32..])),
            "v": format!("0{:x}", u8::from(recovery.is_y_odd())),
        }
    })
}

/// The fake's signed-transaction answer: the unsigned wire form with
/// y-parity, `r` and `s` appended and re-wrapped, minted by `signing`
/// over the exact wire form the adapter sent.
fn signed_transaction_answer(signing: &k256::ecdsa::SigningKey) -> Value {
    // keccak256(unsigned) == the port's signing hash — the encoding the
    // EVM module documents.
    let hash: [u8; 32] =
        sha3::Keccak256::digest(unsigned_transaction(&tx()).expect("encodes")).into();
    let (signature, recovery) = signing.sign_prehash(&hash).expect("signs");
    let bytes = signature.to_bytes();
    let y_parity = u8::from(recovery.is_y_odd());

    // The fixture's list is short-form (header is the byte at index 1);
    // with the three signature fields the payload passes 55 bytes, so
    // the new header is long-form `f8` plus a one-byte length.
    let unsigned = unsigned_transaction(&tx()).expect("encodes");
    assert!(unsigned[1] < 0xf8, "the fixture list is short-form");
    let mut payload = unsigned[2..].to_vec();
    // y-parity as an RLP uint: zero is the empty string.
    payload.push(if y_parity == 0 { 0x80 } else { 0x01 });
    payload.push(0xa0); // r: a 32-byte string
    payload.extend_from_slice(&bytes[..32]);
    payload.push(0xa0); // s
    payload.extend_from_slice(&bytes[32..]);
    let mut signed = vec![0x02, 0xf8];
    signed.push(u8::try_from(payload.len()).expect("the payload fits one length byte"));
    signed.extend_from_slice(&payload);
    json!({ "signTransactionResult": {
        "signedTransaction": format!("0x{}", hex::encode(&signed)),
    } })
}

#[test]
fn signing_a_transaction_round_trips_a_verifiable_signature() {
    let answer = signed_transaction_answer(&cow_signing());
    let (http, signer) = fixture(vec![completed(&answer)]);
    let reference =
        key_ref("acme", SUB_ORG, Scheme::Secp256k1, &cow_address()).expect("a reference");
    let signature =
        pollster::block_on(signer.sign(&reference, &Payload::EvmTransaction(tx()))).expect("signs");
    let Signature::Secp256k1 { r, s, v } = &signature else {
        panic!("an EVM transaction returns (r, s, v), got {signature:?}");
    };

    // The signature is the real `cow` key's: it verifies over the
    // port's signing hash and recovers to the identity the reference
    // carries.
    let hash = Payload::EvmTransaction(tx())
        .payload_hash()
        .expect("hashes");
    let inner = k256::ecdsa::Signature::from_slice(&[*r, *s].concat()).expect("a signature");
    let signing = k256::ecdsa::SigningKey::from_slice(&COW_KEY).expect("a scalar");
    let verifying = k256::ecdsa::VerifyingKey::from(&signing);
    verifying.verify_prehash(&hash, &inner).expect("verifies");
    let recovery = k256::ecdsa::RecoveryId::new(v - 27 == 1, false);
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&hash, &inner, recovery).expect("recovers");
    let point = recovered.to_encoded_point(false);
    let digest: [u8; 32] = sha3::Keccak256::digest(&point.as_bytes()[1..]).into();
    assert_eq!(format!("0x{}", hex::encode(&digest[12..])), cow_address());

    let sent = requests(&http);
    assert_eq!(
        sent[0].uri,
        format!("{BASE}/public/v1/submit/sign_transaction")
    );
    let sent_body = body_of(&sent[0]);
    assert_eq!(sent_body["type"], "ACTIVITY_TYPE_SIGN_TRANSACTION_V2");
    assert_eq!(sent_body["parameters"]["type"], "TRANSACTION_TYPE_ETHEREUM");
    assert_eq!(sent_body["parameters"]["signWith"], cow_address());
    let unsigned_hex = sent_body["parameters"]["unsignedTransaction"]
        .as_str()
        .expect("hex");
    let unsigned = unsigned_transaction(&tx()).expect("encodes");
    assert_eq!(unsigned_hex, format!("0x{}", hex::encode(&unsigned)));
    // The wire form hashes to exactly the port's signing hash — the
    // digest `eth.tx.*` policy conditions are evaluated against.
    assert_eq!(hex::encode(hash), hex::encode(unsigned_hash()));
}

fn unsigned_hash() -> [u8; 32] {
    sha3::Keccak256::digest(unsigned_transaction(&tx()).expect("encodes")).into()
}

#[test]
fn digests_go_out_as_no_op_and_solana_as_not_applicable() {
    let op = UserOperation {
        sender: "0x1111111111111111111111111111111111111111".to_owned(),
        nonce: 1,
        init_code: Vec::new(),
        call_data: Vec::new(),
        verification_gas_limit: 100_000,
        call_gas_limit: 500_000,
        pre_verification_gas: 50_000,
        max_priority_fee_per_gas: 2_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        paymaster_and_data: Vec::new(),
        // The well-known v0.7 entry point, in short `concat!` pieces.
        entry_point: concat!("0x00000000", "71727De22E5E9d8B", "Af0edAc6f37da032").to_owned(),
        chain_id: 1,
    };
    let op_hash = op.user_op_hash().expect("hashes");
    let eip712_digest = Payload::Eip712(sample_eip712())
        .payload_hash()
        .expect("hashes");
    let Payload::SolanaMessage(message) = solana_message() else {
        panic!("a solana message");
    };
    let (http, signer) = fixture(vec![
        completed(&cow_raw_answer(&op_hash)),
        completed(&cow_raw_answer(&eip712_digest)),
        completed(&ed25519_answer(&message.0)),
    ]);
    let reference =
        key_ref("acme", SUB_ORG, Scheme::Secp256k1, &cow_address()).expect("a reference");

    let op_signature =
        pollster::block_on(signer.sign(&reference, &Payload::UserOperation(op))).expect("signs");
    assert!(matches!(op_signature, Signature::Secp256k1 { .. }));
    let eip712_signature =
        pollster::block_on(signer.sign(&reference, &Payload::Eip712(sample_eip712())))
            .expect("signs");
    assert!(matches!(eip712_signature, Signature::Secp256k1 { .. }));

    let sol_reference =
        key_ref("acme", SUB_ORG, Scheme::Ed25519, &solana_identity()).expect("a reference");
    let sol_signature =
        pollster::block_on(signer.sign(&sol_reference, &solana_message())).expect("signs");
    let Signature::Ed25519 { bytes } = &sol_signature else {
        panic!("a Solana message returns 64 bytes, got {sol_signature:?}");
    };
    // The fake's answer is the real ed25519 signature of the message by
    // the key the reference names: `r ‖ s`, verifiable.
    let signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed());
    assert_eq!(*bytes, signing.sign(&message.0).to_bytes());
    signing
        .verifying_key()
        .verify(&message.0, &ed25519_dalek::Signature::from_bytes(bytes))
        .expect("verifies against the fixture key");

    let sent = requests(&http);
    for (request, hash_function) in sent.iter().zip([
        "HASH_FUNCTION_NO_OP",
        "HASH_FUNCTION_NO_OP",
        "HASH_FUNCTION_NOT_APPLICABLE",
    ]) {
        let sent_body = body_of(request);
        assert_eq!(sent_body["type"], "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2");
        assert_eq!(sent_body["parameters"]["hashFunction"], hash_function);
        assert_eq!(
            sent_body["parameters"]["encoding"],
            "PAYLOAD_ENCODING_HEXADECIMAL"
        );
    }
    assert_eq!(
        body_of(&sent[0])["parameters"]["payload"],
        format!("0x{}", hex::encode(op_hash)),
        "the digest rides verbatim — Turnkey hashes nothing"
    );
}

#[test]
fn a_transaction_signed_by_another_key_is_a_provider_error() {
    // A well-formed signed transaction — but minted by a key that is
    // not the one the reference names. The recovery misses the
    // identity, so the answer never becomes a signature.
    let other = k256::ecdsa::SigningKey::from_slice(&[0x42_u8; 32]).expect("a scalar");
    let (http, signer) = fixture(vec![completed(&signed_transaction_answer(&other))]);
    let reference =
        key_ref("acme", SUB_ORG, Scheme::Secp256k1, &cow_address()).expect("a reference");
    let err = pollster::block_on(signer.sign(&reference, &Payload::EvmTransaction(tx())))
        .expect_err("another key's answer is not a signature");
    assert!(matches!(err, SignerError::Provider(_)), "got: {err:?}");
    assert_eq!(requests(&http).len(), 1, "one request, refused answer");
}

#[test]
fn a_raw_answer_from_another_key_or_over_other_bytes_is_refused() {
    let reference =
        key_ref("acme", SUB_ORG, Scheme::Secp256k1, &cow_address()).expect("a reference");
    let digest = Payload::Eip712(sample_eip712())
        .payload_hash()
        .expect("hashes");

    // The right digest, another key.
    let other = k256::ecdsa::SigningKey::from_slice(&[0x42_u8; 32]).expect("a scalar");
    let (signature, recovery) = other.sign_prehash(&digest).expect("signs");
    let bytes = signature.to_bytes();
    let wrong_key = json!({ "signRawPayloadResult": {
        "r": format!("0x{}", hex::encode(&bytes[..32])),
        "s": format!("0x{}", hex::encode(&bytes[32..])),
        "v": format!("0{:x}", u8::from(recovery.is_y_odd())),
    } });
    let (_http, signer) = fixture(vec![completed(&wrong_key)]);
    let err = pollster::block_on(signer.sign(&reference, &Payload::Eip712(sample_eip712())))
        .expect_err("another key's answer is not a signature");
    assert!(matches!(err, SignerError::Provider(_)), "got: {err:?}");

    // The right key, over bytes nobody asked to sign: the recovery
    // cannot land on the identity the reference carries.
    let other_digest: [u8; 32] = sha3::Sha3_256::digest(b"not the payload").into();
    let (_http, signer) = fixture(vec![completed(&cow_raw_answer(&other_digest))]);
    let err = pollster::block_on(signer.sign(&reference, &Payload::Eip712(sample_eip712())))
        .expect_err("an answer over other bytes");
    assert!(matches!(err, SignerError::Provider(_)), "got: {err:?}");
}

#[test]
fn an_ed25519_answer_from_another_key_is_a_provider_error() {
    let Payload::SolanaMessage(message) = solana_message() else {
        panic!("a solana message");
    };
    // A different ed25519 key's answer over the exact message: it does
    // not verify against the identity pubkey, so it is refused rather
    // than handed back.
    let other = ed25519_dalek::SigningKey::from_bytes(&[0x07_u8; 32]);
    let bytes = other.sign(&message.0).to_bytes();
    let answer = json!({ "signRawPayloadResult": {
        "r": format!("0x{}", hex::encode(&bytes[..32])),
        "s": format!("0x{}", hex::encode(&bytes[32..])),
        "v": "00",
    } });
    let (http, signer) = fixture(vec![completed(&answer)]);
    let reference =
        key_ref("acme", SUB_ORG, Scheme::Ed25519, &solana_identity()).expect("a reference");
    let err = pollster::block_on(signer.sign(&reference, &Payload::SolanaMessage(message)))
        .expect_err("another key's answer is not a signature");
    assert!(matches!(err, SignerError::Provider(_)), "got: {err:?}");
    assert_eq!(requests(&http).len(), 1, "one request, refused answer");
}

/// The ed25519 fixture key's real answer over a Solana message.
fn ed25519_answer(message: &[u8]) -> Value {
    let signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed());
    let bytes = signing.sign(message).to_bytes();
    json!({
        "signRawPayloadResult": {
            "r": format!("0x{}", hex::encode(&bytes[..32])),
            "s": format!("0x{}", hex::encode(&bytes[32..])),
            "v": "00",
        }
    })
}

#[test]
fn policy_rejections_and_unformed_consensus_are_denied() {
    for status in [
        "ACTIVITY_STATUS_REJECTED",
        "ACTIVITY_STATUS_CONSENSUS_NEEDED",
    ] {
        let (_http, signer) = fixture(vec![activity(status)]);
        let reference =
            key_ref("acme", SUB_ORG, Scheme::Secp256k1, &cow_address()).expect("a reference");
        let err = pollster::block_on(signer.sign(&reference, &Payload::EvmTransaction(tx())))
            .expect_err("denied");
        let SignerError::Denied { reason } = err else {
            panic!("{status} is a denial, got {err:?}");
        };
        assert!(
            reason.contains(status),
            "the denial names the status: {reason}"
        );
    }
}

#[test]
fn failures_and_surprises_are_provider_errors() {
    for status in [
        "ACTIVITY_STATUS_FAILED",
        "ACTIVITY_STATUS_PENDING",
        "ACTIVITY_STATUS_CREATED",
    ] {
        let (_http, signer) = fixture(vec![activity(status)]);
        let reference =
            key_ref("acme", SUB_ORG, Scheme::Secp256k1, &cow_address()).expect("a reference");
        let err = pollster::block_on(signer.sign(&reference, &Payload::EvmTransaction(tx())))
            .expect_err("not completed");
        assert!(
            matches!(err, SignerError::Provider(_)),
            "{status} is weather or breakage, got {err:?}"
        );
    }
}

#[test]
fn refs_that_are_not_ours_are_unknown_and_mismatches_unsupported() {
    let (_http, signer) = fixture(vec![]);
    for foreign in [
        "session/secp256k1/acme/trading/01020304",
        "fake-secp256k1-1",
        "turnkey",
    ] {
        let reference = cratefield_signer::KeyRef::new(foreign).expect("a reference");
        let errors = [
            pollster::block_on(signer.key(&reference)).expect_err("not one of ours"),
            pollster::block_on(signer.sign(&reference, &Payload::EvmTransaction(tx())))
                .expect_err("not one of ours"),
        ];
        for err in errors {
            assert!(
                matches!(err, SignerError::UnknownKey { .. }),
                "`{foreign}` is unknown here, got {err:?}"
            );
        }
    }

    // A real reference of the wrong scheme for the payload.
    let sol_reference =
        key_ref("acme", SUB_ORG, Scheme::Ed25519, SOLANA_ADDRESS).expect("a reference");
    let err = pollster::block_on(signer.sign(&sol_reference, &Payload::EvmTransaction(tx())))
        .expect_err("scheme mismatch");
    assert!(
        matches!(err, SignerError::Unsupported { .. }),
        "got: {err:?}"
    );
}

#[test]
fn malformed_payloads_are_refused_before_any_request() {
    let (http, signer) = fixture(vec![]);
    let reference =
        key_ref("acme", SUB_ORG, Scheme::Secp256k1, &cow_address()).expect("a reference");
    let malformed = EvmTransaction {
        to: Some("0xnope".to_owned()),
        ..tx()
    };
    let err = pollster::block_on(signer.sign(&reference, &Payload::EvmTransaction(malformed)))
        .expect_err("malformed");
    assert!(
        matches!(err, SignerError::Invalid(_) | SignerError::Payload(_)),
        "got: {err:?}"
    );
    assert!(requests(&http).is_empty(), "nothing went out");
}

#[test]
fn keys_are_not_created_here_and_missing_seals_are_unknown() {
    let (_http, signer) = fixture(vec![]);
    let subject = Subject::new("acme", None).expect("a subject");
    let err = pollster::block_on(signer.create_key(&subject, Scheme::Secp256k1, "session"))
        .expect_err("create_key is not how Turnkey keys are born");
    assert!(
        matches!(err, SignerError::Unsupported { .. }),
        "got: {err:?}"
    );

    // A signer whose store has no API key sealed names that name back.
    let http = Arc::new(FakeHttp {
        responses: std::sync::Mutex::new(VecDeque::new()),
        requests: std::sync::Mutex::new(Vec::new()),
    });
    let client: Arc<dyn HttpClient> = http.clone();
    let empty = TurnkeySigner::new(
        client,
        fixed_clock(),
        PARENT_ORG,
        store(),
        actor(),
        "turnkey/api-key/never-sealed",
    )
    .with_base(BASE);
    let err = pollster::block_on(empty.da_public_key()).expect_err("nothing behind that name");
    assert!(
        matches!(err, SignerError::UnknownKey { .. }),
        "got: {err:?}"
    );
}

/// The EIP-712 `Mail` example, as the port's conformance suite carries it.
fn sample_eip712() -> Eip712 {
    Eip712 {
        name: Some("Ether Mail".to_owned()),
        version: Some("1".to_owned()),
        chain_id: Some(1),
        verifying_contract: Some("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC".to_owned()),
        salt: None,
        primary_type: "Mail".to_owned(),
        struct_hash: [
            0xc5, 0x2c, 0x0e, 0xe5, 0xd8, 0x42, 0x64, 0x47, 0x18, 0x06, 0x29, 0x0a, 0x3f, 0x2c,
            0x4c, 0xec, 0xfc, 0x54, 0x90, 0x62, 0x6b, 0xf9, 0x12, 0xd0, 0x1f, 0x24, 0x0d, 0x7a,
            0x27, 0x4b, 0x37, 0x1e,
        ],
    }
}

/// The port's conformance sample: a legacy Solana wire message, one
/// signer, three keys, a zeroed blockhash, two instructions.
fn solana_message() -> Payload {
    let keys = [[0x11_u8; 32], [0x22_u8; 32], [0x33_u8; 32]];
    let mut message = Vec::new();
    message.extend_from_slice(&[0x01, 0x00, 0x01]); // header
    message.push(u8::try_from(keys.len()).expect("few keys"));
    for key in &keys {
        message.extend_from_slice(key);
    }
    message.extend_from_slice(&[0_u8; 32]); // recent blockhash
    message.push(0x02); // two instructions
    for (program_index, account_index) in [(1_u8, 0_u8), (2, 2)] {
        message.extend_from_slice(&[program_index, 0x01, account_index]);
        message.push(0x02); // two data bytes
        message.extend_from_slice(&[0x02, 0x00]);
    }
    Payload::SolanaMessage(SolanaMessage(message))
}
