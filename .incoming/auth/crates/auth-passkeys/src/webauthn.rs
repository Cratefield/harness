//! Relying-party verification (ADR 0100).
//!
//! Upstream `webauthn-rs` pulls OpenSSL through `webauthn-rs-core` and cannot
//! build for `wasm32-unknown-unknown`, so the ceremony checks are implemented
//! here directly on the wire types. This is the spike's `q2_webauthn.rs`
//! carried into production with the four things the ADR listed as missing:
//! an origin allow-list, all three COSE algorithms a real authenticator may
//! use, a user-verification policy rather than a hard requirement, and the
//! AAGUID and raw COSE key kept for storage.
//!
//! Scope is unchanged: registration and assertion. Attestation statements
//! other than `none` are stored but not verified, which is the ordinary
//! consumer relying-party position.

use std::io::Cursor;

use coset::{AsCborValue, CoseKey, Label, RegisteredLabel, RegisteredLabelWithPrivate, iana};
use sha2::{Digest, Sha256};
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, CollectedClientData, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

/// Authenticator-data flag bits (WebAuthn level 3, section 6.1).
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
/// Extension outputs follow the credential data as one more CBOR map.
const FLAG_EXTENSION_DATA: u8 = 0x80;

/// The spec's ceiling on a credential id.
const MAX_CREDENTIAL_ID: usize = 1023;

/// The smallest authenticator data that can exist: rpIdHash, flags, counter.
const AUTH_DATA_MIN: usize = 37;
/// AAGUID (16) plus the credential-id length (2) before the id itself.
const ATTESTED_HEADER: usize = 18;

/// Whether the ceremony requires the authenticator to have verified the
/// user, or merely to have observed their presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerification {
    Required,
    Preferred,
}

impl UserVerification {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            UserVerification::Required => "required",
            UserVerification::Preferred => "preferred",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "required" => Some(UserVerification::Required),
            "preferred" => Some(UserVerification::Preferred),
            _ => None,
        }
    }
}

/// Why a ceremony was refused. Detailed for logs; every one of these maps to
/// the same answer on the wire, because telling a caller which check failed
/// tells an attacker where to aim.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum WebauthnError {
    #[error("credential type is {0:?}, not public-key")]
    CredentialType(String),
    #[error("clientDataJSON is not valid JSON: {0}")]
    ClientDataJson(String),
    #[error("client data type is {actual:?}, expected {expected:?}")]
    ClientDataType { actual: String, expected: String },
    #[error("challenge does not match the one issued")]
    ChallengeMismatch,
    #[error("origin {0:?} is not in the allow-list")]
    OriginNotAllowed(String),
    #[error("authenticator data is malformed: {0}")]
    AuthenticatorData(String),
    #[error("rpId hash does not match {0:?}")]
    RpIdMismatch(String),
    #[error("the user-present flag is not set")]
    UserNotPresent,
    #[error("user verification was required and the flag is not set")]
    UserNotVerified,
    #[error("registration carried no attested credential data")]
    NoAttestedCredential,
    #[error("attestation object is malformed: {0}")]
    AttestationObject(String),
    #[error("COSE key: {0}")]
    CoseKey(String),
    #[error("unsupported COSE algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("assertion is for a different credential")]
    CredentialMismatch,
    #[error("signature counter did not advance: stored {stored}, presented {presented}")]
    CounterRegression { stored: u32, presented: u32 },
    #[error("signature is malformed: {0}")]
    SignatureFormat(String),
    #[error("signature does not verify")]
    SignatureInvalid,
}

/// The parsed authenticator data.
pub(crate) struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub aaguid: Option<[u8; 16]>,
    pub credential_id: Option<Vec<u8>>,
    /// The COSE key exactly as the authenticator encoded it. Stored
    /// verbatim rather than re-serialised, so a round trip through our
    /// database cannot change a byte of the key a signature is checked
    /// against.
    pub cose_key_raw: Option<Vec<u8>>,
}

impl AuthData {
    pub(crate) fn user_present(&self) -> bool {
        self.flags & FLAG_USER_PRESENT != 0
    }

    pub(crate) fn user_verified(&self) -> bool {
        self.flags & FLAG_USER_VERIFIED != 0
    }
}

/// What a successful registration produced.
pub(crate) struct RegisteredCredential {
    pub credential_id: Vec<u8>,
    pub cose_key_raw: Vec<u8>,
    pub sign_count: u32,
    pub aaguid: Option<[u8; 16]>,
    pub user_verified: bool,
    pub attestation_format: String,
    /// True when the authenticator sent an attestation statement we store
    /// but do not check. Deliberate, and recorded so it is visible.
    pub attestation_unverified: bool,
}

/// What a successful assertion established.
pub(crate) struct VerifiedAssertion {
    pub sign_count: u32,
    pub user_verified: bool,
    pub user_handle: Option<Vec<u8>>,
}

pub(crate) fn parse_auth_data(bytes: &[u8]) -> Result<AuthData, WebauthnError> {
    if bytes.len() < AUTH_DATA_MIN {
        return Err(WebauthnError::AuthenticatorData(format!(
            "{} bytes, need at least {AUTH_DATA_MIN}",
            bytes.len()
        )));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&bytes[..32]);
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

    let mut aaguid = None;
    let mut credential_id = None;
    let mut cose_key_raw = None;

    if flags & FLAG_ATTESTED_CREDENTIAL_DATA != 0 {
        let rest = &bytes[AUTH_DATA_MIN..];
        if rest.len() < ATTESTED_HEADER {
            return Err(WebauthnError::AuthenticatorData(
                "truncated before the credential id length".to_owned(),
            ));
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&rest[..16]);
        aaguid = Some(id);

        let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        if id_len > MAX_CREDENTIAL_ID {
            return Err(WebauthnError::AuthenticatorData(format!(
                "credential id is {id_len} bytes; the spec allows at most {MAX_CREDENTIAL_ID}"
            )));
        }
        let key_start = ATTESTED_HEADER + id_len;
        if rest.len() < key_start {
            return Err(WebauthnError::AuthenticatorData(
                "truncated inside the credential id".to_owned(),
            ));
        }
        credential_id = Some(rest[ATTESTED_HEADER..key_start].to_vec());

        // The COSE key is CBOR of unknown length, so it is measured by
        // decoding it and asking the cursor how far it got.
        let mut cursor = Cursor::new(&rest[key_start..]);
        let value: ciborium::Value = ciborium::de::from_reader(&mut cursor)
            .map_err(|err| WebauthnError::CoseKey(err.to_string()))?;
        let mut consumed = usize::try_from(cursor.position()).unwrap_or(usize::MAX);

        // What follows the key is an extension-output map, when the ED flag
        // says so. It is read only to find where the record ends: the
        // outputs themselves are not acted on. Chrome asks for `credProtect`
        // on a security key whenever a discoverable credential is created
        // without `userVerification: required` — which is exactly what this
        // module requests — so treating those bytes as corruption would
        // refuse every such registration.
        if flags & FLAG_EXTENSION_DATA != 0 {
            let mut extensions = Cursor::new(&rest[key_start + consumed..]);
            ciborium::de::from_reader::<ciborium::Value, _>(&mut extensions)
                .map_err(|err| WebauthnError::AuthenticatorData(format!("extensions: {err}")))?;
            consumed += usize::try_from(extensions.position()).unwrap_or(usize::MAX);
        }

        let trailing = rest.len() - key_start - consumed;
        if trailing != 0 {
            return Err(WebauthnError::AuthenticatorData(format!(
                "{trailing} bytes after the authenticator data"
            )));
        }
        // Parsed once here so a key we could never verify against is
        // refused at registration rather than at the first login.
        CoseKey::from_cbor_value(value).map_err(|err| WebauthnError::CoseKey(err.to_string()))?;
        cose_key_raw = Some(rest[key_start..key_start + consumed].to_vec());
    }

    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        aaguid,
        credential_id,
        cose_key_raw,
    })
}

fn check_client_data(
    raw: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
    allowed_origins: &[url::Url],
) -> Result<CollectedClientData, WebauthnError> {
    let client_data: CollectedClientData = serde_json::from_slice(raw)
        .map_err(|err| WebauthnError::ClientDataJson(err.to_string()))?;
    if client_data.type_ != expected_type {
        return Err(WebauthnError::ClientDataType {
            actual: client_data.type_.clone(),
            expected: expected_type.to_owned(),
        });
    }
    // Constant-time is not the point here (the challenge is public once
    // used); single-use storage is what stops replay. This only has to be
    // exact.
    if client_data.challenge.as_slice() != expected_challenge {
        return Err(WebauthnError::ChallengeMismatch);
    }
    if !allowed_origins.contains(&client_data.origin) {
        return Err(WebauthnError::OriginNotAllowed(
            client_data.origin.to_string(),
        ));
    }
    Ok(client_data)
}

fn check_rp_id(auth_data: &AuthData, rp_id: &str) -> Result<(), WebauthnError> {
    let expected: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if auth_data.rp_id_hash != expected {
        return Err(WebauthnError::RpIdMismatch(rp_id.to_owned()));
    }
    Ok(())
}

fn check_presence(auth_data: &AuthData, policy: UserVerification) -> Result<(), WebauthnError> {
    if !auth_data.user_present() {
        return Err(WebauthnError::UserNotPresent);
    }
    // `preferred` means the authenticator may or may not have verified the
    // user. Refusing when it did not would reject every security key without
    // a PIN, which is exactly what "preferred" is asking us not to do.
    if policy == UserVerification::Required && !auth_data.user_verified() {
        return Err(WebauthnError::UserNotVerified);
    }
    Ok(())
}

/// The attestation object: `{ fmt, attStmt, authData }` in CBOR.
///
/// Read out of a `ciborium::Value` map rather than through a derive, so the
/// byte string stays a byte string without a `serde_bytes` dependency and a
/// missing or mistyped member is named rather than reported as "invalid
/// type".
struct AttestationObject {
    fmt: String,
    att_stmt: ciborium::Value,
    auth_data: Vec<u8>,
}

impl AttestationObject {
    fn parse(bytes: &[u8]) -> Result<Self, WebauthnError> {
        let value: ciborium::Value = ciborium::from_reader(Cursor::new(bytes))
            .map_err(|err| WebauthnError::AttestationObject(err.to_string()))?;
        let ciborium::Value::Map(entries) = value else {
            return Err(WebauthnError::AttestationObject(
                "not a CBOR map".to_owned(),
            ));
        };
        let member = |name: &str| {
            entries
                .iter()
                .find(|(key, _)| matches!(key, ciborium::Value::Text(text) if text == name))
                .map(|(_, value)| value)
        };

        let Some(ciborium::Value::Text(fmt)) = member("fmt") else {
            return Err(WebauthnError::AttestationObject("no fmt".to_owned()));
        };
        let Some(ciborium::Value::Bytes(auth_data)) = member("authData") else {
            return Err(WebauthnError::AttestationObject("no authData".to_owned()));
        };
        let att_stmt = member("attStmt")
            .cloned()
            .unwrap_or(ciborium::Value::Map(Vec::new()));

        Ok(Self {
            fmt: fmt.clone(),
            att_stmt,
            auth_data: auth_data.clone(),
        })
    }
}

pub(crate) fn verify_registration(
    rp_id: &str,
    allowed_origins: &[url::Url],
    expected_challenge: &[u8],
    policy: UserVerification,
    response: &RegisterPublicKeyCredential,
) -> Result<RegisteredCredential, WebauthnError> {
    if response.type_ != "public-key" {
        return Err(WebauthnError::CredentialType(response.type_.clone()));
    }
    check_client_data(
        response.response.client_data_json.as_slice(),
        "webauthn.create",
        expected_challenge,
        allowed_origins,
    )?;

    let attestation = AttestationObject::parse(response.response.attestation_object.as_slice())?;

    let auth_data = parse_auth_data(&attestation.auth_data)?;
    check_rp_id(&auth_data, rp_id)?;
    check_presence(&auth_data, policy)?;

    let attestation_unverified = attestation.fmt != "none";
    match (&attestation.att_stmt, attestation_unverified) {
        // `none` carries an empty map and nothing else (spec 7.1 step 20).
        (ciborium::Value::Map(entries), false) if !entries.is_empty() => {
            return Err(WebauthnError::AttestationObject(
                "format \"none\" with a non-empty attStmt".to_owned(),
            ));
        }
        (ciborium::Value::Map(_), _) => {}
        (_, _) => {
            return Err(WebauthnError::AttestationObject(format!(
                "format {:?} with a non-map attStmt",
                attestation.fmt
            )));
        }
    }

    let credential_id = auth_data
        .credential_id
        .clone()
        .ok_or(WebauthnError::NoAttestedCredential)?;
    let cose_key_raw = auth_data
        .cose_key_raw
        .clone()
        .ok_or(WebauthnError::NoAttestedCredential)?;
    // Refuse a key we could never check a signature against, now, rather
    // than storing it and failing every future login.
    verifier_for(&cose_key_raw)?;

    Ok(RegisteredCredential {
        credential_id,
        cose_key_raw,
        sign_count: auth_data.sign_count,
        aaguid: auth_data.aaguid,
        user_verified: auth_data.user_verified(),
        attestation_format: attestation.fmt,
        attestation_unverified,
    })
}

/// The credential as the database holds it, which is what an assertion is
/// checked against.
pub(crate) struct StoredPasskey<'a> {
    pub credential_id: &'a [u8],
    pub cose_key: &'a [u8],
    pub sign_count: u32,
}

pub(crate) fn verify_assertion(
    rp_id: &str,
    allowed_origins: &[url::Url],
    expected_challenge: &[u8],
    policy: UserVerification,
    stored: &StoredPasskey<'_>,
    response: &PublicKeyCredential,
) -> Result<VerifiedAssertion, WebauthnError> {
    if response.type_ != "public-key" {
        return Err(WebauthnError::CredentialType(response.type_.clone()));
    }
    check_client_data(
        response.response.client_data_json.as_slice(),
        "webauthn.get",
        expected_challenge,
        allowed_origins,
    )?;

    let auth_data = parse_auth_data(response.response.authenticator_data.as_slice())?;
    check_rp_id(&auth_data, rp_id)?;
    check_presence(&auth_data, policy)?;

    if response.get_credential_id() != stored.credential_id {
        return Err(WebauthnError::CredentialMismatch);
    }

    // The signature comes before the counter, and the order is the whole
    // point (spec 7.2: signature is step 21, counter is step 22). The
    // counter is the only check whose failure the caller acts on
    // permanently, and everything an assertion carries except the signature
    // is attacker-chosen: the credential id is handed out by the options
    // endpoint, the rpIdHash is a hash of a published domain, and the flags
    // and the counter are just bytes. Comparing counters first would let one
    // unauthenticated request with a garbage signature mark a stranger's
    // passkey as a clone and lock them out for good.
    verify_signature(stored.cose_key, &response.response)?;

    // Now that the assertion is known to come from the registered key, a
    // counter that has not advanced is the one clone signal WebAuthn gives a
    // relying party. The rule is the spec's: when either value is non-zero
    // the presented one must be greater. Authenticators that keep no counter
    // report zero forever, and those are the only ones exempt.
    if (stored.sign_count != 0 || auth_data.sign_count != 0)
        && auth_data.sign_count <= stored.sign_count
    {
        return Err(WebauthnError::CounterRegression {
            stored: stored.sign_count,
            presented: auth_data.sign_count,
        });
    }

    Ok(VerifiedAssertion {
        sign_count: auth_data.sign_count,
        user_verified: auth_data.user_verified(),
        user_handle: response
            .response
            .user_handle
            .as_ref()
            .map(|handle| handle.as_slice().to_vec()),
    })
}

/// The signed bytes of an assertion: `authenticatorData || SHA-256(clientDataJSON)`.
fn signed_bytes(assertion: &AuthenticatorAssertionResponseRaw) -> Vec<u8> {
    let client_data_hash: [u8; 32] = Sha256::digest(assertion.client_data_json.as_slice()).into();
    let mut signed =
        Vec::with_capacity(assertion.authenticator_data.as_slice().len() + client_data_hash.len());
    signed.extend_from_slice(assertion.authenticator_data.as_slice());
    signed.extend_from_slice(&client_data_hash);
    signed
}

fn verify_signature(
    cose_key_raw: &[u8],
    assertion: &AuthenticatorAssertionResponseRaw,
) -> Result<(), WebauthnError> {
    let signed = signed_bytes(assertion);
    let signature = assertion.signature.as_slice();
    match verifier_for(cose_key_raw)? {
        Verifier::Es256(key) => {
            use p256::ecdsa::signature::Verifier as _;
            // WebAuthn ES256 signatures are ASN.1 DER, not the fixed-width
            // pair.
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(|err| WebauthnError::SignatureFormat(err.to_string()))?;
            key.verify(&signed, &signature)
                .map_err(|_| WebauthnError::SignatureInvalid)
        }
        Verifier::Rs256(key) => {
            use rsa::signature::Verifier as _;
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|err| WebauthnError::SignatureFormat(err.to_string()))?;
            key.verify(&signed, &signature)
                .map_err(|_| WebauthnError::SignatureInvalid)
        }
        Verifier::Ed25519(key) => {
            use ed25519_dalek::Verifier as _;
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|err| WebauthnError::SignatureFormat(err.to_string()))?;
            key.verify(&signed, &signature)
                .map_err(|_| WebauthnError::SignatureInvalid)
        }
    }
}

/// The three algorithms a passkey may present. ES256 is what Apple, Android
/// and most security keys use; RS256 is Windows Hello; EdDSA appears on some
/// security keys.
enum Verifier {
    Es256(Box<p256::ecdsa::VerifyingKey>),
    Rs256(Box<rsa::pkcs1v15::VerifyingKey<rsa::sha2::Sha256>>),
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
}

fn cose_param(key: &CoseKey, label: i64) -> Option<&ciborium::Value> {
    key.params
        .iter()
        .find(|(candidate, _)| matches!(candidate, Label::Int(value) if *value == label))
        .map(|(_, value)| value)
}

fn cose_bytes(key: &CoseKey, label: i64) -> Option<&Vec<u8>> {
    match cose_param(key, label) {
        Some(ciborium::Value::Bytes(bytes)) => Some(bytes),
        _ => None,
    }
}

fn algorithm_is(key: &CoseKey, expected: iana::Algorithm) -> bool {
    match &key.alg {
        Some(RegisteredLabelWithPrivate::Assigned(actual)) => *actual == expected,
        // A key with no algorithm is taken at its key type's word: the
        // curve and key type already narrow it to one algorithm.
        None => true,
        Some(_) => false,
    }
}

fn curve_is(key: &CoseKey, expected: iana::EllipticCurve) -> bool {
    use coset::iana::EnumI64 as _;
    matches!(
        cose_param(key, -1),
        Some(ciborium::Value::Integer(actual)) if *actual == expected.to_i64().into()
    )
}

/// Builds a verifier from a stored COSE key, or explains why the key is
/// unusable. Called at registration too, so an unsupported key is refused
/// before it is stored.
fn verifier_for(cose_key_raw: &[u8]) -> Result<Verifier, WebauthnError> {
    let value: ciborium::Value = ciborium::from_reader(Cursor::new(cose_key_raw))
        .map_err(|err| WebauthnError::CoseKey(err.to_string()))?;
    let key =
        CoseKey::from_cbor_value(value).map_err(|err| WebauthnError::CoseKey(err.to_string()))?;

    match &key.kty {
        RegisteredLabel::Assigned(iana::KeyType::EC2) => {
            if !curve_is(&key, iana::EllipticCurve::P_256) {
                return Err(WebauthnError::UnsupportedAlgorithm(
                    "EC2 key on a curve other than P-256".to_owned(),
                ));
            }
            if !algorithm_is(&key, iana::Algorithm::ES256) {
                return Err(WebauthnError::UnsupportedAlgorithm(format!(
                    "EC2 P-256 key with algorithm {:?}",
                    key.alg
                )));
            }
            let (Some(x), Some(y)) = (cose_bytes(&key, -2), cose_bytes(&key, -3)) else {
                return Err(WebauthnError::CoseKey("missing x or y".to_owned()));
            };
            if x.len() != 32 || y.len() != 32 {
                return Err(WebauthnError::CoseKey(format!(
                    "P-256 coordinates must be 32 bytes, got x={} y={}",
                    x.len(),
                    y.len()
                )));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|err| WebauthnError::CoseKey(err.to_string()))?;
            Ok(Verifier::Es256(Box::new(key)))
        }
        RegisteredLabel::Assigned(iana::KeyType::RSA) => {
            if !algorithm_is(&key, iana::Algorithm::RS256) {
                return Err(WebauthnError::UnsupportedAlgorithm(format!(
                    "RSA key with algorithm {:?}",
                    key.alg
                )));
            }
            let (Some(n), Some(e)) = (cose_bytes(&key, -1), cose_bytes(&key, -2)) else {
                return Err(WebauthnError::CoseKey(
                    "missing modulus or exponent".to_owned(),
                ));
            };
            let public = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(n),
                rsa::BigUint::from_bytes_be(e),
            )
            .map_err(|err| WebauthnError::CoseKey(err.to_string()))?;
            Ok(Verifier::Rs256(Box::new(rsa::pkcs1v15::VerifyingKey::<
                rsa::sha2::Sha256,
            >::new(public))))
        }
        RegisteredLabel::Assigned(iana::KeyType::OKP) => {
            if !curve_is(&key, iana::EllipticCurve::Ed25519) {
                return Err(WebauthnError::UnsupportedAlgorithm(
                    "OKP key on a curve other than Ed25519".to_owned(),
                ));
            }
            if !algorithm_is(&key, iana::Algorithm::EdDSA) {
                return Err(WebauthnError::UnsupportedAlgorithm(format!(
                    "Ed25519 key with algorithm {:?}",
                    key.alg
                )));
            }
            let Some(x) = cose_bytes(&key, -2) else {
                return Err(WebauthnError::CoseKey("missing x".to_owned()));
            };
            let bytes: [u8; 32] = x.as_slice().try_into().map_err(|_| {
                WebauthnError::CoseKey(format!("Ed25519 key must be 32 bytes, got {}", x.len()))
            })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|err| WebauthnError::CoseKey(err.to_string()))?;
            Ok(Verifier::Ed25519(Box::new(key)))
        }
        other => Err(WebauthnError::UnsupportedAlgorithm(format!("{other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticator_data_shorter_than_the_header_is_refused() {
        assert!(matches!(
            parse_auth_data(&[0u8; 36]),
            Err(WebauthnError::AuthenticatorData(_))
        ));
        // Exactly the minimum, with no attested credential data, is valid.
        let data = parse_auth_data(&[0u8; AUTH_DATA_MIN]).expect("minimum is valid");
        assert_eq!(data.sign_count, 0);
        assert!(data.credential_id.is_none());
        assert!(data.aaguid.is_none());
    }

    #[test]
    fn a_truncated_credential_id_is_refused_rather_than_read_past() {
        let mut bytes = vec![0u8; AUTH_DATA_MIN];
        bytes[32] = FLAG_USER_PRESENT | FLAG_ATTESTED_CREDENTIAL_DATA;
        bytes.extend_from_slice(&[0u8; 16]);
        // Claims a 64-byte credential id and supplies none of it.
        bytes.extend_from_slice(&64u16.to_be_bytes());
        assert!(matches!(
            parse_auth_data(&bytes),
            Err(WebauthnError::AuthenticatorData(_))
        ));
    }

    #[test]
    fn presence_policy_distinguishes_required_from_preferred() {
        let present = AuthData {
            rp_id_hash: [0; 32],
            flags: FLAG_USER_PRESENT,
            sign_count: 0,
            aaguid: None,
            credential_id: None,
            cose_key_raw: None,
        };
        let verified = AuthData {
            flags: FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
            ..AuthData {
                rp_id_hash: [0; 32],
                flags: 0,
                sign_count: 0,
                aaguid: None,
                credential_id: None,
                cose_key_raw: None,
            }
        };
        let absent = AuthData {
            rp_id_hash: [0; 32],
            flags: 0,
            sign_count: 0,
            aaguid: None,
            credential_id: None,
            cose_key_raw: None,
        };

        assert!(check_presence(&present, UserVerification::Preferred).is_ok());
        assert!(check_presence(&verified, UserVerification::Required).is_ok());
        assert_eq!(
            check_presence(&present, UserVerification::Required),
            Err(WebauthnError::UserNotVerified)
        );
        assert_eq!(
            check_presence(&absent, UserVerification::Preferred),
            Err(WebauthnError::UserNotPresent)
        );
    }

    #[test]
    fn user_verification_policy_round_trips() {
        for policy in [UserVerification::Required, UserVerification::Preferred] {
            assert_eq!(UserVerification::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(UserVerification::parse("discouraged"), None);
    }

    #[test]
    fn an_unusable_cose_key_is_named_not_guessed() {
        assert!(matches!(
            verifier_for(b"not cbor at all"),
            Err(WebauthnError::CoseKey(_))
        ));
    }
}
