//! Q2: pure-Rust WebAuthn relying-party verification.
//!
//! Scope per BUILD-BRIEF.md: registration and login only, attestation format
//! `none` accepted, other formats stored unverified. Wire types come from
//! `webauthn-rs-proto`, CBOR/COSE from `ciborium`/`coset`, signatures from
//! `p256`, the client-data hash from `sha2`.

use std::io::Cursor;

use coset::{
    iana, iana::EnumI64, AsCborValue, CoseKey, Label, RegisteredLabel, RegisteredLabelWithPrivate,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, CollectedClientData, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

pub const FLAG_USER_PRESENT: u8 = 0x01;
pub const FLAG_USER_VERIFIED: u8 = 0x04;
pub const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub credential_id: Option<Vec<u8>>,
    pub cose_public_key: Option<CoseKey>,
}

pub struct RegisteredCredential {
    pub credential_id: Vec<u8>,
    pub cose_public_key: CoseKey,
    pub sign_count: u32,
    pub attestation_format: String,
    pub attestation_unverified: bool,
}

#[derive(Debug, Serialize)]
pub struct AssertionVerified {
    pub credential_id: String,
    pub sign_count: u32,
    pub user_handle: Option<String>,
}

fn b64u(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn parse_auth_data(bytes: &[u8]) -> Result<AuthData, String> {
    if bytes.len() < 37 {
        return Err(format!(
            "authenticator data too short: {} bytes, need at least 37",
            bytes.len()
        ));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&bytes[..32]);
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

    let mut credential_id = None;
    let mut cose_public_key = None;
    if flags & FLAG_ATTESTED_CREDENTIAL_DATA != 0 {
        let rest = &bytes[37..];
        if rest.len() < 18 {
            return Err("attested credential data truncated before credential id length".into());
        }
        let cred_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
        let body_start = 18 + cred_len;
        if rest.len() < body_start {
            return Err("attested credential data truncated inside credential id".into());
        }
        let mut cursor = Cursor::new(&rest[body_start..]);
        let cbor_value: ciborium::Value =
            ciborium::de::from_reader(&mut cursor).map_err(|e| format!("COSE key CBOR: {e}"))?;
        let consumed = cursor.position() as usize;
        let trailing = &rest[body_start + consumed..];
        if !trailing.is_empty() {
            return Err(format!(
                "{} trailing bytes after the COSE key in authenticator data",
                trailing.len()
            ));
        }
        let key =
            CoseKey::from_cbor_value(cbor_value).map_err(|e| format!("COSE key structure: {e}"))?;
        credential_id = Some(rest[18..body_start].to_vec());
        cose_public_key = Some(key);
    }

    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id,
        cose_public_key,
    })
}

fn check_client_data(
    raw: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
    expected_origin: &url::Url,
) -> Result<CollectedClientData, String> {
    let client_data: CollectedClientData =
        serde_json::from_slice(raw).map_err(|e| format!("clientDataJSON parse: {e}"))?;
    if client_data.type_ != expected_type {
        return Err(format!(
            "client data type {:?}, expected {expected_type:?}",
            client_data.type_
        ));
    }
    if client_data.challenge.as_slice() != expected_challenge {
        return Err("challenge mismatch".into());
    }
    if &client_data.origin != expected_origin {
        return Err(format!(
            "origin mismatch: fixture {:?}, expected {:?}",
            client_data.origin, expected_origin
        ));
    }
    Ok(client_data)
}

fn check_rp_id_hash(auth_data: &AuthData, rp_id: &str) -> Result<(), String> {
    let expected: [u8; 32] = Sha256::digest(rp_id.as_bytes())
        .as_slice()
        .try_into()
        .expect("sha256 is 32 bytes");
    if auth_data.rp_id_hash != expected {
        return Err("rpId hash mismatch".into());
    }
    Ok(())
}

fn cose_param(key: &CoseKey, label: i64) -> Option<&ciborium::Value> {
    key.params
        .iter()
        .find(|(l, _)| matches!(l, Label::Int(v) if *v == label))
        .map(|(_, v)| v)
}

pub fn p256_verifying_key(cose: &CoseKey) -> Result<VerifyingKey, String> {
    if cose.kty != RegisteredLabel::Assigned(iana::KeyType::EC2) {
        return Err(format!("COSE key type is not EC2: {:?}", cose.kty));
    }
    let p_256 = ciborium::Value::Integer(iana::EllipticCurve::P_256.to_i64().into());
    match cose_param(cose, -1) {
        Some(crv) if *crv == p_256 => {}
        other => return Err(format!("COSE curve is not P-256: {other:?}")),
    }
    if let Some(alg) = &cose.alg {
        if *alg != RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256) {
            return Err(format!("COSE algorithm is not ES256: {alg:?}"));
        }
    }
    let (Some(ciborium::Value::Bytes(x)), Some(ciborium::Value::Bytes(y))) =
        (cose_param(cose, -2), cose_param(cose, -3))
    else {
        return Err("COSE key missing x or y coordinate".into());
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(format!(
            "P-256 coordinates must be 32 bytes: x={}, y={}",
            x.len(),
            y.len()
        ));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| format!("invalid P-256 public key: {e}"))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AttestationObject {
    fmt: String,
    #[serde(rename = "attStmt")]
    att_stmt: ciborium::Value,
    #[serde(with = "serde_bytes", rename = "authData")]
    auth_data: Vec<u8>,
}

pub fn verify_registration(
    rp_id: &str,
    origin: &url::Url,
    expected_challenge: &[u8],
    response: &RegisterPublicKeyCredential,
) -> Result<RegisteredCredential, String> {
    if response.type_ != "public-key" {
        return Err(format!("credential type {:?}", response.type_));
    }
    let raw: &[u8] = response.response.client_data_json.as_slice();
    check_client_data(raw, "webauthn.create", expected_challenge, origin)?;

    let attestation: AttestationObject =
        ciborium::from_reader(Cursor::new(response.response.attestation_object.as_slice()))
            .map_err(|e| format!("attestationObject CBOR: {e}"))?;

    let auth_data = parse_auth_data(&attestation.auth_data)?;
    check_rp_id_hash(&auth_data, rp_id)?;
    if auth_data.flags & FLAG_USER_PRESENT == 0 {
        return Err("user-present flag not set".into());
    }
    let attestation_unverified = attestation.fmt != "none";
    if attestation_unverified && !matches!(attestation.att_stmt, ciborium::Value::Map(_)) {
        return Err(format!(
            "attestation format {:?} has a non-map attStmt",
            attestation.fmt
        ));
    }

    let credential_id = auth_data
        .credential_id
        .clone()
        .ok_or("no attested credential data in registration")?;
    let cose_public_key = auth_data
        .cose_public_key
        .clone()
        .ok_or("no COSE public key in registration")?;
    p256_verifying_key(&cose_public_key)?;

    Ok(RegisteredCredential {
        credential_id,
        cose_public_key,
        sign_count: auth_data.sign_count,
        attestation_format: attestation.fmt,
        attestation_unverified,
    })
}

fn assertion_input(
    assertion: &AuthenticatorAssertionResponseRaw,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let client_data_raw = assertion.client_data_json.as_slice();
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_raw)
        .as_slice()
        .try_into()
        .expect("sha256 is 32 bytes");
    let mut signed = Vec::with_capacity(assertion.authenticator_data.len() + 32);
    signed.extend_from_slice(assertion.authenticator_data.as_slice());
    signed.extend_from_slice(&client_data_hash);
    Ok((signed, client_data_hash))
}

pub fn verify_assertion(
    rp_id: &str,
    origin: &url::Url,
    expected_challenge: &[u8],
    credential: &RegisteredCredential,
    response: &PublicKeyCredential,
) -> Result<AssertionVerified, String> {
    if response.type_ != "public-key" {
        return Err(format!("credential type {:?}", response.type_));
    }
    let raw: &[u8] = response.response.client_data_json.as_slice();
    check_client_data(raw, "webauthn.get", expected_challenge, origin)?;

    let auth_data = parse_auth_data(response.response.authenticator_data.as_slice())?;
    check_rp_id_hash(&auth_data, rp_id)?;
    if auth_data.flags & FLAG_USER_PRESENT == 0 {
        return Err("user-present flag not set".into());
    }
    if auth_data.flags & FLAG_USER_VERIFIED == 0 {
        return Err("user-verified flag not set".into());
    }
    if response.get_credential_id() != credential.credential_id.as_slice() {
        return Err("credential id does not match the registered credential".into());
    }
    if credential.sign_count != 0
        && auth_data.sign_count != 0
        && auth_data.sign_count <= credential.sign_count
    {
        return Err(format!(
            "signature counter did not advance: stored {}, got {}",
            credential.sign_count, auth_data.sign_count
        ));
    }

    let (signed, _client_hash) = assertion_input(&response.response)?;
    let signature = Signature::from_der(response.response.signature.as_slice())
        .map_err(|e| format!("signature DER parse: {e}"))?;
    let verifying_key = p256_verifying_key(&credential.cose_public_key)?;
    verifying_key
        .verify(&signed, &signature)
        .map_err(|e| format!("assertion signature invalid: {e}"))?;

    Ok(AssertionVerified {
        credential_id: b64u(&credential.credential_id),
        sign_count: auth_data.sign_count,
        user_handle: response
            .response
            .user_handle
            .as_ref()
            .map(|h| b64u(h.as_slice())),
    })
}

#[derive(Deserialize)]
pub struct PasskeyFixture {
    pub rp_id: String,
    pub origin: url::Url,
    pub registration_challenge: String,
    pub assertion_challenge: String,
    pub registration: RegisterPublicKeyCredential,
    pub assertion: PublicKeyCredential,
}

fn b64u_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url decode: {e}"))
}

pub fn run_fixture(fixture: &PasskeyFixture) -> Result<AssertionVerified, String> {
    let registration_challenge = b64u_decode(&fixture.registration_challenge)?;
    let assertion_challenge = b64u_decode(&fixture.assertion_challenge)?;
    let credential = verify_registration(
        &fixture.rp_id,
        &fixture.origin,
        &registration_challenge,
        &fixture.registration,
    )?;
    verify_assertion(
        &fixture.rp_id,
        &fixture.origin,
        &assertion_challenge,
        &credential,
        &fixture.assertion,
    )
}
