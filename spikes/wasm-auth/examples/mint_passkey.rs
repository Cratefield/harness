//! Host-only fixture generator for Q2 (examples are never built for the wasm
//! target).
//!
//! Acts as a software authenticator: creates a P-256 credential, records a
//! registration (attestation format `none`) and an assertion, both as
//! browser-shaped JSON via the `webauthn-rs-proto` wire types, and writes
//! them to `fixtures/passkey.json`. The signing key is a fixed scalar and the
//! ECDSA nonce is RFC 6979 deterministic, so re-running reproduces the same
//! signature byte for byte.

use base64::Engine;
use base64urlsafedata::Base64UrlSafeData;
use coset::{iana, CborSerializable, CoseKey, CoseKeyBuilder};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttestationResponseRaw, PublicKeyCredential, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs,
};

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:5173";
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

// Any valid scalar works; a fixed one keeps the fixture reproducible.
const FIXED_SIGNING_SCALAR: [u8; 32] = [0x07; 32];

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

struct AttestationObject {
    fmt: &'static str,
    auth_data: Vec<u8>,
}

impl Serialize for AttestationObject {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("fmt", self.fmt)?;
        map.serialize_entry("attStmt", &serde_json::Map::new())?;
        map.serialize_entry("authData", &ByteBuf::from(self.auth_data.clone()))?;
        map.end()
    }
}

#[derive(Serialize)]
struct PasskeyFixtureFile {
    note: &'static str,
    rp_id: &'static str,
    origin: &'static str,
    registration_challenge: String,
    assertion_challenge: String,
    registration: RegisterPublicKeyCredential,
    assertion: PublicKeyCredential,
}

// Chrome's exact clientDataJSON shape; webauthn-rs-proto parses this fine.
fn client_data_json(kind: &str, challenge: &[u8]) -> Vec<u8> {
    serde_json::json!({
        "type": kind,
        "challenge": b64u(challenge),
        "origin": ORIGIN,
        "crossOrigin": false,
    })
    .to_string()
    .into_bytes()
}

fn authenticator_data(flags: u8, sign_count: u32, attested: Option<(&[u8], &CoseKey)>) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((credential_id, cose_key)) = attested {
        data.extend_from_slice(&[0u8; 16]); // aaguid, all zeros for fmt "none"
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);
        let cose_bytes = cose_key.clone().to_vec().expect("COSE key serializes");
        data.extend_from_slice(&cose_bytes);
    }
    data
}

fn main() {
    let signing_key = SigningKey::from_slice(&FIXED_SIGNING_SCALAR).expect("scalar is valid");
    let verifying_key = VerifyingKey::from(&signing_key);
    let sec1 = verifying_key.to_sec1_point(false).as_bytes().to_vec();
    let x = sec1[1..33].to_vec();
    let y = sec1[33..65].to_vec();

    let cose_key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
        .algorithm(iana::Algorithm::ES256)
        .build();

    let credential_id = Sha256::digest(b"spike credential id").to_vec();
    let registration_challenge = Sha256::digest(b"spike registration challenge").to_vec();
    let assertion_challenge = Sha256::digest(b"spike assertion challenge").to_vec();

    let registration_client_data = client_data_json("webauthn.create", &registration_challenge);
    let registration_auth_data = authenticator_data(
        FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL_DATA,
        1,
        Some((&credential_id, &cose_key)),
    );
    let attestation_object = AttestationObject {
        fmt: "none",
        auth_data: registration_auth_data,
    };
    let mut attestation_bytes = Vec::new();
    ciborium::ser::into_writer(&attestation_object, &mut attestation_bytes)
        .expect("attestation object serializes");
    let registration = RegisterPublicKeyCredential {
        id: b64u(&credential_id),
        raw_id: Base64UrlSafeData::from(credential_id.clone()),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData::from(attestation_bytes),
            client_data_json: Base64UrlSafeData::from(registration_client_data),
            transports: None,
        },
        type_: "public-key".into(),
        extensions: RegistrationExtensionsClientOutputs::default(),
    };

    let assertion_client_data = client_data_json("webauthn.get", &assertion_challenge);
    let assertion_auth_data = authenticator_data(FLAG_USER_PRESENT | FLAG_USER_VERIFIED, 2, None);
    let mut signed = assertion_auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&assertion_client_data));
    let signature: Signature = signing_key.sign(&signed);

    let assertion = PublicKeyCredential {
        id: b64u(&credential_id),
        raw_id: Base64UrlSafeData::from(credential_id),
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: Base64UrlSafeData::from(assertion_auth_data),
            client_data_json: Base64UrlSafeData::from(assertion_client_data),
            signature: Base64UrlSafeData::from(signature.to_der().as_bytes().to_vec()),
            user_handle: None,
        },
        extensions: AuthenticationExtensionsClientOutputs::default(),
        type_: "public-key".into(),
    };

    let fixture = PasskeyFixtureFile {
        note: "recorded by examples/mint_passkey.rs (software authenticator, deterministic ECDSA)",
        rp_id: RP_ID,
        origin: ORIGIN,
        registration_challenge: b64u(&registration_challenge),
        assertion_challenge: b64u(&assertion_challenge),
        registration,
        assertion,
    };

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");
    std::fs::create_dir_all(dir).expect("fixtures dir created");
    let path = format!("{dir}/passkey.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&fixture).expect("fixture serializes"),
    )
    .expect("fixture written");
    println!("wrote {path}");
}
