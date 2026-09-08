//! A software authenticator, so the ceremonies under test are real ones.
//!
//! Fixtures recorded from a browser would pin one algorithm, one origin and
//! one moment; this mints a fresh ceremony for whichever algorithm, origin,
//! challenge and counter a test needs, which is what makes the negative
//! cases (wrong origin, replayed challenge, counter regression) possible to
//! write at all. The ES256, RS256 and EdDSA paths are the three a real
//! passkey can present.

#![allow(dead_code)]

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// What Apple, Android and most security keys produce.
    Es256,
    /// Windows Hello.
    Rs256,
    /// Some security keys.
    Eddsa,
}

enum Key {
    Es256(Box<p256::ecdsa::SigningKey>),
    Rs256(Box<rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>>),
    Eddsa(Box<ed25519_dalek::SigningKey>),
}

/// One 2048-bit RSA key for the whole test binary. Generating a key per
/// test would dominate the run time for no extra coverage.
fn rsa_key() -> &'static rsa::RsaPrivateKey {
    static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("rsa key generates")
    })
}

pub struct SoftAuthenticator {
    algorithm: Algorithm,
    key: Key,
    pub credential_id: Vec<u8>,
    pub aaguid: [u8; 16],
    /// The next counter value the authenticator will report. Tests move it
    /// backwards to exercise the clone signal.
    pub counter: u32,
    /// Whether the authenticator verified the user (a PIN or biometric).
    pub user_verified: bool,
    /// Whether to append an extension-output map, as a security key does
    /// when Chrome asks for `credProtect`.
    pub extension_output: bool,
}

impl SoftAuthenticator {
    pub fn new(algorithm: Algorithm) -> Self {
        let key = match algorithm {
            // Fixed key material: these are test keys and determinism makes
            // a failure reproducible.
            Algorithm::Es256 => Key::Es256(Box::new(
                p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).expect("valid scalar"),
            )),
            Algorithm::Rs256 => Key::Rs256(Box::new(
                rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(rsa_key().clone()),
            )),
            Algorithm::Eddsa => {
                Key::Eddsa(Box::new(ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])))
            }
        };
        Self {
            algorithm,
            key,
            credential_id: b"a-test-credential-id".to_vec(),
            aaguid: [0xAB; 16],
            counter: 1,
            user_verified: true,
            extension_output: false,
        }
    }

    /// Emit extension outputs, which sets the ED flag and appends one more
    /// CBOR map after the credential data.
    pub fn with_extension_output(mut self) -> Self {
        self.extension_output = true;
        self
    }

    pub fn with_credential_id(mut self, id: &[u8]) -> Self {
        self.credential_id = id.to_vec();
        self
    }

    pub fn without_user_verification(mut self) -> Self {
        self.user_verified = false;
        self
    }

    /// The COSE public key exactly as the authenticator would encode it.
    pub fn cose_key(&self) -> Vec<u8> {
        let entries: Vec<(Value, Value)> = match &self.key {
            Key::Es256(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                vec![
                    (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
                    (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
                    (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
                    (
                        Value::Integer((-2).into()),
                        Value::Bytes(point.x().expect("x").to_vec()),
                    ),
                    (
                        Value::Integer((-3).into()),
                        Value::Bytes(point.y().expect("y").to_vec()),
                    ),
                ]
            }
            Key::Rs256(_) => {
                use rsa::traits::PublicKeyParts as _;
                // The signing key does not hand back its public half, so it
                // comes from the same generated private key.
                let public = rsa::RsaPublicKey::from(rsa_key().clone());
                let public = &public;
                vec![
                    (Value::Integer(1.into()), Value::Integer(3.into())), // kty: RSA
                    (Value::Integer(3.into()), Value::Integer((-257).into())), // alg: RS256
                    (
                        Value::Integer((-1).into()),
                        Value::Bytes(public.n().to_bytes_be()),
                    ),
                    (
                        Value::Integer((-2).into()),
                        Value::Bytes(public.e().to_bytes_be()),
                    ),
                ]
            }
            Key::Eddsa(key) => vec![
                (Value::Integer(1.into()), Value::Integer(1.into())), // kty: OKP
                (Value::Integer(3.into()), Value::Integer((-8).into())), // alg: EdDSA
                (Value::Integer((-1).into()), Value::Integer(6.into())), // crv: Ed25519
                (
                    Value::Integer((-2).into()),
                    Value::Bytes(key.verifying_key().to_bytes().to_vec()),
                ),
            ],
        };
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out).expect("cose key encodes");
        out
    }

    fn flags(&self, attested: bool) -> u8 {
        let mut flags = FLAG_UP;
        if self.user_verified {
            flags |= FLAG_UV;
        }
        if attested {
            flags |= FLAG_AT;
        }
        if attested && self.extension_output {
            flags |= FLAG_ED;
        }
        flags
    }

    fn authenticator_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        data.push(self.flags(attested));
        data.extend_from_slice(&self.counter.to_be_bytes());
        if attested {
            data.extend_from_slice(&self.aaguid);
            let id_len = u16::try_from(self.credential_id.len()).expect("short id");
            data.extend_from_slice(&id_len.to_be_bytes());
            data.extend_from_slice(&self.credential_id);
            data.extend_from_slice(&self.cose_key());
            if self.extension_output {
                // What Chrome's credProtect request comes back as.
                let outputs = Value::Map(vec![(
                    Value::Text("credProtect".to_owned()),
                    Value::Integer(2.into()),
                )]);
                let mut encoded = Vec::new();
                ciborium::into_writer(&outputs, &mut encoded).expect("extensions encode");
                data.extend_from_slice(&encoded);
            }
        }
        data
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::Es256(key) => {
                use p256::ecdsa::signature::Signer as _;
                // WebAuthn ES256 signatures are ASN.1 DER.
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_der().as_bytes().to_vec()
            }
            Key::Rs256(key) => {
                use rsa::signature::{SignatureEncoding as _, Signer as _};
                key.sign(message).to_vec()
            }
            Key::Eddsa(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(message).to_bytes().to_vec()
            }
        }
    }

    pub fn register(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
    ) -> RegisterPublicKeyCredential {
        self.register_with(rp_id, origin, challenge, "webauthn.create")
    }

    /// Registration with a client-data `type` a test chooses, for the case
    /// where a login response is replayed into the registration endpoint.
    pub fn register_with(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
        data_type: &str,
    ) -> RegisterPublicKeyCredential {
        let client_data = client_data_json(data_type, challenge, origin);
        let auth_data = self.authenticator_data(rp_id, true);
        let attestation = Value::Map(vec![
            (
                Value::Text("fmt".to_owned()),
                Value::Text("none".to_owned()),
            ),
            (Value::Text("attStmt".to_owned()), Value::Map(Vec::new())),
            (Value::Text("authData".to_owned()), Value::Bytes(auth_data)),
        ]);
        let mut attestation_object = Vec::new();
        ciborium::into_writer(&attestation, &mut attestation_object).expect("attestation encodes");

        RegisterPublicKeyCredential {
            id: Base64UrlUnpadded::encode_string(&self.credential_id),
            raw_id: self.credential_id.clone().into(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: attestation_object.into(),
                client_data_json: client_data.into_bytes().into(),
                transports: None,
            },
            type_: "public-key".to_owned(),
            extensions: webauthn_rs_proto::RegistrationExtensionsClientOutputs::default(),
        }
    }

    pub fn assert(&self, rp_id: &str, origin: &str, challenge: &[u8]) -> PublicKeyCredential {
        self.assert_with(rp_id, origin, challenge, None)
    }

    pub fn assert_with(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
        user_handle: Option<&[u8]>,
    ) -> PublicKeyCredential {
        let client_data = client_data_json("webauthn.get", challenge, origin);
        let auth_data = self.authenticator_data(rp_id, false);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let signature = self.sign(&signed);

        PublicKeyCredential {
            id: Base64UrlUnpadded::encode_string(&self.credential_id),
            raw_id: self.credential_id.clone().into(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: auth_data.into(),
                client_data_json: client_data.into_bytes().into(),
                signature: signature.into(),
                user_handle: user_handle.map(|handle| handle.to_vec().into()),
            },
            type_: "public-key".to_owned(),
            extensions: webauthn_rs_proto::AuthenticationExtensionsClientOutputs::default(),
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

/// Chrome's shape, which is what the parser has to cope with.
fn client_data_json(data_type: &str, challenge: &[u8], origin: &str) -> String {
    format!(
        r#"{{"type":"{data_type}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        Base64UrlUnpadded::encode_string(challenge)
    )
}
