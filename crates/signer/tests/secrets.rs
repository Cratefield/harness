//! The `SecretsSigner` end to end, on a real in-memory Secrets store:
//! keys sealed under tenant names, unsealed only inside `sign`, and the
//! whole conformance suite passing against it.

use std::sync::Arc;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_kms::{Dek, Kms, LocalFileKms};
use cratefield_secrets::{Actor, SecretStore, Secrets};
use cratefield_signer::{
    EvmTransaction, GuardedSigner, KeyRef, KeySigner, MemorySignAudit, Payload, Scheme,
    SecretsSigner, SignerError, StaticGuardrails, Subject,
};

fn tenant_store() -> Arc<SecretStore> {
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
    Actor::new("signer-test-suite").expect("named")
}

fn signer() -> SecretsSigner {
    SecretsSigner::new(tenant_store(), actor())
}

#[test]
fn the_secrets_signer_passes_conformance() {
    pollster::block_on(async {
        cratefield_signer::key_signer_conformance(&signer()).await;
    });
}

#[test]
fn created_keys_are_session_keys_with_verifiable_identities() {
    pollster::block_on(async {
        let signer = signer();
        let subject = Subject::new("acme", Some("ops".to_owned())).expect("a subject");
        let secp = signer
            .create_key(&subject, Scheme::Secp256k1, "trading")
            .await
            .expect("a key");
        assert_eq!(secp.role, cratefield_signer::KeyRole::Session);
        assert_eq!(secp.subject, subject);
        assert_eq!(secp.label, "trading");
        assert!(
            secp.key_ref()
                .as_str()
                .starts_with("session/secp256k1/acme/ops/trading/")
        );

        // A key that verifies: the conformance suite checks the
        // signature against the identity; here, one deliberate check —
        // a second key on the same subject and label is a *different*
        // key, not a re-derivation of the first.
        let second = signer
            .create_key(&subject, Scheme::Secp256k1, "trading")
            .await
            .expect("a key");
        assert_ne!(secp.key_ref(), second.key_ref());
        assert_ne!(secp.identity, second.identity);

        let ed = signer
            .create_key(&subject, Scheme::Ed25519, "solana")
            .await
            .expect("a key");
        assert_eq!(ed.role, cratefield_signer::KeyRole::Session);
        assert!(
            ed.key_ref()
                .as_str()
                .starts_with("session/ed25519/acme/ops/solana/"),
            "the reference carries scheme, venture, user and label: {}",
            ed.key_ref()
        );
    });
}

#[test]
fn deleting_the_secret_revokes_the_key() {
    pollster::block_on(async {
        let store = tenant_store();
        let signer = SecretsSigner::new(Arc::clone(&store), actor());
        let subject = Subject::new("acme", None).expect("a subject");
        let key = signer
            .create_key(&subject, Scheme::Secp256k1, "revocable")
            .await
            .expect("a key");
        signer
            .sign(
                key.key_ref(),
                &Payload::EvmTransaction(EvmTransaction {
                    chain_id: 1,
                    nonce: 0,
                    max_priority_fee_per_gas: 1_000_000_000,
                    max_fee_per_gas: 2_000_000_000,
                    gas_limit: 21_000,
                    to: Some("0x000000000000000000000000000000000000aaaa".to_owned()),
                    value: 0,
                    data: Vec::new(),
                }),
            )
            .await
            .expect("signs");

        store
            .delete(key.key_ref().as_str(), &actor())
            .await
            .expect("deleted");
        let err = signer
            .sign(
                key.key_ref(),
                &Payload::EvmTransaction(EvmTransaction {
                    chain_id: 1,
                    nonce: 0,
                    max_priority_fee_per_gas: 1_000_000_000,
                    max_fee_per_gas: 2_000_000_000,
                    gas_limit: 21_000,
                    to: Some("0x000000000000000000000000000000000000aaaa".to_owned()),
                    value: 0,
                    data: Vec::new(),
                }),
            )
            .await
            .expect_err("revoked");
        assert!(
            matches!(err, SignerError::UnknownKey { .. }),
            "a deleted secret is an unknown key, got: {err:?}"
        );
    });
}

#[test]
fn the_guarded_composition_works_over_the_secrets_signer() {
    pollster::block_on(async {
        let guardrails = StaticGuardrails::new()
            .allow_evm(
                1,
                "0x000000000000000000000000000000000000aaaa",
                [0xa9, 0x05, 0x9c, 0xbb],
            )
            .expect("a valid address");
        let audit = MemorySignAudit::new();
        let signer = GuardedSigner::new(signer(), guardrails, &audit);
        let subject = Subject::new("acme", None).expect("a subject");
        let key = signer
            .create_key(&subject, Scheme::Secp256k1, "session-1")
            .await
            .expect("a key");
        let payload = Payload::EvmTransaction(EvmTransaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            to: Some("0x000000000000000000000000000000000000aaaa".to_owned()),
            value: 1_000_000_000_000_000_000,
            data: vec![0xa9, 0x05, 0x9c, 0xbb],
        });
        signer
            .sign(&subject, key.key_ref(), &payload)
            .await
            .expect("allowed and signed");
        audit.verify().expect("the chain holds");
        // Two records per signature, as everywhere else.
        assert_eq!(audit.records().len(), 2);
    });
}

#[test]
fn payloads_and_keys_round_trip_through_json() {
    // The types ventures will put on a wire or in a queue.
    let payload = Payload::EvmTransaction(EvmTransaction {
        chain_id: 1,
        nonce: 7,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 2_000_000_000,
        gas_limit: 21_000,
        to: Some("0x000000000000000000000000000000000000aaaa".to_owned()),
        value: 1_000_000_000_000_000_000,
        data: vec![0xde, 0xad, 0xbe, 0xef],
    });
    let json = serde_json::to_string(&payload).expect("serialises");
    assert!(json.contains("\"kind\":\"evm_transaction\""), "{json}");
    assert!(json.contains("\"data\":\"0xdeadbeef\""), "{json}");
    // Wei amounts are decimal strings: JSON numbers cannot carry a u128.
    assert!(json.contains("\"value\":\"1000000000000000000\""), "{json}");
    let back: Payload = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, payload);

    let reference =
        KeyRef::new("session/secp256k1/acme/ops/trading/0102030405060708").expect("a reference");
    let json = serde_json::to_string(&reference).expect("serialises");
    assert_eq!(
        json,
        "\"session/secp256k1/acme/ops/trading/0102030405060708\""
    );

    let signature = cratefield_signer::Signature::Secp256k1 {
        r: [1; 32],
        s: [2; 32],
        v: 27,
    };
    let json = serde_json::to_string(&signature).expect("serialises");
    let back: cratefield_signer::Signature = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, signature);
}
