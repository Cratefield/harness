#![cfg_attr(
    not(any(
        feature = "rustcrypto",
        feature = "ring-backend",
        feature = "aws-lc-backend"
    )),
    allow(dead_code)
)]

//! Per-candidate conformance for the design's encrypt/decrypt path (#38):
//! every candidate runs the SAME matrix — round trip, tamper detection,
//! and every AAD-binding failure the design requires (row copied to
//! another store, secret renamed, version rolled, key id swapped).

use spike_crypto::{Dek, EnvelopeAead, SecretContext, generate_key, random_bytes};

const PLAINTEXT: &[u8] = b"sk_test_51HypersecretStripeKey00000000";

fn ctx() -> SecretContext {
    SecretContext {
        store_id: "01J8ZQ9P7K3M2W4N6R8T0V2X4Z6B8D0F2".into(),
        secret_name: "stripe/secret_key".into(),
        version: 3,
        key_id: "01J8ZQA5C7E9G1I3K5M7O9Q1S3U5W7Y9A".into(),
    }
}

fn mutated(
    aead: &dyn EnvelopeAead,
    key: &Dek,
    nonce: &[u8],
    aad: &[u8],
    sealed: &[u8],
    f: impl FnOnce(&mut Vec<u8>),
) -> bool {
    let mut bad = sealed.to_vec();
    f(&mut bad);
    aead.open(key, nonce, aad, &bad).is_err()
}

/// The full design matrix against one backend.
fn assert_conforms(aead: &dyn EnvelopeAead) {
    let key = generate_key();
    let nonce = random_bytes(aead.nonce_len());
    let ctx = ctx();
    let aad = ctx.aad();

    let sealed = aead.seal(&key, &nonce, &aad, PLAINTEXT).expect("seal");
    assert_ne!(&sealed[..PLAINTEXT.len()], PLAINTEXT);

    let opened = aead.open(&key, &nonce, &aad, &sealed).expect("open");
    assert_eq!(opened, PLAINTEXT);

    // Tampered ciphertext and tampered tag.
    assert!(mutated(aead, &key, &nonce, &aad, &sealed, |b| b[0] ^= 1));
    assert!(
        mutated(aead, &key, &nonce, &aad, &sealed, |b| *b
            .last_mut()
            .expect("tag") ^=
            1),
        "flipped tag byte must fail"
    );

    // Tampered / wrong-length nonce.
    let mut bad_nonce = nonce.clone();
    bad_nonce[0] ^= 1;
    assert!(aead.open(&key, &bad_nonce, &aad, &sealed).is_err());
    let short: Vec<u8> = nonce[..aead.nonce_len() - 1].to_vec();
    assert!(aead.seal(&key, &short, &aad, PLAINTEXT).is_err());
    assert!(aead.open(&key, &short, &aad, &sealed).is_err());

    // Wrong key.
    let other_key: Dek = generate_key();
    assert!(aead.open(&other_key, &nonce, &aad, &sealed).is_err());

    // AAD binding: every context field the design pins must change the AAD.
    let variants = [
        // row copied to another store (tenant A -> tenant B)
        SecretContext {
            store_id: "02AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            ..ctx.clone()
        },
        // copied into the global store
        SecretContext {
            store_id: "global".into(),
            ..ctx.clone()
        },
        // secret renamed
        SecretContext {
            secret_name: "stripe/webhook_signing".into(),
            ..ctx.clone()
        },
        // version rolled
        SecretContext {
            version: 2,
            ..ctx.clone()
        },
        // pointed at a different key id
        SecretContext {
            key_id: "01J8ZQA5C7E9G1I3K5M7O9Q1S3U5W7Y9B".into(),
            ..ctx.clone()
        },
    ];
    for v in &variants {
        assert_ne!(v.aad(), aad, "variant must produce a different AAD");
        assert!(
            aead.open(&key, &nonce, &v.aad(), &sealed).is_err(),
            "{} must not open with a foreign context ({})",
            aead.name(),
            v.secret_name
        );
    }

    // AAD omission must also fail (an implementation that ignores AAD
    // cannot pass this line).
    assert!(aead.open(&key, &nonce, b"", &sealed).is_err());
}

#[cfg(feature = "rustcrypto")]
mod rustcrypto {
    #[test]
    fn xchacha20_poly1305_conforms() {
        super::assert_conforms(&spike_crypto::backends::rustcrypto::XChaCha20Poly1305Aead);
    }

    #[test]
    fn aes_256_gcm_conforms() {
        super::assert_conforms(&spike_crypto::backends::rustcrypto::Aes256GcmAead);
    }
}

#[cfg(feature = "ring-backend")]
mod ring_tests {
    #[test]
    fn ring_aes_256_gcm_conforms() {
        super::assert_conforms(&spike_crypto::backends::ring_backend::RingAead::aes_256_gcm());
    }

    #[test]
    fn ring_chacha20_poly1305_conforms() {
        super::assert_conforms(
            &spike_crypto::backends::ring_backend::RingAead::chacha20_poly1305(),
        );
    }
}

#[cfg(feature = "aws-lc-backend")]
mod aws_lc_tests {
    #[test]
    fn aws_lc_aes_256_gcm_conforms() {
        super::assert_conforms(&spike_crypto::backends::aws_lc::AwsLcAead::aes_256_gcm());
    }

    #[test]
    fn aws_lc_chacha20_poly1305_conforms() {
        super::assert_conforms(&spike_crypto::backends::aws_lc::AwsLcAead::chacha20_poly1305());
    }
}

// age: scored once. The round trip works — and the context binding the
// design REQUIRES is absent: age has no AAD parameter, so the same
// ciphertext decrypts under a swapped (or empty) context. That absence is
// the elimination, recorded here so the question does not return.
#[cfg(feature = "age-backend")]
mod age_tests {
    use spike_crypto::SecretContext;
    use spike_crypto::backends::age_backend::AgeDemo;

    #[test]
    fn age_round_trips_but_does_not_bind_context() {
        let demo = AgeDemo::generate();
        let sealed = demo.seal(b"sk_test_51HypersecretStripeKey00000000");

        let opened = demo.open(&sealed, b"");
        assert_eq!(opened, b"sk_test_51HypersecretStripeKey00000000");

        // Any "context" — another store, another name, another version —
        // decrypts just as well. age authenticates its own header, never
        // caller context. A candidate that cannot fail these opens cannot
        // implement the design's binding requirement.
        let foreign = SecretContext {
            store_id: "global".into(),
            secret_name: "renamed".into(),
            version: 99,
            key_id: "other".into(),
        };
        let still_opens = demo.open(&sealed, &foreign.aad());
        assert_eq!(still_opens, b"sk_test_51HypersecretStripeKey00000000");
    }
}
