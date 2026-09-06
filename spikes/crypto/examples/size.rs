//! Binary-size probe (#38): one seal+open per enabled backend so the
//! candidate's code survives the linker, then print the backend name.
//! Measure with:
//! `cargo build --release --example size --features <candidate>` and
//! `stat` the resulting binary — commands recorded in ADR 0102.

use spike_crypto::{EnvelopeAead, SecretContext, generate_key, random_bytes};

fn main() {
    let ctx = SecretContext {
        store_id: "global".into(),
        secret_name: "probe".into(),
        version: 1,
        key_id: "k1".into(),
    };
    let aad = ctx.aad();
    let key = generate_key();
    let pt = b"probe";

    macro_rules! probe {
        ($backend:expr) => {{
            let b: Box<dyn EnvelopeAead> = Box::new($backend);
            let nonce = random_bytes(b.nonce_len());
            let ct = b.seal(&key, &nonce, &aad, pt).expect("seal");
            assert_eq!(b.open(&key, &nonce, &aad, &ct).expect("open"), pt);
            println!("{}", b.name());
        }};
    }

    #[cfg(feature = "rustcrypto")]
    {
        probe!(spike_crypto::backends::rustcrypto::XChaCha20Poly1305Aead);
        probe!(spike_crypto::backends::rustcrypto::Aes256GcmAead);
    }
    #[cfg(feature = "ring-backend")]
    {
        probe!(spike_crypto::backends::ring_backend::RingAead::aes_256_gcm());
        probe!(spike_crypto::backends::ring_backend::RingAead::chacha20_poly1305());
    }
    #[cfg(feature = "aws-lc-backend")]
    {
        probe!(spike_crypto::backends::aws_lc::AwsLcAead::aes_256_gcm());
    }
    #[cfg(feature = "age-backend")]
    {
        // Not an EnvelopeAead — seal once so its code links.
        let demo = spike_crypto::backends::age_backend::AgeDemo::generate();
        let ct = demo.seal(b"probe");
        assert_eq!(demo.open(&ct, b""), b"probe");
        println!("age (recipient demo)");
    }
}
