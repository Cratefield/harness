//! Runs under any envelope backend feature; an age-only build has no
//! backend to exercise, so the file is compiled out.
#![cfg(any(
    feature = "rustcrypto",
    feature = "ring-backend",
    feature = "aws-lc-backend"
))]

use spike_crypto::store::{CountingKms, LocalKms, SecretsStore, UnreachableKms};
use spike_crypto::{EnvelopeAead, SecretContext};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(300);
const TENANT: &str = "01J8ZQ9P7K3M2W4N6R8T0V2X4Z6B8D0F2";
const OTHER_TENANT: &str = "02BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const KEY_ID: &str = "01J8ZQA5C7E9G1I3K5M7O9Q1S3U5W7Y9A";

// The store tests run against whichever envelope backend is enabled,
// preferring the recommended one.
fn backend() -> Box<dyn EnvelopeAead> {
    #[cfg(feature = "rustcrypto")]
    return Box::new(spike_crypto::backends::rustcrypto::XChaCha20Poly1305Aead);
    #[cfg(all(feature = "ring-backend", not(feature = "rustcrypto")))]
    return Box::new(spike_crypto::backends::ring_backend::RingAead::aes_256_gcm());
    #[cfg(all(
        feature = "aws-lc-backend",
        not(any(feature = "rustcrypto", feature = "ring-backend"))
    ))]
    return Box::new(spike_crypto::backends::aws_lc::AwsLcAead::aes_256_gcm());
}

fn counting_kms() -> Arc<CountingKms> {
    Arc::new(CountingKms::new(Arc::new(LocalKms::new(backend()))))
}

fn context(store: &str, name: &str, version: u32, key_id: &str) -> SecretContext {
    SecretContext {
        store_id: store.into(),
        secret_name: name.into(),
        version,
        key_id: key_id.into(),
    }
}

fn store(id: &str, kms: Arc<CountingKms>) -> SecretsStore {
    SecretsStore::new(id, TTL, backend(), kms)
}

#[test]
fn envelope_round_trip_and_binding() {
    let mut s = store(TENANT, counting_kms());
    s.provision_dek(KEY_ID).expect("provision");

    let ctx = context(TENANT, "stripe/secret_key", 1, KEY_ID);
    let envelope = s.encrypt(&ctx, b"sk_live_round_trip").expect("encrypt");
    assert_eq!(
        s.decrypt(&ctx, &envelope).expect("decrypt"),
        b"sk_live_round_trip"
    );

    // The same row read under a foreign context — copied store, renamed
    // secret, rolled version, swapped key id — must not open.
    for ctx in [
        context("global", "stripe/secret_key", 1, KEY_ID),
        context(TENANT, "stripe/renamed", 1, KEY_ID),
        context(TENANT, "stripe/secret_key", 0, KEY_ID),
        context(
            TENANT,
            "stripe/secret_key",
            1,
            "01J8ZQA5C7E9G1I3K5M7O9Q1S3U5W7Y9B",
        ),
    ] {
        assert!(
            s.decrypt(&ctx, &envelope).is_err(),
            "must not open: {}",
            ctx.secret_name
        );
    }
}

#[test]
fn kms_is_called_on_cache_miss_only() {
    let kms = counting_kms();
    let mut s = store(TENANT, kms.clone());
    s.provision_dek(KEY_ID).expect("provision");
    let ctx = context(TENANT, "stripe/secret_key", 1, KEY_ID);
    let envelope = s.encrypt(&ctx, b"value").expect("encrypt");

    let (wraps, unwraps) = kms.counts();
    assert_eq!(
        (wraps, unwraps),
        (1, 0),
        "one wrap at provision; cache warm, no unwrap"
    );

    for _ in 0..10 {
        s.decrypt(&ctx, &envelope).expect("decrypt from cache");
    }
    let (wraps, unwraps) = kms.counts();
    assert_eq!((wraps, unwraps), (1, 0), "warm cache: no KMS calls");

    // TTL expiry (driven directly on the cache type; time is an explicit
    // parameter, so no sleeping): entry evicted, DEK zeroised on drop.
    let mut cache = spike_crypto::store::DekCache::new(TTL);
    let dek = spike_crypto::generate_key();
    let t0 = Instant::now();
    cache.put(TENANT, KEY_ID, dek, t0);
    assert!(cache.get(TENANT, KEY_ID, t0).is_some(), "fresh entry");
    assert!(
        cache
            .get(TENANT, KEY_ID, t0 + TTL + Duration::from_secs(1))
            .is_none(),
        "expired entry evicted"
    );
    assert!(
        cache.get(TENANT, KEY_ID, t0).is_none(),
        "eviction is permanent"
    );
}

#[test]
fn kms_unreachable_warm_cache_serves_cold_store_cannot() {
    let mut warm = store(TENANT, counting_kms());
    warm.provision_dek(KEY_ID).expect("provision");
    let ctx = context(TENANT, "stripe/secret_key", 1, KEY_ID);
    let envelope = warm.encrypt(&ctx, b"value").expect("encrypt");

    // The wrapped DEK travels with the database (reading its row).
    let wrapped = warm.wrapped_dek(KEY_ID).expect("wrapped blob");

    // KMS goes down; the warm process keeps serving from its cache.
    warm.replace_kms(Arc::new(UnreachableKms));
    assert!(
        warm.decrypt(&ctx, &envelope).is_ok(),
        "warm cache survives KMS outage"
    );

    // A process that restarted while the KMS is down (cold cache, same
    // database) cannot decrypt — the design's accepted availability
    // dependency, which #37 requires to be alarmed.
    let mut cold = SecretsStore::new(TENANT, TTL, backend(), Arc::new(UnreachableKms));
    cold.adopt_wrapped_dek(wrapped, KEY_ID);
    assert!(
        cold.decrypt(&ctx, &envelope).is_err(),
        "cold process with KMS down cannot decrypt"
    );
}

#[test]
fn cross_store_copy_fails() {
    let mut tenant_a = store(TENANT, counting_kms());
    tenant_a.provision_dek(KEY_ID).expect("provision A");
    let ctx_a = context(TENANT, "stripe/secret_key", 1, KEY_ID);
    let envelope = tenant_a
        .encrypt(&ctx_a, b"tenant-a-secret")
        .expect("encrypt");

    // Tenant B holds its own DEK under a coincidentally identical key id;
    // different DEK bytes, different AAD. A's row must not open in B under
    // any context B can construct.
    let mut tenant_b = store(OTHER_TENANT, counting_kms());
    tenant_b.provision_dek(KEY_ID).expect("provision B");
    for ctx in [
        ctx_a.clone(),
        context(OTHER_TENANT, "stripe/secret_key", 1, KEY_ID),
    ] {
        assert!(
            tenant_b.decrypt(&ctx, &envelope).is_err(),
            "foreign envelope must not open in tenant B"
        );
    }
    tenant_a
        .decrypt(&ctx_a, &envelope)
        .expect("original store still opens it");
}

#[test]
fn shred_makes_ciphertexts_undecryptable() {
    let mut s = store(TENANT, counting_kms());
    s.provision_dek(KEY_ID).expect("provision");
    let ctx = context(TENANT, "stripe/secret_key", 1, KEY_ID);
    let envelope = s.encrypt(&ctx, b"offboard-me").expect("encrypt");
    assert!(s.decrypt(&ctx, &envelope).is_ok());

    s.shred(KEY_ID);
    assert!(
        s.decrypt(&ctx, &envelope).is_err(),
        "destroyed wrapped DEK: ciphertext is permanently undecryptable"
    );
    assert_eq!(s.cache_len(), 0, "shred evicts the cached copy too");
}
