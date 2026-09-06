//! The envelope path itself (#37 design): DEK generation and wrapping, the
//! TTL cache with zeroisation, and seal/open of secret values. Native-only
//! (OS RNG, `std::time`); cfg-gated off wasm builds — the AEAD layer is
//! the wasm-provable part, the store is a native-runtime concern (ADR 0008).

use crate::{Dek, Envelope, EnvelopeAead, SecretContext, generate_key, random_bytes};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct StoreError(&'static str);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for StoreError {}

/// What #40 will implement as a port over a real KMS: wrap a DEK under the
/// environment's master key (KEK), unwrap it again. The spike implements
/// it locally so the whole envelope path runs without network or credentials.
pub trait Kms: Send + Sync {
    /// Identifier of the KEK (for row metadata and key rotation).
    fn kek_id(&self) -> &str;
    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, StoreError>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, StoreError>;
}

/// Local stand-in for a KMS: holds a locally generated KEK in memory (never
/// written anywhere) and wraps DEKs with the candidate AEAD under test.
pub struct LocalKms {
    kek: Dek,
    aead: Box<dyn EnvelopeAead>,
    kek_id: String,
}

impl LocalKms {
    /// Generates the KEK in memory — the test owns it, nothing persists it.
    pub fn new(aead: Box<dyn EnvelopeAead>) -> Self {
        Self {
            kek: generate_key(),
            aead,
            kek_id: "kek-local-1".into(),
        }
    }
}

impl Kms for LocalKms {
    fn kek_id(&self) -> &str {
        &self.kek_id
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, StoreError> {
        let nonce = random_bytes(self.aead.nonce_len());
        let sealed = self
            .aead
            .seal(&self.kek, &nonce, b"fz-dek-wrap-v1", dek.as_slice())
            .map_err(|_| StoreError("kms wrap failed"))?;
        let mut out = nonce;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, StoreError> {
        let n = self.aead.nonce_len();
        if wrapped.len() < n {
            return Err(StoreError("kms unwrap failed"));
        }
        let (nonce, sealed) = wrapped.split_at(n);
        let dek = self
            .aead
            .open(&self.kek, nonce, b"fz-dek-wrap-v1", sealed)
            .map_err(|_| StoreError("kms unwrap failed"))?;
        let bytes: [u8; crate::DEK_LEN] = dek
            .as_slice()
            .try_into()
            .map_err(|_| StoreError("kms unwrap failed"))?;
        Ok(Dek::new(bytes))
    }
}

/// KMS decorator that counts wrap/unwrap calls — proves "KMS is called on
/// cache miss only" and quantifies the TTL's effect on call rate.
pub struct CountingKms {
    inner: Arc<dyn Kms>,
    wraps: AtomicU64,
    unwraps: AtomicU64,
}

impl CountingKms {
    pub fn new(inner: Arc<dyn Kms>) -> Self {
        Self {
            inner,
            wraps: AtomicU64::new(0),
            unwraps: AtomicU64::new(0),
        }
    }

    pub fn counts(&self) -> (u64, u64) {
        (
            self.wraps.load(Ordering::Relaxed),
            self.unwraps.load(Ordering::Relaxed),
        )
    }
}

impl Kms for CountingKms {
    fn kek_id(&self) -> &str {
        self.inner.kek_id()
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, StoreError> {
        self.wraps.fetch_add(1, Ordering::Relaxed);
        self.inner.wrap(dek)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, StoreError> {
        self.unwraps.fetch_add(1, Ordering::Relaxed);
        self.inner.unwrap(wrapped)
    }
}

/// A KMS that always fails — models "KMS unreachable" so the design's
/// availability behaviour can be tested: a warm cache keeps serving, a
/// cold process cannot decrypt.
pub struct UnreachableKms;

impl Kms for UnreachableKms {
    fn kek_id(&self) -> &str {
        "kek-unreachable"
    }

    fn wrap(&self, _dek: &Dek) -> Result<Vec<u8>, StoreError> {
        Err(StoreError("kms unreachable"))
    }

    fn unwrap(&self, _wrapped: &[u8]) -> Result<Dek, StoreError> {
        Err(StoreError("kms unreachable"))
    }
}

/// Unwrapped DEKs cached in process memory with a TTL, zeroised on
/// eviction and on drop. Time is passed in explicitly (`now: Instant`) so
/// tests drive expiry without sleeping — and so no hidden clock exists
/// anywhere near the wasm boundary.
pub struct DekCache {
    ttl: Duration,
    entries: HashMap<(String, String), (Instant, Dek)>,
}

impl DekCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: HashMap::new(),
        }
    }

    pub fn get(&mut self, store_id: &str, key_id: &str, now: Instant) -> Option<Dek> {
        match self
            .entries
            .get(&(store_id.to_string(), key_id.to_string()))
        {
            Some((at, dek)) if now.duration_since(*at) < self.ttl => Some(dek.clone()),
            Some(_) => {
                // Evict; the Dek (Zeroizing) zeroises on drop.
                self.entries
                    .remove(&(store_id.to_string(), key_id.to_string()));
                None
            }
            None => None,
        }
    }

    pub fn put(&mut self, store_id: &str, key_id: &str, dek: Dek, now: Instant) {
        self.entries
            .insert((store_id.to_string(), key_id.to_string()), (now, dek));
    }

    pub fn remove(&mut self, store_id: &str, key_id: &str) {
        self.entries
            .remove(&(store_id.to_string(), key_id.to_string()));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One secrets store: the global store in the control database, or a
/// tenant store inside a tenant database (ADR 0008). Holds the AEAD, the
/// KMS and the DEK cache. The wrapped DEKs live in the store's own
/// database — passed in as `wrapped_deks`, a stand-in for the #39 table.
pub struct SecretsStore {
    store_id: String,
    aead: Box<dyn EnvelopeAead>,
    kms: Arc<dyn Kms>,
    cache: DekCache,
    /// key_id -> wrapped DEK, as it would sit in the database this store
    /// protects. Cleared DEKs (offboarding = crypto-shred) are removed.
    wrapped_deks: HashMap<String, Vec<u8>>,
}

impl SecretsStore {
    pub fn new(
        store_id: impl Into<String>,
        ttl: Duration,
        aead: Box<dyn EnvelopeAead>,
        kms: Arc<dyn Kms>,
    ) -> Self {
        Self {
            store_id: store_id.into(),
            aead,
            kms,
            cache: DekCache::new(ttl),
            wrapped_deks: HashMap::new(),
        }
    }

    /// Provision this store's first (or rotated) DEK: generate 256 bits
    /// from the OS RNG, wrap it under the KMS master key, keep the wrapped
    /// blob (the database owns it) and warm the cache. Returns the key id.
    pub fn provision_dek(&mut self, key_id: impl Into<String>) -> Result<String, StoreError> {
        let key_id = key_id.into();
        let dek = generate_key();
        let wrapped = self.kms.wrap(&dek)?;
        self.wrapped_deks.insert(key_id.clone(), wrapped);
        self.cache.put(&self.store_id, &key_id, dek, Instant::now());
        Ok(key_id)
    }

    /// The wrapped DEK as stored in this store's database (one row read).
    pub fn wrapped_dek(&self, key_id: &str) -> Option<Vec<u8>> {
        self.wrapped_deks.get(key_id).cloned()
    }

    /// Adopt a wrapped DEK row (a restored backup, or a database whose
    /// store object was rebuilt) without a KMS round trip.
    pub fn adopt_wrapped_dek(&mut self, wrapped: Vec<u8>, key_id: &str) {
        self.wrapped_deks.insert(key_id.to_string(), wrapped);
    }

    /// Swap the KMS (models an outage taking hold of a warm process).
    pub fn replace_kms(&mut self, kms: Arc<dyn Kms>) {
        self.kms = kms;
    }

    fn dek(&mut self, key_id: &str) -> Result<Dek, StoreError> {
        if let Some(dek) = self.cache.get(&self.store_id, key_id, Instant::now()) {
            return Ok(dek);
        }
        // Cache miss: the wrapped DEK comes from THIS store's rows; the
        // KMS is the only way to unwrap it.
        let wrapped = self
            .wrapped_deks
            .get(key_id)
            .ok_or(StoreError("unknown key id (shredded or foreign)"))?;
        let dek = self.kms.unwrap(wrapped)?;
        self.cache
            .put(&self.store_id, key_id, dek.clone(), Instant::now());
        Ok(dek)
    }

    /// Seal one secret version with a fresh random nonce.
    pub fn encrypt(
        &mut self,
        ctx: &SecretContext,
        plaintext: &[u8],
    ) -> Result<Envelope, StoreError> {
        debug_assert_eq!(self.store_id, ctx.store_id, "context must name this store");
        let dek = self.dek(&ctx.key_id)?;
        let nonce = random_bytes(self.aead.nonce_len());
        let ciphertext = self
            .aead
            .seal(&dek, &nonce, &ctx.aad(), plaintext)
            .map_err(|_| StoreError("seal failed"))?;
        Ok(Envelope {
            key_id: ctx.key_id.clone(),
            nonce,
            ciphertext,
        })
    }

    /// Open one secret version. The AAD is recomputed from the caller's
    /// context — which is the row's identity — so a row copied between
    /// databases or renamed fails here.
    pub fn decrypt(
        &mut self,
        ctx: &SecretContext,
        envelope: &Envelope,
    ) -> Result<Vec<u8>, StoreError> {
        let dek = self.dek(&ctx.key_id)?;
        self.aead
            .open(&dek, &envelope.nonce, &ctx.aad(), &envelope.ciphertext)
            .map_err(|_| StoreError("open failed (wrong store, name, version, key, or tampered)"))
    }

    /// Crypto-shred: destroy the wrapped DEK. Offboarding a tenant is
    /// deleting its database / its wrapped DEK row; the ciphertexts become
    /// permanently undecryptable. The cached copy is evicted and zeroised.
    pub fn shred(&mut self, key_id: &str) {
        self.wrapped_deks.remove(key_id);
        self.cache.remove(&self.store_id, key_id);
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }
}
