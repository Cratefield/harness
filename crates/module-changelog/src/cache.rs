//! The optional `KeyValue` read cache. The key carries the **generation** —
//! a ULID written when a refresh actually changed something — so a refresh
//! that moves the generation orphans every older entry instantly, and a
//! lost generation key can only ever cost one TTL of staleness. Every entry
//! carries the TTL; correctness never depends on any of this: a missing
//! port, a miss and an error all read the same to the caller, and the
//! caller's answer is the database.

use std::sync::Arc;
use std::time::Duration;

use cratefield_core::{KeyValue, ModuleContext};
use sha2::{Digest, Sha256};

/// The KV key holding the current generation. Missing means `"0"`: entries
/// written before any generation was published sit under `changelog:0:…`,
/// where they are as reachable as any other entry and die by TTL.
pub(crate) const GENERATION_KEY: &str = "changelog:gen";

const KEY_PREFIX: &str = "changelog";

/// A per-request handle on the cache: absent, or live with a TTL.
pub(crate) struct ReadCache {
    kv: Option<Arc<dyn KeyValue>>,
    ttl: Option<Duration>,
}

impl ReadCache {
    /// The cache for one request's context. `ttl_secs == 0` disables it
    /// entirely — no reads, no writes.
    pub(crate) fn of(ctx: &ModuleContext, ttl_secs: u64) -> Self {
        Self {
            kv: ctx.ports.kv.clone(),
            ttl: (ttl_secs > 0).then(|| Duration::from_secs(ttl_secs)),
        }
    }

    /// The cached response body for `fingerprint`, or `None` on a miss, a
    /// disabled cache and any KV error alike — the caller cannot tell the
    /// difference and falls through to the database.
    pub(crate) async fn get(&self, fingerprint: &str) -> Option<String> {
        let kv = self.kv.as_deref()?;
        self.ttl.as_ref()?;
        let Some(generation) = generation(kv).await else {
            tracing::warn!("changelog: could not read the cache generation; reading the database");
            return None;
        };
        match kv.get(&key(&generation, fingerprint)).await {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(error = %error, "changelog: cache read failed; reading the database");
                None
            }
        }
    }

    /// Caches `body` under `fingerprint`, best-effort. A failed write is a
    /// lost cache entry, not a lost read.
    pub(crate) async fn put(&self, fingerprint: &str, body: &str) {
        let Some(kv) = self.kv.as_deref() else {
            return;
        };
        let Some(ttl) = self.ttl else {
            return;
        };
        // Re-read the generation rather than carrying one in: if a refresh
        // moved it mid-flight, the entry lands under the new generation,
        // which is where reads will look.
        let Some(generation) = generation(kv).await else {
            return;
        };
        if let Err(error) = kv
            .put(&key(&generation, fingerprint), body, Some(ttl))
            .await
        {
            tracing::warn!(error = %error, "changelog: cache write failed; reads will use the database");
        }
    }

    /// Publishes the new generation: every entry cached before this call
    /// stops resolving, instantly. Best-effort — if it fails, the old
    /// entries live out their TTL, which is the most staleness the design
    /// ever allows.
    pub(crate) async fn publish_generation(&self, generation: &str) {
        let Some(kv) = self.kv.as_deref() else {
            return;
        };
        if let Err(error) = kv.put(GENERATION_KEY, generation, None).await {
            tracing::warn!(
                error = %error,
                "changelog: could not publish the new cache generation; old entries live out their TTL"
            );
        }
    }
}

/// The full KV key for one cached response: the generation the entry was
/// written under, then the fingerprint keyed by a fixed-length hash.
fn key(generation: &str, fingerprint: &str) -> String {
    format!("{KEY_PREFIX}:{generation}:{}", fingerprint_key(fingerprint))
}

/// The generation reads and writes key under: the stored one, or `"0"`.
/// `None` means the KV port itself failed.
async fn generation(kv: &dyn KeyValue) -> Option<String> {
    match kv.get(GENERATION_KEY).await {
        Ok(Some(generation)) => Some(generation),
        Ok(None) => Some("0".to_owned()),
        Err(_) => None,
    }
}

/// The key material for one fingerprint: the SHA-256 of the **whole**
/// fingerprint, hex. The fixed length bounds the key — any path or query
/// can be one, however long — and hashing (rather than truncating) keeps
/// two fingerprints apart: a prefix cut would make two versions agreeing
/// on their first hundred bytes share one cached body, and serve one
/// release for the other with a confident 200.
fn fingerprint_key(fingerprint: &str) -> String {
    let digest = Sha256::digest(fingerprint.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("a hex digit"));
        out.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("a hex digit"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_key_by_their_whole_digest() {
        // Pinned: sha256("list:1:20"), hex — the algorithm the KV keys are
        // built on is part of what an operator sees in a KV binding.
        assert_eq!(
            fingerprint_key("list:1:20"),
            "72955ba08ab9248bf24fae638721115ed519ee6f64d749cc4d4d3854e5f9799b"
        );
        // Fixed length whatever the input, so no query can stretch a key.
        assert_eq!(fingerprint_key("").len(), 64);
        let long = "x".repeat(4096);
        assert_eq!(fingerprint_key(&long).len(), 64);
        // Two fingerprints that agree far past any prefix never alias.
        let prefix = format!("release:v9.0.0-{}", "a".repeat(200));
        let other = format!("{prefix}X");
        assert_ne!(fingerprint_key(&prefix), fingerprint_key(&other));
    }
}
