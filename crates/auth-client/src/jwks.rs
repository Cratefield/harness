//! Fetching and caching the issuer's public keys.
//!
//! Keys rotate, so a cache that never refreshes eventually rejects every
//! token; a cache that refreshes on demand lets anyone drive traffic at
//! the auth service by presenting tokens naming keys that do not exist.
//! Both are handled: a TTL for the ordinary case, and a forced refetch
//! on an unknown key id that is itself rate-limited.

use std::sync::{Arc, RwLock};

use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::Bytes;
use cratefield_core::{Clock, HttpClient};
use futures_util::lock::Mutex;
use p256::ecdsa::VerifyingKey;
use serde::Deserialize;

use crate::verify::{Claims, VerifyError, peek_kid, verify_with};
use crate::{JWKS_MIN_REFETCH_SECS, JWKS_TTL_SECS};

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: Option<String>,
    kid: Option<String>,
    x: Option<String>,
    y: Option<String>,
    /// Present only on a private key. Its presence is a bug at the
    /// issuer, and this client refuses such a key rather than using it.
    #[serde(default)]
    d: Option<String>,
}

/// The cached key set and the times that govern refetching.
#[derive(Default)]
pub struct JwksCache {
    keys: Vec<(String, VerifyingKey)>,
    fetched_at: Option<i64>,
    last_forced: Option<i64>,
}

impl JwksCache {
    fn is_fresh(&self, now: i64) -> bool {
        self.fetched_at.is_some_and(|at| now - at < JWKS_TTL_SECS)
    }

    fn may_force(&self, now: i64) -> bool {
        self.last_forced
            .is_none_or(|at| now - at >= JWKS_MIN_REFETCH_SECS)
    }
}

/// Verifies tokens issued by one auth instance, for one
/// registered client.
pub struct AuthClient {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    issuer: String,
    jwks_uri: String,
    client_id: String,
    /// Read-mostly: every verification reads it, only a refetch writes.
    /// `RwLock` rather than `Mutex` for that reason, and because the
    /// lint bans `Mutex` as shared mutable state (ADR 0007). This is
    /// wiring state, not request state.
    cache: RwLock<JwksCache>,
    /// Held across a fetch, so concurrent verifications take turns rather
    /// than each deciding to refetch. A cold cache, or the instant a TTL
    /// lapses under load, otherwise sends one JWKS request per waiting
    /// verification — and lets a slow fetch that started earlier land
    /// after a faster one and overwrite the newer key set.
    ///
    /// An async mutex, and not a `std::sync::Mutex` held across the
    /// `await`: this crate is wasm-safe (ADR 0200), where the standard
    /// mutex has no thread primitives to block on.
    flight: Mutex<()>,
}

impl AuthClient {
    /// `issuer` is the auth service's base URL, exactly as it appears in
    /// the `iss` claim. `client_id` is this app's registered id, and is
    /// what every token's `aud` must equal.
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        let issuer = issuer.into();
        let jwks_uri = format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'));
        Self {
            http,
            clock,
            issuer,
            jwks_uri,
            client_id: client_id.into(),
            cache: RwLock::new(JwksCache::default()),
            flight: Mutex::new(()),
        }
    }

    fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }

    /// Verifies a bearer token and returns its claims.
    ///
    /// On an unknown key id the key set is refetched once — that is
    /// what makes rotation invisible to a running app — but no more
    /// often than [`crate::JWKS_MIN_REFETCH_SECS`].
    ///
    /// # Errors
    ///
    /// [`VerifyError`] describing the first check that failed. Callers
    /// should log it and answer `401` without saying which.
    pub async fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        let now = self.now();
        if !self.cached_is_fresh(now) {
            self.refresh(now, false).await;
        }
        match self.verify_cached(token, now) {
            Err(VerifyError::UnknownKey(kid)) => {
                // A key we have not seen: either the issuer rotated, or
                // someone is inventing key ids. Refetch at most once a
                // minute, then decide for good.
                if peek_kid(token).as_deref() == Some(kid.as_str()) {
                    self.refresh(now, true).await;
                }
                self.verify_cached(token, now)
            }
            other => other,
        }
    }

    fn cached_is_fresh(&self, now: i64) -> bool {
        self.cache
            .read()
            .expect("jwks cache uncontended")
            .is_fresh(now)
    }

    fn verify_cached(&self, token: &str, now: i64) -> Result<Claims, VerifyError> {
        let cache = self.cache.read().expect("jwks cache uncontended");
        verify_with(token, &cache.keys, &self.issuer, &self.client_id, now)
    }

    /// Fetches the key set. A failure leaves the previous keys in place:
    /// a momentarily unreachable auth service must not invalidate every
    /// session in a running app.
    ///
    /// One fetch at a time, and the freshness question is asked again
    /// *after* taking the flight lock rather than only before it. A caller
    /// that queued behind an in-flight refetch therefore finds the cache
    /// fresh and returns without a second request, and — the half that
    /// matters for rotation — a fetch that started earlier can no longer
    /// land after a newer one and put the retired key set back.
    ///
    /// A forced refresh still goes ahead even when the cache is fresh:
    /// that is the whole point of it, and the throttle below is what keeps
    /// it from becoming one request per verification.
    async fn refresh(&self, now: i64, forced: bool) {
        let _flight = self.flight.lock().await;
        // The guards are scoped: an `RwLock` guard must not be live across
        // the `await` below, because the future this sits in has to be
        // `Send` for axum's extractors.
        {
            let cache = self.cache.read().expect("jwks cache uncontended");
            if !forced && cache.is_fresh(now) {
                return;
            }
            if forced && !cache.may_force(now) {
                return;
            }
        }
        if forced {
            self.cache
                .write()
                .expect("jwks cache uncontended")
                .last_forced = Some(now);
        }
        match self.fetch(now).await {
            Ok(keys) => {
                let mut cache = self.cache.write().expect("jwks cache uncontended");
                cache.keys = keys;
                cache.fetched_at = Some(now);
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    jwks_uri = %self.jwks_uri,
                    "fetching the issuer's keys failed; keeping the previous set"
                );
            }
        }
    }

    async fn fetch(&self, _now: i64) -> Result<Vec<(String, VerifyingKey)>, String> {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(&self.jwks_uri)
            .header(http::header::ACCEPT, "application/json")
            .body(Bytes::new())
            .map_err(|err| err.to_string())?;
        let response = self
            .http
            .send(request)
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("jwks endpoint answered {}", response.status()));
        }
        let jwks: Jwks = serde_json::from_slice(response.body()).map_err(|err| err.to_string())?;
        Ok(jwks.keys.iter().filter_map(parse_key).collect())
    }
}

/// Turns one JWK into a verifying key, skipping anything unusable.
///
/// A key carrying `d` is a private key, which must never appear in a
/// public key set; it is skipped rather than used, so an issuer bug
/// cannot become a client vulnerability.
fn parse_key(jwk: &Jwk) -> Option<(String, VerifyingKey)> {
    if jwk.d.is_some() {
        tracing::error!(
            kid = jwk.kid.as_deref().unwrap_or("?"),
            "the issuer published a PRIVATE key in its JWKS; refusing to use it"
        );
        return None;
    }
    if jwk.kty != "EC" || jwk.crv.as_deref() != Some("P-256") {
        return None;
    }
    let kid = jwk.kid.clone()?;
    let x = Base64UrlUnpadded::decode_vec(jwk.x.as_deref()?).ok()?;
    let y = Base64UrlUnpadded::decode_vec(jwk.y.as_deref()?).ok()?;
    // Uncompressed SEC1: 0x04 || X || Y. Both coordinates are exactly
    // 32 bytes for P-256; anything else is a malformed key.
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let key = VerifyingKey::from_sec1_bytes(&sec1).ok()?;
    Some((kid, key))
}
