//! Provider discovery, cached, and the adapter that carries
//! `openidconnect` over the harness `HttpClient` port (ADR 0200 Q3).
//!
//! The adapter is the spike's, with one difference: its future is `Send`.
//! The spike needed a bridge because it implemented the port over
//! `worker::Fetch`, whose handles are `!Send`; a module never sees that, it
//! sees a port that is `Send + Sync` already. The bridge is the runtime
//! adapter's problem, not this module's.
//!
//! Discovery is cached because it is two network calls (the configuration
//! document and the JWKS) that would otherwise run on every login. The cache
//! holds signing keys, so it has a lifetime and a forced-refresh path: a
//! provider that rotates keys must not lock everyone out until the isolate
//! recycles.

use std::future::Future;
use std::pin::Pin;
use std::sync::RwLock;

use bytes::Bytes;
use cratefield_core::{Clock, HttpClient};
use openidconnect::core::CoreProviderMetadata;
use openidconnect::{IssuerUrl, JsonWebKey as _, JsonWebKeySet};

use crate::provider::Provider;

/// How long a discovery document is trusted. An hour is far shorter than
/// any provider's key rotation, and far longer than a login.
const CACHE_TTL_SECS: i64 = 3_600;

/// The shortest gap between two forced refreshes. Without it, a burst of
/// failures against a genuinely broken provider becomes a burst of
/// discovery requests.
const FORCE_COOLDOWN_SECS: i64 = 30;

#[derive(Debug, thiserror::Error)]
pub(crate) enum DiscoveryError {
    #[error("{provider} discovery failed: {detail}")]
    Failed {
        /// The issuer, not the slug: an SSO connection's provider is one
        /// row's issuer (issue #627), and its slug is the same for all of
        /// them.
        provider: String,
        detail: String,
    },
}

/// `openidconnect`'s HTTP client, implemented over the port.
///
/// It owns an `Arc` rather than borrowing the port. A borrowed one makes
/// the `AsyncHttpClient<'c>` impl carry two lifetimes, and the compiler then
/// cannot prove the future is `Send` for *every* `'c`, which is what
/// `discover_async` and `request_async` ask for. An `Arc` is one clone per
/// request and the whole class of error goes away.
pub(crate) struct PortHttpClient {
    port: std::sync::Arc<dyn HttpClient>,
}

impl PortHttpClient {
    pub(crate) fn new(port: std::sync::Arc<dyn HttpClient>) -> Self {
        Self { port }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PortHttpError {
    #[error("http port: {0}")]
    Port(#[from] cratefield_core::HttpError),
}

impl<'c> openidconnect::AsyncHttpClient<'c> for PortHttpClient {
    type Error = PortHttpError;
    type Future =
        Pin<Box<dyn Future<Output = Result<openidconnect::HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: openidconnect::HttpRequest) -> Self::Future {
        let port = std::sync::Arc::clone(&self.port);
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let response = port
                .send(http::Request::from_parts(parts, Bytes::from(body)))
                .await?;
            let (parts, body) = response.into_parts();
            Ok(http::Response::from_parts(parts, body.to_vec()))
        })
    }
}

#[derive(Clone)]
struct Cached {
    metadata: CoreProviderMetadata,
    fetched_at: i64,
    /// When a *forced* refresh last ran. Throttling on `fetched_at` instead
    /// would defeat the force entirely: the entry we are trying to get past
    /// is by definition a recent one.
    forced_at: Option<i64>,
}

/// One cache per module instance, keyed by issuer. `RwLock` rather than
/// `Mutex` because reads dominate and the clippy configuration disallows
/// `Mutex` (ADR 0007); this is not request state, it is a per-isolate memo
/// of a public document.
///
/// The key is the issuer rather than the provider slug because an SSO
/// connection's issuer is a row's value, not a constant (issue #627) —
/// and because two connections pointed at the same `IdP` share one document
/// and one JWKS, which is what discovery is.
#[derive(Default)]
pub(crate) struct Cache {
    entries: RwLock<Vec<(String, Cached)>>,
    /// When discovery last failed, per issuer. While an issuer is down,
    /// every request would otherwise re-run two upstream fetches.
    failures: RwLock<Vec<(String, i64)>>,
}

impl Cache {
    /// The cached document, when it is still usable for this kind of read.
    /// An ordinary read wants a fresh entry; a forced one wants only to know
    /// whether another forced refresh happened moments ago.
    fn read(&self, key: &str, now: i64, force: bool) -> Option<CoreProviderMetadata> {
        let entries = self.entries.read().ok()?;
        let (_, cached) = entries.iter().find(|(entry, _)| entry == key)?;
        let usable = if force {
            cached
                .forced_at
                .is_some_and(|at| now - at < FORCE_COOLDOWN_SECS)
        } else {
            now - cached.fetched_at < CACHE_TTL_SECS
        };
        usable.then(|| cached.metadata.clone())
    }

    fn write(&self, key: String, metadata: &CoreProviderMetadata, now: i64, force: bool) {
        let Ok(mut entries) = self.entries.write() else {
            return;
        };
        let forced_at = force.then_some(now);
        if let Some(slot) = entries.iter_mut().find(|(entry, _)| *entry == key) {
            slot.1.metadata = metadata.clone();
            slot.1.fetched_at = now;
            if forced_at.is_some() {
                slot.1.forced_at = forced_at;
            }
        } else {
            entries.push((
                key,
                Cached {
                    metadata: metadata.clone(),
                    fetched_at: now,
                    forced_at,
                },
            ));
        }
    }

    /// The provider's metadata, from cache when it is fresh.
    ///
    /// `force` bypasses a fresh entry, for the one case that needs it: an ID
    /// token signed by a key the cached JWKS does not hold. It is throttled,
    /// so a provider that is simply broken cannot turn every login into a
    /// discovery request.
    pub(crate) async fn metadata(
        &self,
        provider: &Provider,
        http: std::sync::Arc<dyn HttpClient>,
        clock: &dyn Clock,
        force: bool,
    ) -> Result<CoreProviderMetadata, DiscoveryError> {
        let now = clock.now().unix_timestamp();
        // The issuer is both the cache key and the discovery document's
        // own claim about itself: `discover` refuses a document whose
        // `issuer` is not the one asked for, which is what pins an SSO
        // connection to the IdP it was configured with.
        let key = provider.issuer.to_string();
        if let Some(metadata) = self.read(&key, now, force) {
            return Ok(metadata);
        }
        if self.failed_recently(&key, now) {
            return Err(DiscoveryError::Failed {
                provider: key,
                detail: "discovery failed moments ago; not retrying yet".to_owned(),
            });
        }

        let issuer = IssuerUrl::new(key.clone()).map_err(|err| DiscoveryError::Failed {
            provider: key.clone(),
            detail: format!("issuer url: {err}"),
        })?;
        let client = PortHttpClient::new(http);
        let metadata = CoreProviderMetadata::discover_async(issuer, &client)
            .await
            .map_err(|err| {
                self.remember_failure(key.clone(), now);
                DiscoveryError::Failed {
                    provider: key.clone(),
                    detail: err.to_string(),
                }
            })?;

        self.write(key, &metadata, now, force);
        Ok(metadata)
    }

    fn failed_recently(&self, key: &str, now: i64) -> bool {
        let Ok(failures) = self.failures.read() else {
            return false;
        };
        failures
            .iter()
            .find(|(entry, _)| entry == key)
            .is_some_and(|(_, at)| now - at < FORCE_COOLDOWN_SECS)
    }

    fn remember_failure(&self, key: String, now: i64) {
        let Ok(mut failures) = self.failures.write() else {
            return;
        };
        if let Some(slot) = failures.iter_mut().find(|(entry, _)| *entry == key) {
            slot.1 = now;
        } else {
            failures.push((key, now));
        }
    }

    /// Whether the cached JWKS holds a given key id. Used to decide whether
    /// a verification failure is worth one forced refresh, rather than
    /// refreshing on every failure.
    pub(crate) fn knows_key(&self, key: &str, key_id: &str) -> bool {
        let Ok(entries) = self.entries.read() else {
            return false;
        };
        entries
            .iter()
            .find(|(entry, _)| entry == key)
            .is_some_and(|(_, cached)| jwks_has_key(cached.metadata.jwks(), key_id))
    }
}

fn jwks_has_key(jwks: &JsonWebKeySet<openidconnect::core::CoreJsonWebKey>, key_id: &str) -> bool {
    jwks.keys().iter().any(|key| {
        key.key_id()
            .is_some_and(|candidate| candidate.as_str() == key_id)
    })
}

/// The `kid` of a JWT, read without verifying anything. Only used to ask
/// the cache whether it has heard of that key.
pub(crate) fn key_id_of(token: &str) -> Option<String> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let header = token.split('.').next()?;
    let decoded = Base64UrlUnpadded::decode_vec(header).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value.get("kid")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_id_is_read_from_an_unverified_header() {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        let header = Base64UrlUnpadded::encode_string(br#"{"alg":"RS256","kid":"abc123"}"#);
        let token = format!("{header}.body.signature");
        assert_eq!(key_id_of(&token).as_deref(), Some("abc123"));
    }

    #[test]
    fn a_malformed_token_has_no_key_id_and_does_not_panic() {
        for bad in ["", ".", "not-base64.x.y", "e30.x.y"] {
            assert_eq!(key_id_of(bad), None, "{bad}");
        }
    }
}
