//! Mint-once-reuse for provider tokens.
//!
//! Generalises the cache `cratefield-adapter-apns` grew for its provider
//! JWT: Apple rejects regenerating one more than once per ~20 minutes and
//! accepts it for up to 60, so it is minted once and reused. VAPID needs the
//! same thing **per push-service origin** (a token's `aud` is the origin, so
//! Chrome's and Firefox's are different tokens), and Google's exchanged
//! bearer token needs it per service account. Hence the key.
//!
//! The cache holds a `Mutex` and is not request state: it is the adapter's
//! own credential, shared across sends for its TTL (ADR 0007 allows a
//! scoped, justified `Mutex`).
#![allow(clippy::disallowed_types)]

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Duration;

use cratefield_core::Clock;

/// A minted token and when it was minted.
struct Minted {
    token: String,
    minted_unix: i64,
}

/// Keyed mint-once-reuse with a [`Clock`]-driven TTL.
///
/// `K` is what the token varies by: `()` where an adapter has exactly one
/// (APNs), a push-service origin for VAPID, a service-account id for Google.
pub struct CachedToken<K = ()> {
    ttl: Duration,
    entries: Mutex<HashMap<K, Minted>>,
}

impl<K: Eq + Hash + Clone> CachedToken<K> {
    /// A cache that re-mints a token once it is older than `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// How long a token is reused before it is re-minted.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The token for `key`, minting one if there is none or the cached one
    /// has aged past the TTL. `mint` is handed the current UNIX time, which
    /// is the same instant the entry is stamped with, so a token's `iat` can
    /// never disagree with the cache's idea of its age.
    ///
    /// The clock is read once. A clock that goes backwards makes an entry
    /// look fresh rather than making its age negative, which is the safe
    /// direction: the worst case is one provider rejection, and every caller
    /// of this already handles that with [`Self::invalidate`].
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic inside a previous `mint`.
    pub fn get_or_mint(
        &self,
        clock: &dyn Clock,
        key: &K,
        mint: impl FnOnce(i64) -> String,
    ) -> String {
        let now_unix = clock.now().unix_timestamp();
        let ttl = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        {
            let entries = self.entries.lock().expect("push-auth token cache");
            if let Some(cached) = entries.get(key)
                && now_unix.saturating_sub(cached.minted_unix) < ttl
            {
                return cached.token.clone();
            }
        }
        let token = mint(now_unix);
        self.entries.lock().expect("push-auth token cache").insert(
            key.clone(),
            Minted {
                token: token.clone(),
                minted_unix: now_unix,
            },
        );
        token
    }

    /// Drops the token for `key`, so the next [`Self::get_or_mint`] re-mints
    /// — what an adapter does when the provider says the token expired.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic inside a previous mint.
    pub fn invalidate(&self, key: &K) {
        self.entries
            .lock()
            .expect("push-auth token cache")
            .remove(key);
    }

    /// Drops every cached token.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic inside a previous mint.
    pub fn clear(&self) {
        self.entries.lock().expect("push-auth token cache").clear();
    }
}

impl<K: Eq + Hash + Clone> std::fmt::Debug for CachedToken<K> {
    /// Never prints a token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self
            .entries
            .lock()
            .map_or(0, |entries: std::sync::MutexGuard<'_, _>| entries.len());
        f.debug_struct("CachedToken")
            .field("ttl", &self.ttl)
            .field("entries", &entries)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

    /// A fake clock the test advances by hand.
    struct StepClock(AtomicI64);
    impl StepClock {
        fn at(secs: i64) -> Self {
            Self(AtomicI64::new(secs))
        }
        fn advance(&self, secs: i64) {
            self.0.fetch_add(secs, Ordering::Relaxed);
        }
    }
    #[async_trait::async_trait]
    impl Clock for StepClock {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::Relaxed))
                .expect("in range")
        }
    }

    /// Mints `token-<n>` and counts how often it was called.
    #[derive(Default)]
    struct Minter(AtomicUsize);
    impl Minter {
        fn mint(&self) -> impl FnOnce(i64) -> String + '_ {
            move |now| {
                let n = self.0.fetch_add(1, Ordering::Relaxed);
                format!("token-{n}-at-{now}")
            }
        }
        fn count(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn reuses_within_the_ttl_and_remints_after() {
        let clock = StepClock::at(1_000);
        let minter = Minter::default();
        let cache: CachedToken<()> = CachedToken::new(Duration::from_mins(50));

        let first = cache.get_or_mint(&clock, &(), minter.mint());
        assert_eq!(first, "token-0-at-1000");

        clock.advance(2_400);
        assert_eq!(cache.get_or_mint(&clock, &(), minter.mint()), first);
        assert_eq!(minter.count(), 1, "reused within the TTL");

        clock.advance(1_200);
        let second = cache.get_or_mint(&clock, &(), minter.mint());
        assert_ne!(second, first, "re-minted past the TTL");
        assert_eq!(minter.count(), 2);
    }

    #[test]
    fn invalidate_forces_a_remint() {
        let clock = StepClock::at(0);
        let minter = Minter::default();
        let cache: CachedToken<()> = CachedToken::new(Duration::from_mins(50));

        let first = cache.get_or_mint(&clock, &(), minter.mint());
        cache.invalidate(&());
        // Same instant, so only the mint counter can tell the two apart.
        let second = cache.get_or_mint(&clock, &(), minter.mint());
        assert_ne!(second, first);
        assert_eq!(minter.count(), 2);
    }

    #[test]
    fn a_key_gets_its_own_token() {
        let clock = StepClock::at(0);
        let minter = Minter::default();
        let cache: CachedToken<String> = CachedToken::new(Duration::from_mins(50));

        let chrome = "https://fcm.googleapis.com".to_owned();
        let firefox = "https://updates.push.services.mozilla.com".to_owned();
        let a = cache.get_or_mint(&clock, &chrome, minter.mint());
        let b = cache.get_or_mint(&clock, &firefox, minter.mint());
        assert_ne!(a, b, "VAPID `aud` differs per push service");
        assert_eq!(minter.count(), 2);

        // Each is cached under its own key...
        assert_eq!(cache.get_or_mint(&clock, &chrome, minter.mint()), a);
        assert_eq!(cache.get_or_mint(&clock, &firefox, minter.mint()), b);
        assert_eq!(minter.count(), 2);

        // ...and invalidating one leaves the other alone.
        cache.invalidate(&chrome);
        assert_ne!(cache.get_or_mint(&clock, &chrome, minter.mint()), a);
        assert_eq!(cache.get_or_mint(&clock, &firefox, minter.mint()), b);
        assert_eq!(minter.count(), 3);

        cache.clear();
        assert_ne!(cache.get_or_mint(&clock, &firefox, minter.mint()), b);
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_remint_forever() {
        let clock = StepClock::at(10_000);
        let minter = Minter::default();
        let cache: CachedToken<()> = CachedToken::new(Duration::from_mins(50));

        let first = cache.get_or_mint(&clock, &(), minter.mint());
        clock.advance(-9_000);
        assert_eq!(cache.get_or_mint(&clock, &(), minter.mint()), first);
        assert_eq!(minter.count(), 1);
    }
}
