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

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use cratefield_core::Clock;

// The adapter's own credential, held for its TTL (see module docs) — not
// request state, which is what ADR 0007 bans. Named, so the allow sits on
// this one item instead of the whole file, as the workspace `clippy.toml`
// requires and `cratefield-adapter-sqlite` already does for its connection.
#[allow(clippy::disallowed_types)]
type Guarded<T> = std::sync::Mutex<T>;

/// A minted token and when it was minted.
struct Minted {
    token: String,
    minted_unix: i64,
}

/// Keyed mint-once-reuse with a [`Clock`]-driven TTL.
///
/// `K` is what the token varies by: `()` where an adapter has exactly one
/// (APNs), a push-service origin for VAPID, a service-account id for Google.
///
/// The map is **bounded** at [`Self::CAPACITY`] (#136/#137: no unbounded
/// resource on an isolate). A VAPID cache is keyed by push-service origin
/// and a UnifiedPush endpoint is an arbitrary host, so without a bound the
/// map grows for the isolate's lifetime and never sheds an expired entry.
pub struct CachedToken<K = ()> {
    ttl: Duration,
    /// The adapter's own credential, shared across sends for its TTL — not
    /// request state (see [`Guarded`]). A mutex and not an `RwLock`: the
    /// miss path mints under the lock, so writers must exclude each other
    /// anyway.
    #[allow(clippy::disallowed_types)]
    entries: Guarded<HashMap<K, Minted>>,
}

impl<K: Eq + Hash + Clone> CachedToken<K> {
    /// How many keys the cache holds at once.
    ///
    /// Sized for the realistic key space: one entry for an APNs adapter,
    /// one per push-service origin for VAPID (the browsers' four, plus the
    /// UnifiedPush hosts a venture's users actually chose), one per service
    /// account for Google. Past it, the **oldest-minted** entry is dropped —
    /// mint time is what an entry records, and the oldest is the one closest
    /// to needing a re-mint anyway. Eviction costs one extra mint, never
    /// correctness.
    pub const CAPACITY: usize = 64;

    /// A cache that re-mints a token once it is older than `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Guarded::new(HashMap::new()),
        }
    }

    /// How long a token is reused before it is re-minted.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// How many keys are cached right now, expired entries included until
    /// the next insert prunes them.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic inside a previous mint.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().expect("push-auth token cache").len()
    }

    /// Whether nothing is cached.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic inside a previous mint.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    /// **`mint` runs while the lock is held**, so a TTL miss mints exactly
    /// once however many threads race into it. Dropping the lock first would
    /// let two threads both mint and present two provider JWTs to Apple
    /// milliseconds apart — `TooManyProviderTokenUpdates`, the precise
    /// failure this cache exists to prevent. Signing takes microseconds and
    /// the losing threads want that same token anyway, so the contention is
    /// the point. `mint` must therefore not call back into this cache, and
    /// is a plain `FnOnce` (not a future) so it cannot await while holding
    /// the lock.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic inside a previous `mint`
    /// — which now runs under the lock, so a panicking `mint` poisons the
    /// cache for the isolate rather than only failing its own send.
    pub fn get_or_mint(
        &self,
        clock: &dyn Clock,
        key: &K,
        mint: impl FnOnce(i64) -> String,
    ) -> String {
        let now_unix = clock.now().unix_timestamp();
        let ttl = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        let mut entries = self.entries.lock().expect("push-auth token cache");
        if let Some(cached) = entries.get(key)
            && now_unix.saturating_sub(cached.minted_unix) < ttl
        {
            return cached.token.clone();
        }
        let token = mint(now_unix);
        Self::make_room(&mut entries, now_unix, ttl);
        entries.insert(
            key.clone(),
            Minted {
                token: token.clone(),
                minted_unix: now_unix,
            },
        );
        token
    }

    /// Keeps the map inside [`Self::CAPACITY`] before one more entry goes in:
    /// every entry past its TTL is dropped (it would be re-minted on its next
    /// use regardless), and if that is not enough the oldest-minted entries
    /// go until there is room.
    fn make_room(entries: &mut HashMap<K, Minted>, now_unix: i64, ttl: i64) {
        entries.retain(|_, minted| now_unix.saturating_sub(minted.minted_unix) < ttl);
        while entries.len() >= Self::CAPACITY {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, minted)| minted.minted_unix)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&oldest);
        }
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

    /// Two threads racing an empty cache must mint **once**: Apple counts a
    /// second provider JWT within ~20 minutes as
    /// `TooManyProviderTokenUpdates` and rejects it, which is the whole
    /// reason this cache exists.
    #[test]
    fn a_race_on_a_cold_cache_mints_exactly_once() {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;

        const THREADS: usize = 8;

        let clock = StepClock::at(1_000);
        let mints = AtomicUsize::new(0);
        let cache: CachedToken<()> = CachedToken::new(Duration::from_mins(50));
        let gate = Barrier::new(THREADS);

        let tokens: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        gate.wait();
                        cache.get_or_mint(&clock, &(), |now| {
                            let n = mints.fetch_add(1, Ordering::SeqCst);
                            // Widen the window a lock-free miss would race in,
                            // so the unguarded version fails every run rather
                            // than one in a hundred.
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            format!("token-{n}-at-{now}")
                        })
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("thread"))
                .collect()
        });

        assert_eq!(
            mints.load(Ordering::SeqCst),
            1,
            "a cold-cache race must present one provider token, not {THREADS}"
        );
        assert!(
            tokens.windows(2).all(|pair| pair[0] == pair[1]),
            "every racing caller gets the same token: {tokens:?}"
        );
    }

    #[test]
    fn expired_entries_are_pruned_and_the_map_is_bounded() {
        let clock = StepClock::at(0);
        let minter = Minter::default();
        let cache: CachedToken<String> = CachedToken::new(Duration::from_mins(50));

        // Expired entries do not accumulate: a VAPID cache is keyed by
        // push-service origin, and a UnifiedPush endpoint is an arbitrary
        // host, so nothing else would ever remove them.
        for n in 0..10 {
            cache.get_or_mint(&clock, &format!("https://push-{n}.example"), minter.mint());
        }
        assert_eq!(cache.len(), 10);
        clock.advance(4_000); // past the TTL for all ten
        cache.get_or_mint(&clock, &"https://fresh.example".to_owned(), minter.mint());
        assert_eq!(cache.len(), 1, "the ten expired entries were pruned");

        // And the live set is bounded, however many distinct origins arrive.
        for n in 0..(CachedToken::<String>::CAPACITY * 2) {
            cache.get_or_mint(&clock, &format!("https://live-{n}.example"), minter.mint());
            assert!(
                cache.len() <= CachedToken::<String>::CAPACITY,
                "cache grew past its bound at {n}: {}",
                cache.len()
            );
        }
        assert_eq!(cache.len(), CachedToken::<String>::CAPACITY);
        assert!(!cache.is_empty());
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
