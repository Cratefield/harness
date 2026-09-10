//! Mint-once-reuse for provider tokens.
//!
//! Generalises the cache `cratefield-adapter-apns` grew for its provider
//! JWT: Apple rejects regenerating one more than once per ~20 minutes and
//! accepts it for up to 60, so it is minted once and reused. VAPID needs the
//! same thing **per push-service origin** (a token's `aud` is the origin, so
//! Chrome's and Firefox's are different tokens), and Google's exchanged
//! bearer token needs it per service account. Hence the key.
//!
//! Two ways in, because not every token can be minted locally.
//! [`CachedToken::get_or_mint`] mints under the lock, which is what makes a
//! cold-cache race present Apple exactly one provider JWT. Google's bearer
//! token is *exchanged* over HTTP instead, and no lock may be held across an
//! `await`, so that path reads with [`CachedToken::cached`] and writes with
//! [`CachedToken::store`] — the same map, the same invalidation, one extra
//! exchange in a race.
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

/// One cached token: the value, when it was minted or stored, and how long
/// it may be reused from then.
struct Entry {
    token: String,
    minted_unix: i64,
    /// Seconds this entry may be reused for. The cache's own TTL for a
    /// [`CachedToken::get_or_mint`]; the provider's stated lifetime, capped
    /// by that TTL, for a [`CachedToken::store`].
    ttl_secs: i64,
}

impl Entry {
    /// Whether the entry is still inside its own lifetime at `now_unix`.
    fn fresh_at(&self, now_unix: i64) -> bool {
        now_unix.saturating_sub(self.minted_unix) < self.ttl_secs
    }
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
    entries: Guarded<HashMap<K, Entry>>,
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
        let ttl = self.ttl_secs();
        let mut entries = self.entries.lock().expect("push-auth token cache");
        if let Some(cached) = entries.get(key)
            && cached.fresh_at(now_unix)
        {
            return cached.token.clone();
        }
        let token = mint(now_unix);
        Self::make_room(&mut entries, now_unix);
        entries.insert(
            key.clone(),
            Entry {
                token: token.clone(),
                minted_unix: now_unix,
                ttl_secs: ttl,
            },
        );
        token
    }

    /// The cached token for `key`, or `None` when there is none or it has
    /// aged past its lifetime. **Nothing is minted.**
    ///
    /// This is the read half of [`Self::get_or_mint`], for a token that
    /// cannot be minted synchronously: Google's bearer token is *exchanged*
    /// over HTTP, and `mint` is a plain `FnOnce` precisely so it can never
    /// await while holding the lock. Pair it with [`Self::store`]:
    ///
    /// ```rust,ignore
    /// if let Some(token) = cache.cached(clock, &key) { return Ok(token); }
    /// let (token, lifetime) = exchange().await?;
    /// cache.store(clock, &key, &token, lifetime);
    /// ```
    ///
    /// The lock is therefore *not* held across the exchange, so two sends
    /// racing a cold cache can each exchange one token. That costs a round
    /// trip, never correctness: Google issues both and the second `store`
    /// simply wins. It is the trade a synchronous `mint` does not have to
    /// make — and the reason `get_or_mint` remains the right call wherever
    /// minting is local.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic inside a previous mint.
    #[must_use]
    pub fn cached(&self, clock: &dyn Clock, key: &K) -> Option<String> {
        let now_unix = clock.now().unix_timestamp();
        let entries = self.entries.lock().expect("push-auth token cache");
        entries
            .get(key)
            .filter(|cached| cached.fresh_at(now_unix))
            .map(|cached| cached.token.clone())
    }

    /// Records `token` for `key`, minted now and reusable for `lifetime` —
    /// or for the cache's own TTL where that is shorter, so the TTL stays a
    /// ceiling however long a provider claims its token lives.
    ///
    /// A zero `lifetime` stores nothing that will ever be read back: the
    /// entry is stale the instant it lands, which is the honest answer when
    /// a provider hands over a token that expires inside the safety margin.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic inside a previous mint.
    pub fn store(&self, clock: &dyn Clock, key: &K, token: impl Into<String>, lifetime: Duration) {
        let now_unix = clock.now().unix_timestamp();
        let ttl = self
            .ttl_secs()
            .min(i64::try_from(lifetime.as_secs()).unwrap_or(i64::MAX));
        let mut entries = self.entries.lock().expect("push-auth token cache");
        Self::make_room(&mut entries, now_unix);
        entries.insert(
            key.clone(),
            Entry {
                token: token.into(),
                minted_unix: now_unix,
                ttl_secs: ttl,
            },
        );
    }

    /// The cache's own TTL in whole seconds.
    fn ttl_secs(&self) -> i64 {
        i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX)
    }

    /// Keeps the map inside [`Self::CAPACITY`] before one more entry goes in:
    /// every entry past its TTL is dropped (it would be re-minted on its next
    /// use regardless), and if that is not enough the oldest-minted entries
    /// go until there is room.
    fn make_room(entries: &mut HashMap<K, Entry>, now_unix: i64) {
        entries.retain(|_, minted| minted.fresh_at(now_unix));
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

    /// The async half: a token that is *exchanged* over HTTP cannot be
    /// minted under the lock, so it is read with `cached` and written with
    /// `store`.
    #[test]
    fn cached_reads_without_minting_and_store_writes() {
        let clock = StepClock::at(1_000);
        let cache: CachedToken<()> = CachedToken::new(Duration::from_mins(55));

        assert_eq!(cache.cached(&clock, &()), None, "nothing cached yet");
        assert!(cache.is_empty(), "a miss must not insert anything");

        cache.store(&clock, &(), "ya29.bearer", Duration::from_mins(55));
        assert_eq!(cache.cached(&clock, &()), Some("ya29.bearer".to_owned()));

        clock.advance(3_299);
        assert_eq!(cache.cached(&clock, &()), Some("ya29.bearer".to_owned()));
        clock.advance(1);
        assert_eq!(cache.cached(&clock, &()), None, "past its lifetime");
    }

    #[test]
    fn a_stored_lifetime_is_capped_by_the_caches_own_ttl() {
        let clock = StepClock::at(0);
        let cache: CachedToken<()> = CachedToken::new(Duration::from_secs(600));

        // A provider claiming an hour does not get an hour: the TTL is the
        // ceiling.
        cache.store(&clock, &(), "long", Duration::from_secs(3_600));
        clock.advance(600);
        assert_eq!(cache.cached(&clock, &()), None, "capped at the cache TTL");

        // ...and a shorter provider lifetime wins over the TTL.
        cache.store(&clock, &(), "short", Duration::from_secs(30));
        clock.advance(30);
        assert_eq!(cache.cached(&clock, &()), None, "the provider said 30s");

        // A zero lifetime is never read back.
        cache.store(&clock, &(), "already-stale", Duration::ZERO);
        assert_eq!(cache.cached(&clock, &()), None);
    }

    #[test]
    fn invalidate_drops_a_stored_token_too() {
        let clock = StepClock::at(0);
        let cache: CachedToken<()> = CachedToken::new(Duration::from_mins(50));
        cache.store(&clock, &(), "ya29.bearer", Duration::from_mins(55));
        cache.invalidate(&());
        assert_eq!(
            cache.cached(&clock, &()),
            None,
            "a 401 drops the cache so the next send re-exchanges"
        );
    }

    #[test]
    fn stored_entries_are_pruned_and_bounded_like_minted_ones() {
        let clock = StepClock::at(0);
        let cache: CachedToken<String> = CachedToken::new(Duration::from_mins(50));
        for n in 0..(CachedToken::<String>::CAPACITY * 2) {
            cache.store(
                &clock,
                &format!("account-{n}"),
                format!("token-{n}"),
                Duration::from_mins(55),
            );
            assert!(
                cache.len() <= CachedToken::<String>::CAPACITY,
                "cache grew past its bound at {n}: {}",
                cache.len()
            );
        }
    }

    /// The two halves share one map: a token stored by the async path is
    /// returned by `get_or_mint` without re-minting, and vice versa.
    #[test]
    fn the_two_halves_share_one_entry() {
        let clock = StepClock::at(0);
        let minter = Minter::default();
        let cache: CachedToken<()> = CachedToken::new(Duration::from_mins(50));

        cache.store(&clock, &(), "exchanged", Duration::from_mins(55));
        assert_eq!(cache.get_or_mint(&clock, &(), minter.mint()), "exchanged");
        assert_eq!(minter.count(), 0, "nothing was minted over a live entry");

        cache.invalidate(&());
        let signed = cache.get_or_mint(&clock, &(), minter.mint());
        assert_eq!(cache.cached(&clock, &()), Some(signed));
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
