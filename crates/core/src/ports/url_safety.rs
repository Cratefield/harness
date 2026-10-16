//! The `UrlSafety` port (issue #857): whether a URL is safe to fetch,
//! asked by capability, never by vendor (ADR 0002, ports and adapters) —
//! the way [`TextModel`](crate::TextModel) is for completions. A module
//! holds `Arc<dyn UrlSafety>` and never learns which provider answered.
//!
//! # The privacy contract
//!
//! **The checked URL is a secret.** It names who is about to fetch what:
//! a password reset, an unsubscribe, a reporter's source. Every
//! implementation MUST never log the checked URL and MUST never place it
//! in an error string. [`UrlSafetyError`] carries no URL in any variant,
//! and the one variant carrying provider text
//! ([`UrlSafetyError::Provider`]) is scrubbed through
//! [`crate::logging::scrub_text`] in `Display`, the way
//! [`MailError`](crate::MailError)'s and [`PushError`](crate::PushError)'s
//! are (issue #235). `Debug` still shows the raw string for tests; the
//! logging formatters scrub `{:?}` output too.
//!
//! **Limits are checked locally, before any network call.** Every
//! implementation MUST run [`check_url`] / [`check_batch`] on the input
//! first, so an over-long URL or an over-size batch is refused with
//! [`UrlSafetyError::LimitExceeded`] without being paid for, and every
//! adapter refuses identically. The defaults
//! ([`UrlSafetyLimits::default()`]) are the 2 048-byte URL every browser
//! and provider accepts in a request line and Safe Browsing v4's
//! 500-URL lookup batch.
//!
//! [`CachedUrlSafety`] decorates any implementation with a bounded,
//! [`Clock`]-driven TTL cache that honours the provider's advised
//! retention. Its lock is never held across an `await`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::Clock;

/// The longest URL one check accepts: 2 048 bytes, the length every
/// browser and every URL-safety provider accepts in a request line.
pub const DEFAULT_MAX_URL_LEN: usize = 2048;

/// The most URLs one batch accepts: Safe Browsing v4's documented
/// `threatMatches` lookup ceiling.
pub const DEFAULT_MAX_BATCH: usize = 500;

/// How many URLs [`CachedUrlSafety`] holds at once.
pub const DEFAULT_CACHE_CAPACITY: usize = 4096;

/// How long [`CachedUrlSafety`] serves a verdict whose provider said
/// nothing about retention ([`UrlVerdict::cache_ttl`] is `None`):
/// five minutes.
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(300);

/// What a provider says a URL does. The names map 1:1 onto Google Web
/// Risk v1's and Safe Browsing v4's `threatType` values, so an adapter
/// translates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ThreatType {
    /// A drive-by download or an exploit page.
    Malware,
    /// Deceptive: phishing and the rest of the social-engineering family.
    SocialEngineering,
    /// Software the user did not meaningfully agree to (adware and the
    /// like).
    UnwantedSoftware,
    /// An app the provider rates harmful.
    PotentiallyHarmfulApplication,
}

impl ThreatType {
    /// The provider wire name, shared by Google Web Risk v1 and Safe
    /// Browsing v4.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malware => "MALWARE",
            Self::SocialEngineering => "SOCIAL_ENGINEERING",
            Self::UnwantedSoftware => "UNWANTED_SOFTWARE",
            Self::PotentiallyHarmfulApplication => "POTENTIALLY_HARMFUL_APPLICATION",
        }
    }
}

/// Which provider produced a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UrlSafetySource {
    /// Google Web Risk.
    GoogleWebRisk,
    /// Google Safe Browsing.
    GoogleSafeBrowsing,
    /// A decorator in front of the real provider (a cache rebuilding a
    /// verdict, say); it names itself, never the provider behind it.
    Cache,
}

impl UrlSafetySource {
    /// The short name used in logs and health reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoogleWebRisk => "google-webrisk",
            Self::GoogleSafeBrowsing => "google-safebrowsing",
            Self::Cache => "cache",
        }
    }
}

/// One URL's safety verdict. An empty `threats` means known-clean —
/// there is no separate "safe" flag to disagree with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlVerdict {
    /// The URL this verdict is for, verbatim as it was asked.
    pub url: String,
    /// Every threat the provider named; empty for a known-clean URL.
    pub threats: Vec<ThreatType>,
    /// Which provider produced the verdict.
    pub source: UrlSafetySource,
    /// When the provider answered.
    pub checked_at: OffsetDateTime,
    /// The provider-advised retention for this verdict; `None` when it
    /// said nothing (a cache then applies its own negative TTL).
    pub cache_ttl: Option<Duration>,
    /// Whether a cache served this verdict instead of the provider.
    pub cached: bool,
}

impl UrlVerdict {
    /// Whether the provider named any threat.
    #[must_use]
    pub fn is_threat(&self) -> bool {
        !self.threats.is_empty()
    }
}

/// Which [`UrlSafetyLimits`] ceiling an ask crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UrlSafetyLimit {
    /// The URL's byte length over [`UrlSafetyLimits::max_url_len`].
    UrlLength,
    /// The batch's size over [`UrlSafetyLimits::max_batch`].
    BatchSize,
}

impl UrlSafetyLimit {
    /// The name used in errors and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UrlLength => "url length",
            Self::BatchSize => "batch size",
        }
    }
}

/// The local ceilings a [`UrlSafety`] adapter enforces before any network
/// call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlSafetyLimits {
    /// The longest URL accepted, in bytes.
    pub max_url_len: usize,
    /// The most URLs accepted in one [`UrlSafety::check_many`] call.
    pub max_batch: usize,
}

impl Default for UrlSafetyLimits {
    fn default() -> Self {
        Self {
            max_url_len: DEFAULT_MAX_URL_LEN,
            max_batch: DEFAULT_MAX_BATCH,
        }
    }
}

/// URL-safety failures, mapped by the adapter from provider responses.
///
/// **No variant carries the checked URL.** It names the caller's next
/// step, and an error string is one `format!` away from a log line. The
/// one variant carrying provider text is sanitized in `Display`, the way
/// [`MailError`](crate::MailError)'s and [`PushError`](crate::PushError)'s
/// are (issue #235): `Display` runs it through
/// [`crate::logging::scrub_text`], so every tracing field, problem detail
/// and report line that renders the error gets the sanitized text.
/// `Debug` still shows the raw string for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UrlSafetyError {
    /// The input does not parse as a URL, or its scheme is not `http` or
    /// `https`: nothing was sent anywhere. The offending text is
    /// deliberately not carried.
    InvalidUrl,
    /// A local ceiling was crossed and the provider was never called.
    LimitExceeded {
        limit: UrlSafetyLimit,
        actual: usize,
        max: usize,
    },
    /// The provider refused the request (a `4xx`); not retryable without
    /// a change. The status only — never the URL that drew it.
    Rejected { status: u16 },
    /// Retryable (a `5xx`, a `429`, a transport error); wait out
    /// `retry_after` when the provider named one.
    Transient { retry_after: Option<Duration> },
    /// The provider failed on its side, in its own (scrubbed) words.
    Provider(String),
}

impl std::fmt::Display for UrlSafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::InvalidUrl => f.write_str("not an http(s) URL; nothing was checked"),
            Self::LimitExceeded { limit, actual, max } => {
                write!(f, "over the {} ceiling: {actual} > {max}", limit.name())
            }
            Self::Rejected { status } => {
                write!(
                    f,
                    "url safety provider rejected the request: status {status}"
                )
            }
            Self::Transient { retry_after } => {
                write!(
                    f,
                    "url safety call failed, retryable: retry after {retry_after:?}"
                )
            }
            Self::Provider(message) => write!(f, "url safety provider failed: {}", scrub(message)),
        }
    }
}

impl std::error::Error for UrlSafetyError {}

impl UrlSafetyError {
    /// The provider-named back-off, where there was one.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Transient { retry_after } => *retry_after,
            _ => None,
        }
    }
}

/// Refuses a URL no provider should ever see, **before** any network
/// call: one over [`UrlSafetyLimits::max_url_len`] bytes is
/// [`UrlSafetyError::LimitExceeded`], and a string that does not parse as
/// a URL or whose scheme is not `http` or `https` is
/// [`UrlSafetyError::InvalidUrl`].
///
/// # Errors
/// The refusals named above; the length check runs first.
pub fn check_url(url: &str, limits: &UrlSafetyLimits) -> Result<(), UrlSafetyError> {
    if url.len() > limits.max_url_len {
        return Err(UrlSafetyError::LimitExceeded {
            limit: UrlSafetyLimit::UrlLength,
            actual: url.len(),
            max: limits.max_url_len,
        });
    }
    let parsed = url::Url::parse(url).map_err(|_| UrlSafetyError::InvalidUrl)?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(UrlSafetyError::InvalidUrl);
    }
    Ok(())
}

/// Refuses a batch the port's ceilings reject, **before** any network
/// call: more than [`UrlSafetyLimits::max_batch`] URLs is
/// [`UrlSafetyError::LimitExceeded`], and any one invalid URL is
/// [`UrlSafetyError::InvalidUrl`]. An empty batch is fine — there is
/// nothing in it to refuse.
///
/// # Errors
/// The refusals named above; the batch size first, then the URLs in
/// order.
pub fn check_batch(urls: &[String], limits: &UrlSafetyLimits) -> Result<(), UrlSafetyError> {
    if urls.len() > limits.max_batch {
        return Err(UrlSafetyError::LimitExceeded {
            limit: UrlSafetyLimit::BatchSize,
            actual: urls.len(),
            max: limits.max_batch,
        });
    }
    for url in urls {
        check_url(url, limits)?;
    }
    Ok(())
}

/// Asks whether URLs are safe to fetch, by capability and never by
/// vendor. Every adapter MUST run [`check_url`] / [`check_batch`] at the
/// top of `check` / `check_many`, before any network call, so a refusal
/// costs nothing and every adapter refuses identically. The privacy
/// contract in the [module docs](self) is binding: never log the checked
/// URL, never carry it in an error string.
#[async_trait]
pub trait UrlSafety: Send + Sync {
    /// Checks one URL. The returned verdict's `url` equals the input,
    /// verbatim.
    ///
    /// # Errors
    /// [`UrlSafetyError::InvalidUrl`] for a URL that does not parse or is
    /// not http(s); [`UrlSafetyError::LimitExceeded`] for a local
    /// ceiling; the refusal and failure variants otherwise.
    async fn check(&self, url: &str) -> Result<UrlVerdict, UrlSafetyError>;

    /// Checks many URLs; the results are in input order, one verdict per
    /// input. The default runs [`check_batch`] locally, then
    /// [`Self::check`] in a loop; a batch-friendly adapter overrides this
    /// with one provider call.
    ///
    /// # Errors
    /// As `check`; an over-size batch or any invalid URL refuses the
    /// whole call before the provider is reached.
    async fn check_many(&self, urls: &[String]) -> Result<Vec<UrlVerdict>, UrlSafetyError> {
        check_batch(urls, &UrlSafetyLimits::default())?;
        let mut verdicts = Vec::with_capacity(urls.len());
        for url in urls {
            verdicts.push(self.check(url).await?);
        }
        Ok(verdicts)
    }
}

// The cache is the decorator's own state, shared across checks for an
// entry's TTL — not request state, which is what ADR 0007 bans. Named,
// so the allow sits on this one item instead of the whole file, as the
// workspace `clippy.toml` requires and `cratefield-push-auth`'s token
// cache already does. No lock is ever held across an `await`.
#[allow(clippy::disallowed_types)]
type Guarded<T> = std::sync::Mutex<T>;

/// One cached verdict and when it stops being servable.
struct Entry {
    verdict: UrlVerdict,
    expires_at: OffsetDateTime,
}

impl Entry {
    /// Whether the entry is still servable at `now`.
    fn fresh_at(&self, now: OffsetDateTime) -> bool {
        now < self.expires_at
    }
}

/// [`UrlSafety`] with a TTL cache in front of any implementation,
/// honouring the provider's own durations: an entry lives for the
/// verdict's [`UrlVerdict::cache_ttl`] where the provider gave one, and
/// for [`Self::with_negative_ttl`] where it did not.
///
/// The map is **bounded** (the push-auth rule: no unbounded resource on
/// an isolate) and the mutex is never held across an `await` — hits are
/// served and misses staged in short critical sections around the one
/// inner call.
pub struct CachedUrlSafety {
    inner: Arc<dyn UrlSafety>,
    clock: Arc<dyn Clock>,
    #[allow(clippy::disallowed_types)]
    state: Guarded<HashMap<String, Entry>>,
    capacity: usize,
    negative_ttl: Duration,
}

impl CachedUrlSafety {
    /// Wraps `inner`, holding at most [`DEFAULT_CACHE_CAPACITY`] URLs and
    /// serving a provider-silent verdict for [`DEFAULT_NEGATIVE_TTL`].
    #[must_use]
    pub fn new(inner: Arc<dyn UrlSafety>, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner,
            clock,
            state: Guarded::new(HashMap::new()),
            capacity: DEFAULT_CACHE_CAPACITY,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
        }
    }

    /// Caps the cache at `capacity` URLs; `0` falls back to
    /// [`DEFAULT_CACHE_CAPACITY`] — a cache that holds nothing is not a
    /// cache, and a caller who wants no caching simply does not decorate.
    ///
    /// Past the bound, the entry that expires first is evicted: it is the
    /// one closest to needing a re-check anyway, so eviction costs one
    /// extra provider call, never correctness.
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = if capacity == 0 {
            DEFAULT_CACHE_CAPACITY
        } else {
            capacity
        };
        self
    }

    /// Overrides the TTL applied when a verdict's provider said nothing
    /// ([`UrlVerdict::cache_ttl`] is `None`).
    #[must_use]
    pub fn with_negative_ttl(mut self, ttl: Duration) -> Self {
        self.negative_ttl = ttl;
        self
    }

    /// The fresh cached verdict for `url`, if there is one, stamped as
    /// served-from-cache.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic in a previous check.
    fn fresh(&self, url: &str) -> Option<UrlVerdict> {
        let now = self.clock.now();
        let state = self.state.lock().expect("url safety cache");
        state
            .get(url)
            .filter(|entry| entry.fresh_at(now))
            .map(Self::served)
    }

    /// A cached entry's verdict as it is served: the original with
    /// `cached` stamped on.
    fn served(entry: &Entry) -> UrlVerdict {
        let mut verdict = entry.verdict.clone();
        verdict.cached = true;
        verdict
    }

    /// Writes `verdicts` into the map, making room before each insert.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic in a previous check.
    fn store(&self, verdicts: &[UrlVerdict]) {
        if verdicts.is_empty() {
            return;
        }
        let now = self.clock.now();
        let mut state = self.state.lock().expect("url safety cache");
        for verdict in verdicts {
            Self::insert(&mut state, verdict, now, self.capacity, self.negative_ttl);
        }
    }

    /// Inserts one entry, making room first: expired entries go free
    /// (they would not be served again regardless), then the
    /// earliest-expiring entries go while the map is at capacity.
    fn insert(
        state: &mut HashMap<String, Entry>,
        verdict: &UrlVerdict,
        now: OffsetDateTime,
        capacity: usize,
        negative_ttl: Duration,
    ) {
        state.retain(|_, entry| entry.fresh_at(now));
        while state.len() >= capacity {
            let Some(oldest) = state
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(url, _)| url.clone())
            else {
                break;
            };
            state.remove(&oldest);
        }
        let ttl = verdict.cache_ttl.unwrap_or(negative_ttl);
        let expires_at = verdict
            .checked_at
            .saturating_add(time::Duration::try_from(ttl).unwrap_or(time::Duration::MAX));
        state.insert(
            verdict.url.clone(),
            Entry {
                verdict: verdict.clone(),
                expires_at,
            },
        );
    }

    /// Splits `urls` into fresh cached verdicts (in input position,
    /// stamped `cached`) and the misses that must reach the inner
    /// provider, under one short lock.
    ///
    /// # Panics
    ///
    /// If the cache mutex was poisoned by a panic in a previous check.
    fn partition(&self, urls: &[String]) -> (Vec<Option<UrlVerdict>>, Vec<String>) {
        let now = self.clock.now();
        let state = self.state.lock().expect("url safety cache");
        let mut slots = Vec::with_capacity(urls.len());
        let mut misses = Vec::new();
        for url in urls {
            let hit = state
                .get(url)
                .filter(|entry| entry.fresh_at(now))
                .map(Self::served);
            if hit.is_none() {
                misses.push(url.clone());
            }
            slots.push(hit);
        }
        drop(state);
        (slots, misses)
    }
}

#[async_trait]
impl UrlSafety for CachedUrlSafety {
    async fn check(&self, url: &str) -> Result<UrlVerdict, UrlSafetyError> {
        if let Some(verdict) = self.fresh(url) {
            return Ok(verdict);
        }
        // The lock is already dropped: no lock is held across the await.
        let verdict = self.inner.check(url).await?;
        self.store(std::slice::from_ref(&verdict));
        Ok(verdict)
    }

    async fn check_many(&self, urls: &[String]) -> Result<Vec<UrlVerdict>, UrlSafetyError> {
        check_batch(urls, &UrlSafetyLimits::default())?;
        let (mut slots, misses) = self.partition(urls);
        if !misses.is_empty() {
            // ONE inner batch call covers every miss; the fetched entries
            // go back into the cache before the results are merged into
            // input order.
            let fetched = self.inner.check_many(&misses).await?;
            self.store(&fetched);
            let mut fetched = fetched.into_iter();
            for slot in &mut slots {
                if slot.is_none() {
                    *slot = fetched.next();
                }
            }
        }
        // The inner port answers one verdict per input, so every slot is
        // filled; `flatten` keeps the merge total without a panic on an
        // inner that broke its own contract.
        Ok(slots.into_iter().flatten().collect())
    }
}

impl std::fmt::Debug for CachedUrlSafety {
    /// Never prints a URL: the map's contents are the checked URLs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self
            .state
            .lock()
            .map_or(0, |state: std::sync::MutexGuard<'_, _>| state.len());
        f.debug_struct("CachedUrlSafety")
            .field("capacity", &self.capacity)
            .field("negative_ttl", &self.negative_ttl)
            .field("entries", &entries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

    fn limits() -> UrlSafetyLimits {
        UrlSafetyLimits {
            max_url_len: 32,
            max_batch: 2,
        }
    }

    #[test]
    fn threat_types_and_sources_name_themselves() {
        assert_eq!(ThreatType::Malware.as_str(), "MALWARE");
        assert_eq!(ThreatType::SocialEngineering.as_str(), "SOCIAL_ENGINEERING");
        assert_eq!(ThreatType::UnwantedSoftware.as_str(), "UNWANTED_SOFTWARE");
        assert_eq!(
            ThreatType::PotentiallyHarmfulApplication.as_str(),
            "POTENTIALLY_HARMFUL_APPLICATION"
        );
        assert_eq!(UrlSafetySource::GoogleWebRisk.as_str(), "google-webrisk");
        assert_eq!(
            UrlSafetySource::GoogleSafeBrowsing.as_str(),
            "google-safebrowsing"
        );
        assert_eq!(UrlSafetySource::Cache.as_str(), "cache");
    }

    #[test]
    fn check_url_accepts_http_and_https_and_refuses_the_rest() {
        let limits = UrlSafetyLimits::default();
        assert_eq!(check_url("https://example.com/", &limits), Ok(()));
        assert_eq!(check_url("http://example.com/a?b=c", &limits), Ok(()));
        assert_eq!(
            check_url("ftp://example.com/file", &limits),
            Err(UrlSafetyError::InvalidUrl)
        );
        // Schemeless: `url` cannot find a base to resolve against.
        assert_eq!(
            check_url("example.com/path", &limits),
            Err(UrlSafetyError::InvalidUrl)
        );
        assert_eq!(check_url("", &limits), Err(UrlSafetyError::InvalidUrl));
        assert_eq!(
            check_url("mailto:someone@example.com", &limits),
            Err(UrlSafetyError::InvalidUrl)
        );
    }

    #[test]
    fn check_url_refuses_an_over_long_url_as_a_limit() {
        let limits = limits();
        // "https://example.com/" is 20 bytes, so 12 fillers land exactly
        // on the ceiling and 13 cross it.
        let fits = format!("https://example.com/{}", "a".repeat(12));
        assert_eq!(fits.len(), 32);
        assert_eq!(check_url(&fits, &limits), Ok(()));
        let long = format!("https://example.com/{}", "a".repeat(13));
        assert_eq!(
            check_url(&long, &limits),
            Err(UrlSafetyError::LimitExceeded {
                limit: UrlSafetyLimit::UrlLength,
                actual: 33,
                max: 32,
            })
        );
    }

    #[test]
    fn check_batch_bounds_the_size_and_still_checks_each_url() {
        let limits = limits();
        assert_eq!(check_batch(&[], &limits), Ok(()), "an empty batch is fine");
        let ok = vec![
            "https://a.example".to_owned(),
            "https://b.example".to_owned(),
        ];
        assert_eq!(check_batch(&ok, &limits), Ok(()));

        let oversized = vec![
            "https://a.example".to_owned(),
            "https://b.example".to_owned(),
            "https://c.example".to_owned(),
        ];
        assert_eq!(
            check_batch(&oversized, &limits),
            Err(UrlSafetyError::LimitExceeded {
                limit: UrlSafetyLimit::BatchSize,
                actual: 3,
                max: 2,
            })
        );

        // A batch within its size ceiling still refuses an invalid URL.
        let one_bad = vec!["https://a.example".to_owned(), "ftp://b.example".to_owned()];
        assert_eq!(
            check_batch(&one_bad, &limits),
            Err(UrlSafetyError::InvalidUrl)
        );
    }

    #[test]
    fn provider_text_is_scrubbed_in_display_but_not_debug() {
        let error =
            UrlSafetyError::Provider("400 for https://api.example.test?token=secret".to_owned());
        let text = error.to_string();
        assert!(!text.contains("secret"), "{text}");
        assert!(format!("{error:?}").contains("secret"));
        // The typed variants carry numbers and fixed text only — never
        // the URL that drew the rejection.
        assert_eq!(
            UrlSafetyError::Rejected { status: 429 }.to_string(),
            "url safety provider rejected the request: status 429"
        );
        assert_eq!(
            UrlSafetyError::InvalidUrl.to_string(),
            "not an http(s) URL; nothing was checked"
        );
    }

    #[test]
    fn transient_carries_an_optional_retry_after() {
        let throttled = UrlSafetyError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(
            UrlSafetyError::Transient { retry_after: None }.retry_after(),
            None
        );
        assert_eq!(UrlSafetyError::InvalidUrl.retry_after(), None);
    }

    /// A fake clock the test advances by hand.
    struct FakeClock(AtomicI64);

    impl FakeClock {
        fn at(secs: i64) -> Arc<Self> {
            Arc::new(Self(AtomicI64::new(secs)))
        }

        fn advance(&self, secs: i64) {
            self.0.fetch_add(secs, Ordering::Relaxed);
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::Relaxed)).expect("in range")
        }
    }

    /// An inner provider that counts its calls, stamps verdicts from the
    /// same clock the cache sees, and fails on demand. `checks` counts
    /// single checks, `batches` batch calls; neither feeds the other.
    struct FakeInner {
        clock: Arc<FakeClock>,
        checks: AtomicUsize,
        batches: AtomicUsize,
        fail: AtomicBool,
        /// The retention handed out with every verdict; `None` exercises
        /// the negative-TTL path.
        ttl: Option<Duration>,
    }

    impl FakeInner {
        fn checks(&self) -> usize {
            self.checks.load(Ordering::Relaxed)
        }

        fn batches(&self) -> usize {
            self.batches.load(Ordering::Relaxed)
        }

        fn verdict(&self, url: &str) -> UrlVerdict {
            let threats = if url.contains("malware") {
                vec![ThreatType::Malware]
            } else if url.contains("phishing") {
                vec![ThreatType::SocialEngineering]
            } else {
                Vec::new()
            };
            UrlVerdict {
                url: url.to_owned(),
                threats,
                source: UrlSafetySource::GoogleWebRisk,
                checked_at: self.clock.now(),
                cache_ttl: self.ttl,
                cached: false,
            }
        }
    }

    #[async_trait]
    impl UrlSafety for FakeInner {
        async fn check(&self, url: &str) -> Result<UrlVerdict, UrlSafetyError> {
            self.checks.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Relaxed) {
                return Err(UrlSafetyError::Provider(format!("boom for {url}")));
            }
            Ok(self.verdict(url))
        }

        async fn check_many(&self, urls: &[String]) -> Result<Vec<UrlVerdict>, UrlSafetyError> {
            self.batches.fetch_add(1, Ordering::Relaxed);
            let mut verdicts = Vec::with_capacity(urls.len());
            for url in urls {
                if self.fail.load(Ordering::Relaxed) {
                    return Err(UrlSafetyError::Provider(format!("boom for {url}")));
                }
                verdicts.push(self.verdict(url));
            }
            Ok(verdicts)
        }
    }

    type Parts = (Arc<FakeClock>, Arc<FakeInner>, CachedUrlSafety);

    /// A cache over a counting inner whose verdicts carry `ttl`.
    fn cache_with(ttl: Option<Duration>, fail: bool) -> Parts {
        let clock = FakeClock::at(1_000);
        let inner = Arc::new(FakeInner {
            clock: clock.clone(),
            checks: AtomicUsize::new(0),
            batches: AtomicUsize::new(0),
            fail: AtomicBool::new(fail),
            ttl,
        });
        let cache = CachedUrlSafety::new(inner.clone(), clock.clone());
        (clock, inner, cache)
    }

    #[test]
    fn a_hit_within_the_ttl_serves_the_cache_and_a_miss_goes_to_the_provider() {
        let (clock, inner, cache) = cache_with(Some(Duration::from_secs(60)), false);

        let url = "https://example.test/page";
        let first = pollster::block_on(cache.check(url)).expect("checked");
        assert_eq!(inner.checks(), 1);
        assert!(!first.cached);
        assert_eq!(
            first.url, url,
            "the verdict's url equals the input, verbatim"
        );
        assert!(!first.is_threat());

        // Within the TTL: no provider call, same threats and stamp,
        // `cached` on.
        clock.advance(59);
        let second = pollster::block_on(cache.check(url)).expect("checked");
        assert_eq!(inner.checks(), 1, "served from the cache");
        assert!(second.cached);
        assert_eq!(second.threats, first.threats);
        assert_eq!(second.checked_at, first.checked_at);

        // Past the TTL, the provider is asked again.
        clock.advance(2); // 61 s after the check
        pollster::block_on(cache.check(url)).expect("checked");
        assert_eq!(inner.checks(), 2, "past the TTL the provider answers again");
    }

    #[test]
    fn a_verdict_without_a_provider_ttl_uses_the_negative_ttl() {
        let (clock, inner, cache) = cache_with(None, false);
        let cache = cache.with_negative_ttl(Duration::from_secs(30));

        pollster::block_on(cache.check("https://example.test")).expect("checked");
        clock.advance(29);
        pollster::block_on(cache.check("https://example.test")).expect("checked");
        assert_eq!(inner.checks(), 1, "still inside the negative TTL");

        clock.advance(2); // 31 s after the check
        pollster::block_on(cache.check("https://example.test")).expect("checked");
        assert_eq!(inner.checks(), 2, "past the negative TTL");
    }

    #[test]
    fn check_many_merges_in_input_order_with_one_batch_call_for_the_misses() {
        let (_, inner, cache) = cache_with(Some(Duration::from_secs(300)), false);

        // The plain URL is warm before the batch; the two named by
        // threat are cold, so the batch has work to do.
        pollster::block_on(cache.check("https://a.example")).expect("warmed");
        assert_eq!(inner.checks(), 1);

        let urls = vec![
            "https://malware.example".to_owned(),
            "https://a.example".to_owned(),
            "https://phishing.example".to_owned(),
        ];
        let verdicts = pollster::block_on(cache.check_many(&urls)).expect("checked");
        assert_eq!(verdicts.len(), urls.len(), "one verdict per input");
        assert_eq!(inner.batches(), 1, "one batch call covered every miss");
        assert_eq!(inner.checks(), 1, "the warm URL was not re-checked");
        assert_eq!(verdicts[0].url, urls[0]);
        assert_eq!(verdicts[0].threats, vec![ThreatType::Malware]);
        assert!(!verdicts[0].cached);
        assert_eq!(verdicts[1].url, urls[1], "the hit kept its input position");
        assert!(verdicts[1].cached);
        assert_eq!(verdicts[2].url, urls[2]);
        assert_eq!(verdicts[2].threats, vec![ThreatType::SocialEngineering]);
        assert!(!verdicts[2].cached);

        // The fetched entries were stored: the same ask now hits in full.
        let again = pollster::block_on(cache.check_many(&urls)).expect("checked");
        assert_eq!(inner.batches(), 1, "nothing new reached the provider");
        assert!(again.iter().all(|verdict| verdict.cached));
    }

    #[test]
    fn the_cache_checks_limits_before_the_provider() {
        let (_, inner, cache) = cache_with(Some(Duration::from_secs(60)), false);
        let urls = (0..501)
            .map(|n| format!("https://{n}.example"))
            .collect::<Vec<_>>();
        let error = pollster::block_on(cache.check_many(&urls)).expect_err("over the ceiling");
        assert!(matches!(
            error,
            UrlSafetyError::LimitExceeded {
                limit: UrlSafetyLimit::BatchSize,
                ..
            }
        ));
        assert_eq!(inner.batches(), 0, "the provider was never asked");
    }

    #[test]
    fn a_full_cache_evicts_the_earliest_expiring_entry() {
        let (_, inner, cache) = cache_with(Some(Duration::from_secs(60)), false);
        let cache = cache.with_capacity(1);

        pollster::block_on(cache.check("https://first.example")).expect("checked");
        pollster::block_on(cache.check("https://second.example")).expect("checked");
        assert_eq!(inner.checks(), 2);
        // The first entry was evicted to make room, so re-checking it
        // goes back to the provider...
        pollster::block_on(cache.check("https://first.example")).expect("checked");
        assert_eq!(inner.checks(), 3);
        // ...and that re-check evicted the second, which is now a miss
        // too. Capacity one holds, whatever the order of asks.
        pollster::block_on(cache.check("https://second.example")).expect("checked");
        assert_eq!(inner.checks(), 4);
    }

    #[test]
    fn an_error_propagates_and_is_never_cached() {
        let (_, inner, cache) = cache_with(Some(Duration::from_secs(60)), true);

        let error = pollster::block_on(cache.check("https://example.test")).expect_err("failed");
        assert!(matches!(error, UrlSafetyError::Provider(_)));
        // Not cached: the next ask reaches the provider again.
        pollster::block_on(cache.check("https://example.test")).expect_err("failed again");
        assert_eq!(inner.checks(), 2, "a failed check must not be cached");
    }
}
