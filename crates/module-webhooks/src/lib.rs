//! `cratefield-module-webhooks`: outbound webhook delivery.
//!
//! ```no_run
//! use cratefield_module_webhooks::Webhooks;
//!
//! let module = Webhooks::new().max_attempts(5);
//! ```
//!
//! Two things, said once here and once in the README's first section:
//! this module ships **no HTTP routes of its own** — the Rust API is the
//! surface — and [`Webhooks::create_endpoint`] hands back the endpoint's
//! signing secret **exactly once**. The wire format, the delivery
//! policy, the configuration and the worked examples are the README
//! below.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod clock;
mod deliver;
mod store;

pub use crate::deliver::{
    DeliveryError, DrainReport, EVENT_ID_HEADER, EVENT_TYPE_HEADER, SIGNATURE_HEADER,
};
pub use crate::store::{DeadLetter, Delivery, Endpoint, TOPIC_DELIVER};
use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, Database, DbError, IdGen, Migrations, Module,
    ModuleConfig, ModuleContext, PersonalDataSet, Port, SqlMigration, UlidIdGen,
};

/// The name the module mounts under: `/v1/webhooks`.
pub const MODULE_NAME: &str = "webhooks";

/// The one migration: the endpoints, outbox, deliveries and dead-letter
/// tables, in the portable SQL subset (ADR 0004).
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The bounds the builder's clamp and `WEBHOOKS_MAX_ATTEMPTS` validation
/// share, so the two can never drift apart.
const MAX_ATTEMPTS_RANGE: std::ops::RangeInclusive<u32> = 1..=1_000;

/// A module that delivers signed outbound webhooks.
#[derive(Debug, Clone)]
pub struct Webhooks {
    /// Dead-letter a delivery after this many failed attempts. Overridden
    /// per deployment by `WEBHOOKS_MAX_ATTEMPTS`.
    max_attempts: u32,
}

impl Default for Webhooks {
    fn default() -> Self {
        Self::new()
    }
}

impl Webhooks {
    /// Defaults: dead-letter after five failed attempts.
    #[must_use]
    pub fn new() -> Self {
        Self { max_attempts: 5 }
    }

    /// Dead-letter a delivery after this many failed attempts instead of
    /// five. Values outside `1..=1_000` clamp to the nearest bound — the
    /// same range `WEBHOOKS_MAX_ATTEMPTS` must pass validation with.
    /// `WEBHOOKS_MAX_ATTEMPTS` overrides this when set.
    #[must_use]
    pub fn max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts =
            max_attempts.clamp(*MAX_ATTEMPTS_RANGE.start(), *MAX_ATTEMPTS_RANGE.end());
        self
    }

    /// Registers one delivery endpoint for `subject` and returns its
    /// signing secret — **the only time the secret is ever handed back**.
    /// List the endpoints later and the secret is not in the answer.
    ///
    /// `event_types` is a filter; an empty slice means "everything"
    /// (`*`). A URL that is not http(s), or a filter naming an event type
    /// that could never ride a header, is refused here rather than failed
    /// at every delivery.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] for a malformed URL or subject, or a filter
    /// naming an unusable event type, and [`DbError`] when the insert
    /// fails.
    pub async fn create_endpoint(
        &self,
        db: &dyn Database,
        subject: &str,
        url: &str,
        event_types: &[&str],
        now: &str,
    ) -> Result<CreatedEndpoint, EndpointError> {
        if subject.trim().is_empty() || subject.len() > 255 {
            return Err(EndpointError::InvalidSubject);
        }
        if !is_http_url(url) {
            return Err(EndpointError::InvalidUrl(url.to_owned()));
        }
        for candidate in event_types {
            let candidate = candidate.trim();
            if !candidate.is_empty() && !is_valid_event_type(candidate) {
                return Err(EndpointError::InvalidEventType(candidate.to_owned()));
            }
        }
        let secret = generate_secret()?;
        let id = UlidIdGen.ulid();
        db.execute(&store::insert_endpoint_statement(
            &id,
            subject,
            url,
            &secret,
            &normalize_event_types(event_types),
            now,
        ))
        .await?;
        Ok(CreatedEndpoint {
            endpoint_id: id,
            secret,
        })
    }

    /// The endpoints registered for `subject`, creation order — without
    /// their secrets.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the read fails.
    pub async fn endpoints(
        &self,
        db: &dyn Database,
        subject: &str,
    ) -> Result<Vec<Endpoint>, DbError> {
        store::endpoints_for_subject(db, subject).await
    }

    /// Deletes one endpoint of one subject; `false` when no such endpoint
    /// belongs to that subject. Events already queued for it are dropped
    /// by the next drain — there is nobody left to deliver them to.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the delete fails.
    pub async fn delete_endpoint(
        &self,
        db: &dyn Database,
        subject: &str,
        endpoint_id: &str,
    ) -> Result<bool, DbError> {
        store::delete_endpoint(db, subject, endpoint_id).await
    }

    /// Fans one event out to every endpoint of `subject` whose filter
    /// matches `event_type`, and returns the outbox `INSERT`s — append
    /// `Published::into_statements` to the caller's **own**
    /// `db.batch_atomic(..)`, so the event is durable exactly when the
    /// state change that caused it is. Nothing is written until that
    /// batch runs.
    ///
    /// An event no endpoint matches is `Published::endpoints == 0` and
    /// nothing else — not an error: "nobody subscribed to that" is an
    /// ordinary answer.
    ///
    /// # Errors
    ///
    /// [`PublishError::InvalidEventType`] for an event type that could
    /// never ride the `Cratefield-Event-Type` header (refused before any
    /// read, so it cannot burn attempts later), and [`DbError`] when the
    /// endpoint read fails.
    pub async fn publish(
        &self,
        db: &dyn Database,
        subject: &str,
        event_type: &str,
        data: &serde_json::Value,
        now: &str,
    ) -> Result<Published, PublishError> {
        if !is_valid_event_type(event_type) {
            return Err(PublishError::InvalidEventType(event_type.to_owned()));
        }
        let endpoints = store::endpoints_for_subject(db, subject).await?;
        let event_id = UlidIdGen.ulid();
        let mut statements = Vec::new();
        for endpoint in &endpoints {
            if !matches_filter(&endpoint.event_types, event_type) {
                continue;
            }
            statements.push(store::enqueue_statement(
                &store::DeliveryJob {
                    endpoint_id: endpoint.id.clone(),
                    event_id: event_id.clone(),
                    event_type: event_type.to_owned(),
                    subject: subject.to_owned(),
                    created_at: now.to_owned(),
                    data: data.clone(),
                },
                subject,
                now,
            ));
        }
        Ok(Published {
            event_id,
            endpoints: statements.len(),
            statements,
        })
    }

    /// Delivers due outbox rows through the ports of `ctx`, spending no
    /// more than what the invocation's `ctx.scheduled` budget allows (ADR
    /// 0023). Call it from the venture's **scheduled** entry point — a cron
    /// invocation builds no router, so the context must be the one the
    /// runtime hands in, not one parked at router-build time.
    ///
    /// Each row is signed and delivered once per pass: 2xx completes it,
    /// anything else retries with exponential backoff (410 Gone and
    /// SSRF-blocked destinations dead-letter immediately), and
    /// `MAX_ATTEMPTS` failures dead-letter it for
    /// [`Webhooks::replay`]. One delivery attempt spends one subrequest;
    /// when the budget runs out the rows it never reached stay queued, due
    /// now, for the next tick. A per-row failure never aborts the pass.
    ///
    /// # Errors
    ///
    /// [`DeliveryError`] when a port is missing, the claim fails, or the
    /// outbox refuses a completion write.
    pub async fn drain_with(&self, ctx: &ModuleContext) -> Result<DrainReport, DeliveryError> {
        deliver::drain(ctx, self.max_attempts).await
    }

    /// Re-enqueues one dead letter of `subject` — attempts reset to zero —
    /// and removes it, in one batch. The delivery log keeps the history.
    /// `false` — the letter left exactly where it was — when the id names
    /// no dead letter of this subject, **or** when the letter's endpoint
    /// is gone: a replay into a deleted endpoint would consume the letter
    /// and then be dropped by the drain, destroying the event for good.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the read or the batch fails.
    pub async fn replay(
        &self,
        db: &dyn Database,
        subject: &str,
        dead_letter_id: &str,
        now: &str,
    ) -> Result<bool, DbError> {
        store::replay(db, subject, dead_letter_id, now).await
    }

    /// A subject's delivery log, newest attempt first. `status_code` is
    /// `None` for an attempt that never got an answer.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the read fails.
    pub async fn deliveries(
        &self,
        db: &dyn Database,
        subject: &str,
        limit: u64,
    ) -> Result<Vec<Delivery>, DbError> {
        store::deliveries(db, subject, limit).await
    }

    /// A subject's dead letters, oldest first — the ids
    /// [`Webhooks::replay`] takes.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the read fails.
    pub async fn dead_letters(
        &self,
        db: &dyn Database,
        subject: &str,
        limit: u64,
    ) -> Result<Vec<DeadLetter>, DbError> {
        store::dead_letters(db, subject, limit).await
    }
}

impl Module for Webhooks {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // `Clock` stamps both the stored timestamps and the signature; a
        // webhook that cannot be delivered is not a delivery pipeline.
        &[Port::Db, Port::HttpClient, Port::Clock]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[
            store::ENDPOINTS,
            store::OUTBOX,
            store::DELIVERIES,
            store::DEAD_LETTERS,
        ]
    }

    /// Every table keys its rows on the subject the event (or endpoint)
    /// belongs to, so erasure reaches all four; the endpoint `secret` is
    /// credential material and is exported redacted.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet {
                table: store::ENDPOINTS,
                subject: "subject",
                kind: cratefield_core::DataKind::Identifier,
                disposition: cratefield_core::Disposition::Erase,
                description: "The webhook URLs this venture delivers your events to, one row \
                              each. Each row holds a signing secret, which is why it is \
                              redacted here; deleting your account deletes the endpoints and \
                              their secrets.",
                redacted: &["secret"],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::OUTBOX,
                subject: "subject",
                kind: cratefield_core::DataKind::Content,
                disposition: cratefield_core::Disposition::Erase,
                description: "Events queued for delivery to the endpoints above, with the \
                              account they are about. A delivery is erased with the account \
                              even if it has not been sent yet.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::DELIVERIES,
                subject: "subject",
                kind: cratefield_core::DataKind::Usage,
                disposition: cratefield_core::Disposition::Erase,
                description: "The log of delivery attempts: which endpoint, which event, what \
                              status code came back, and when. It shows which of your events \
                              left the venture, and nothing else.",
                redacted: &[],
                subject_via: None,
            },
            PersonalDataSet {
                table: store::DEAD_LETTERS,
                subject: "subject",
                kind: cratefield_core::DataKind::Content,
                disposition: cratefield_core::Disposition::Erase,
                description: "Events that gave up after repeated failed deliveries, kept so \
                              they can be replayed. They carry the same data as the queued \
                              events above, and go when your account is deleted.",
                redacted: &[],
                subject_via: None,
            },
        ];
        SETS
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new(MODULE_NAME, cfg);
        let mut errors = ConfigError::default();
        if let Some(raw) = cfg
            .get(&module.key("MAX_ATTEMPTS"))
            .map(|raw| raw.parse::<u32>())
            && !raw.is_ok_and(|value| MAX_ATTEMPTS_RANGE.contains(&value))
        {
            errors.push(format!(
                "webhooks: {} must be a whole number between 1 and 1000",
                module.key("MAX_ATTEMPTS")
            ));
        }
        errors.into_result()
    }

    /// Deliberately empty: see the crate documentation — the Rust API is
    /// this module's surface, and a management route would need an auth
    /// decision this crate does not make.
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }

    /// The recovery half of the outbox contract: whatever a caller's
    /// immediate drain never got to is delivered on the next tick — as far
    /// as the invocation's budget reaches (ADR 0023), with the rest left
    /// due for the ticks after — and the dead letters pile up here for
    /// [`Webhooks::replay`].
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            let report = self
                .drain_with(ctx)
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            // `deferred` alone is worth a line: the budget stopped a pass
            // that had work left, and the next tick must pick it up.
            if report.claimed > 0 || report.deferred > 0 {
                tracing::info!(?report, cron, "drained the webhooks outbox");
            }
            Ok(())
        })
    }
}

/// What [`Webhooks::create_endpoint`] returns: the endpoint's id, and the
/// signing secret — which is returned **once**. Store it now; it is never
/// listed again.
#[derive(Clone, PartialEq, Eq)]
pub struct CreatedEndpoint {
    pub endpoint_id: String,
    pub secret: String,
}

// The `Debug` is manual because the struct carries a signing secret: a
// `{:?}` in a log, a trace or a test failure must not print it (the
// pattern `cratefield-secrets` uses for its own bytes).
impl std::fmt::Debug for CreatedEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedEndpoint")
            .field("endpoint_id", &self.endpoint_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Why an endpoint was refused before the database was touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointError {
    /// The URL is not an http(s) URL, carries whitespace, or is longer
    /// than 2048 bytes.
    InvalidUrl(String),
    /// The subject is empty or longer than 255 bytes.
    InvalidSubject,
    /// A filter named an event type no HTTP header could carry. Refused
    /// here, because it would filter out every event: publishing such a
    /// type fails too, so no match could ever happen.
    InvalidEventType(String),
    /// The operating system refused to give this process random bytes,
    /// so no secret could be generated.
    Entropy(String),
    /// The insert failed.
    Database(DbError),
}

impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointError::InvalidUrl(url) => {
                write!(f, "webhooks: not an http(s) URL: {url:?}")
            }
            EndpointError::InvalidSubject => {
                f.write_str("webhooks: the subject must be 1..=255 bytes")
            }
            EndpointError::InvalidEventType(event_type) => {
                write!(f, "webhooks: not a usable event type: {event_type:?}")
            }
            EndpointError::Entropy(error) => write!(f, "webhooks: {error}"),
            EndpointError::Database(error) => write!(f, "webhooks: {error}"),
        }
    }
}

impl std::error::Error for EndpointError {}

impl From<DbError> for EndpointError {
    fn from(error: DbError) -> Self {
        EndpointError::Database(error)
    }
}

/// Why [`Webhooks::publish`] refused before writing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// The event type is not a header-safe token: empty, whitespace, or
    /// anything outside visible ASCII. Refused here because such a type
    /// would otherwise become an undeliverable `Cratefield-Event-Type`
    /// header value that burns every retry.
    InvalidEventType(String),
    /// The endpoint read failed.
    Database(DbError),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishError::InvalidEventType(event_type) => {
                write!(f, "webhooks: not a usable event type: {event_type:?}")
            }
            PublishError::Database(error) => write!(f, "webhooks: {error}"),
        }
    }
}

impl std::error::Error for PublishError {}

impl From<DbError> for PublishError {
    fn from(error: DbError) -> Self {
        PublishError::Database(error)
    }
}

/// What [`Webhooks::publish`] produced. Append
/// `Published::into_statements` to the caller's own `db.batch_atomic(..)`;
/// nothing is written until that batch runs.
#[derive(Debug, Clone)]
pub struct Published {
    /// The event's identity, shared by every fan-out row of this one
    /// event and sent as the `Cratefield-Event-Id` header, so a receiver
    /// can dedupe the redeliveries at-least-once delivery promises.
    pub event_id: String,
    /// How many endpoints matched — how many statements there are, and
    /// how many POSTs the drain will eventually make.
    pub endpoints: usize,
    statements: Vec<cratefield_core::Statement>,
}

impl Published {
    /// The outbox `INSERT`s, for the caller's own
    /// `db.batch_atomic(..)`.
    #[must_use]
    pub fn into_statements(self) -> Vec<cratefield_core::Statement> {
        self.statements
    }
}

/// Whether an event type can be both a filter entry and a header value:
/// 1..=128 bytes of visible ASCII, no whitespace — the characters an
/// HTTP header value survives verbatim. Enforced at `publish` and at
/// `create_endpoint`, so no filter can name a type no event could ever
/// carry.
fn is_valid_event_type(event_type: &str) -> bool {
    (1..=128).contains(&event_type.len()) && event_type.chars().all(|c| c.is_ascii_graphic())
}

/// Whether an endpoint's stored `event_types` filter matches an event.
///
/// `*` (what an empty filter normalises to) matches everything; anything
/// else is a comma-separated list of exact event types, so `order.paid`
/// does not match `order.paid.v2`.
#[must_use]
pub fn matches_filter(filter: &str, event_type: &str) -> bool {
    let filter = filter.trim();
    filter == "*"
        || filter
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == event_type)
}

/// Normalises the `create_endpoint` filter: trimmed, empty parts dropped,
/// duplicates collapsed, and an empty result meaning "everything".
#[must_use]
pub fn normalize_event_types(event_types: &[&str]) -> String {
    let mut seen = Vec::new();
    for candidate in event_types {
        let candidate = candidate.trim();
        if !candidate.is_empty() && !seen.contains(&candidate) {
            seen.push(candidate);
        }
    }
    if seen.is_empty() {
        "*".to_owned()
    } else {
        seen.join(",")
    }
}

/// An http(s) URL with nowhere for whitespace to hide. The deep checks —
/// loopback, private and metadata destinations — are the `HttpClient`
/// port's contract, re-vetted per delivery and per redirect hop; this is
/// the fast, obvious refusal a typo earns at registration.
fn is_http_url(url: &str) -> bool {
    let max = 2048;
    (url.starts_with("https://") || url.starts_with("http://"))
        && url.len() <= max
        && !url.contains(char::is_whitespace)
        && match url.split_once("://") {
            // The authority must be non-empty: `http:///path` names no
            // host at all.
            Some((_, rest)) => {
                let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
                !authority.is_empty()
            }
            None => false,
        }
}

/// 32 OS-random bytes, hex, with the `whsec_` prefix the in-repo fixtures
/// use. A signing key, generated where it is stored: it crosses one
/// response boundary (creation) and is then never handed back, never
/// logged, and exported only redacted.
fn generate_secret() -> Result<String, EndpointError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| EndpointError::Entropy(error.to_string()))?;
    let mut hex = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        // Writing to a String cannot fail.
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(format!("whsec_{hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_documented_ones() {
        let module = Webhooks::new();
        assert_eq!(module.name(), "webhooks");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(module.requires(), [Port::Db, Port::HttpClient, Port::Clock]);
        assert_eq!(
            module.tables(),
            [
                "webhooks_endpoints",
                "webhooks_outbox",
                "webhooks_deliveries",
                "webhooks_dead_letters"
            ]
        );
        assert_eq!(module.max_attempts, 5);
    }

    #[test]
    fn max_attempts_stays_within_the_range_the_config_must_pass() {
        assert_eq!(Webhooks::new().max_attempts(0).max_attempts, 1);
        assert_eq!(Webhooks::new().max_attempts(2).max_attempts, 2);
        assert_eq!(Webhooks::new().max_attempts(1_000).max_attempts, 1_000);
        assert_eq!(Webhooks::new().max_attempts(5_000).max_attempts, 1_000);
    }

    #[test]
    fn a_created_endpoints_debug_never_carries_the_secret() {
        let created = CreatedEndpoint {
            endpoint_id: "ep_01HXYZ".to_owned(),
            secret: "whsec_hunter2".to_owned(),
        };
        let rendered = format!("{created:?}");
        assert!(rendered.contains("ep_01HXYZ"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn event_types_must_be_header_safe_tokens() {
        assert!(is_valid_event_type("order.paid"));
        assert!(is_valid_event_type("order-paid_v2"));
        assert!(!is_valid_event_type(""), "empty");
        assert!(!is_valid_event_type(" order.paid"), "leading space");
        assert!(!is_valid_event_type("order paid"), "inner space");
        assert!(!is_valid_event_type("command\ninjection"), "control char");
        assert!(!is_valid_event_type("héllo"), "non-ASCII");
        assert!(is_valid_event_type(&"x".repeat(128)), "the max is allowed");
        assert!(!is_valid_event_type(&"x".repeat(129)), "over the max");
    }

    #[test]
    fn a_star_filter_matches_everything_and_a_list_matches_exactly() {
        assert!(matches_filter("*", "order.paid"));
        assert!(matches_filter("*", ""));
        assert!(matches_filter("order.paid", "order.paid"));
        assert!(matches_filter(
            " order.paid , order.refunded ",
            "order.refunded"
        ));
        assert!(!matches_filter("order.paid", "order.paid.v2"));
        assert!(!matches_filter("order.paid", "order.refunded"));
        assert!(
            !matches_filter("", "order.paid"),
            "empty stores as *, never as nothing"
        );
    }

    #[test]
    fn filters_normalise_to_a_stored_list_or_a_star() {
        assert_eq!(
            normalize_event_types(&["order.paid", "order.refunded"]),
            "order.paid,order.refunded"
        );
        assert_eq!(normalize_event_types(&[" order.paid ", ""]), "order.paid");
        assert_eq!(normalize_event_types(&["a", "a", "b"]), "a,b");
        assert_eq!(normalize_event_types(&[]), "*");
        assert_eq!(normalize_event_types(&["", "  "]), "*");
    }

    #[test]
    fn urls_must_be_http_s_with_nowhere_for_whitespace_to_hide() {
        assert!(is_http_url("https://example.com/hook"));
        assert!(is_http_url("http://example.com"));
        assert!(!is_http_url("example.com/hook"));
        assert!(!is_http_url("ftp://example.com"));
        assert!(!is_http_url("https://"));
        assert!(!is_http_url("http:///path"), "no host at all");
        assert!(!is_http_url("https:///q?a=1"), "no host, only a query");
        assert!(is_http_url("http://example.com?a=1"), "authority, no path");
        assert!(!is_http_url("https://example.com/a b"));
        assert!(!is_http_url(""));
        assert!(!is_http_url("https://example.com/\n"));
    }

    #[test]
    fn secrets_are_prefixed_hex_and_never_repeat() {
        let a = generate_secret().expect("os randomness");
        let b = generate_secret().expect("os randomness");
        assert!(a.starts_with("whsec_"), "{a}");
        let hex = a.strip_prefix("whsec_").expect("prefix");
        assert_eq!(hex.len(), 64, "32 bytes in hex");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a, b, "two secrets are two draws");
    }

    #[test]
    fn a_bad_config_is_collected_not_thrown_one_at_a_time() {
        let ok = MapConfig::from_pairs([("WEBHOOKS_MAX_ATTEMPTS", "3")]);
        assert!(Webhooks::new().validate_config(&ok).is_ok());

        let empty = MapConfig::from_pairs([("WEBHOOKS_MAX_ATTEMPTS", "")]);
        let error = Webhooks::new()
            .validate_config(&empty)
            .expect_err("an unparsable attempt count is refused");
        assert!(
            error.to_string().contains("WEBHOOKS_MAX_ATTEMPTS"),
            "{error}"
        );

        let zero = MapConfig::from_pairs([("WEBHOOKS_MAX_ATTEMPTS", "0")]);
        assert!(Webhooks::new().validate_config(&zero).is_err());

        // The range the builder clamps to is the range this accepts.
        let ceiling = MapConfig::from_pairs([("WEBHOOKS_MAX_ATTEMPTS", "1000")]);
        assert!(Webhooks::new().validate_config(&ceiling).is_ok());
        let past = MapConfig::from_pairs([("WEBHOOKS_MAX_ATTEMPTS", "1001")]);
        assert!(Webhooks::new().validate_config(&past).is_err());
    }

    use cratefield_core::MapConfig;
}
