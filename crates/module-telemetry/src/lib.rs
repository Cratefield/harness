//! Aggregate usage telemetry for a Cratefield venture (issue #413): the
//! collector, the closed payload grammar and the consent model, in one
//! crate. Clients report **counted** events; every field is validated
//! against a fixed vocabulary — an unknown field or an undeclared value is
//! a rejection, never a truncation or a coercion — and the counts
//! accumulate into buckets in the venture's own database, under the same
//! retention and erasure rules as the rest of its tables.
//!
//! # Composition
//!
//! ```no_run
//! use cratefield_module_telemetry::Telemetry;
//!
//! let module = Telemetry::new()
//!     .events(["run", "report", "upgrade"]) // closed event vocabulary
//!     .modules(["telemetry", "waitlist"]) // closed composed-module vocabulary
//!     .retention_days(180)
//!     .max_events_per_batch(64)
//!     .opt_out_command("fz telemetry off")
//!     .status_command("fz telemetry status");
//! ```
//!
//! Both vocabularies default to **empty, which fails closed**: a venture
//! that forgets to declare them runs a collector that rejects every batch
//! naming an event or a module, not one that counts anything it is sent.
//!
//! # Consent
//!
//! The consent model lives in [`consent`]: a pure decision over the
//! environment (the local opt-out, `DO_NOT_TRACK`, `CI`), a first-run
//! notice generated from the payload schema so it cannot drift, a `status`
//! rendering of the exact bytes that would be sent, and an install id the
//! caller mints from random bytes and rotates every [`consent::ROTATION_DAYS`]
//! days. The crate itself never generates randomness and never opens a
//! connection, which is what keeps it wasm-safe and dependency-free.
//!
//! See `docs/TELEMETRY.md` for the published client contract this crate
//! implements.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;
mod store;

pub mod consent;
pub mod payload;

use std::sync::OnceLock;

// Re-exported because it appears in public signatures (`consent::notice`,
// `consent::status` take it): a caller should be able to name what it holds.
pub use handlers::Settings;

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DataKind, Disposition, Migrations, Module,
    ModuleConfig, ModuleContext, PersonalDataSet, Port, SqlMigration,
};

use crate::payload::Vocabulary;
use time::OffsetDateTime;

/// The longest retention a venture may configure, in days: 36,500 — about
/// a century, several times any retention a venture has ever wanted. The
/// ceiling exists because the purge computes `now - retention` as a real
/// date, and a retention in the millions (a number of days fat-fingered
/// from milliseconds or seconds) walks that date out of the representable
/// calendar; catching it at build time is cheaper than a failed run on
/// every cron fire (issue #413).
pub const MAX_RETENTION_DAYS: u32 = 36_500;

/// The module's migration: the two aggregate tables in the portable SQL
/// subset (issue #413, ADR 0004 — applied verbatim on Postgres while the
/// postgres list is empty).
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// Aggregate usage telemetry with a consent model built in (issue #413).
///
/// Compose it for the vocabularies a venture wants counted; everything
/// else — routes, grammar, storage, retention — is fixed by the module.
pub struct Telemetry {
    settings: Settings,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    /// Empty vocabularies (fail closed: every batch naming an event or a
    /// module is rejected until the venture declares them), the 64-event
    /// batch ceiling, 180-day retention, and the `fz telemetry` commands.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: Settings {
                vocabulary: Vocabulary::default(),
                retention_days: 180,
                opt_out_command: "fz telemetry off".to_owned(),
                status_command: "fz telemetry status".to_owned(),
            },
        }
    }

    /// Declares the whole event vocabulary. Exactly these names may be
    /// counted; anything else is a rejection, never a new series (issue
    /// #413). Replaces any previous list.
    #[must_use]
    pub fn events(mut self, events: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.settings.vocabulary.events = events.into_iter().map(Into::into).collect();
        self
    }

    /// Declares the whole composed-module vocabulary a client may report.
    /// Replaces any previous list.
    #[must_use]
    pub fn modules(mut self, modules: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.settings.vocabulary.modules = modules.into_iter().map(Into::into).collect();
        self
    }

    /// How long buckets live before the scheduled purge deletes them
    /// (default 180). Clamped to `1..=[MAX_RETENTION_DAYS]`: a builder
    /// cannot return an error, and zero would delete every bucket the day
    /// it is written while a value past the ceiling would walk the purge's
    /// date arithmetic off the calendar — so an impossible value is
    /// narrowed to the nearest workable one rather than honoured (issue
    /// #413).
    #[must_use]
    pub fn retention_days(mut self, days: u32) -> Self {
        self.settings.retention_days = days.clamp(1, MAX_RETENTION_DAYS);
        self
    }

    /// The largest batch the collector parses (default 64). Clamped to
    /// `1..=[payload::MAX_EVENTS_PER_BATCH]`: "at most this many" is part
    /// of the closed grammar, so a venture may tighten it and never widen
    /// it, and zero — which the clamp also removes — would leave a
    /// collector that rejects every batch with a message about exceeding a
    /// ceiling of nothing (issue #413).
    #[must_use]
    pub fn max_events_per_batch(mut self, max: u32) -> Self {
        self.settings.vocabulary.max_events = usize::try_from(max)
            .unwrap_or(crate::payload::MAX_EVENTS_PER_BATCH)
            .clamp(1, crate::payload::MAX_EVENTS_PER_BATCH);
        self
    }

    /// The command a client prints as the one-line way to switch reporting
    /// off (default `fz telemetry off`).
    #[must_use]
    pub fn opt_out_command(mut self, command: impl Into<String>) -> Self {
        self.settings.opt_out_command = command.into();
        self
    }

    /// The command a client prints as the way to see exactly what would be
    /// sent (default `fz telemetry status`).
    #[must_use]
    pub fn status_command(mut self, command: impl Into<String>) -> Self {
        self.settings.status_command = command.into();
        self
    }
}

impl Module for Telemetry {
    fn name(&self) -> &'static str {
        "telemetry"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// The database is where the aggregates live; there is no mode of this
    /// module without it.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }

    /// The Clock port decides "now" — the day buckets and the retention
    /// cutoff — and is what makes time deterministic under test. The
    /// `RateLimiter` port is the abuse control the public ingest route
    /// actually has.
    fn optional(&self) -> &'static [Port] {
        &[Port::Clock, Port::RateLimiter]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["telemetry_events", "telemetry_modules"]
    }

    /// Two aggregate tables, both keyed on the install id, both erased on
    /// request (issue #413).
    ///
    /// **The tension, and the decided answer.** The payload carries no
    /// identifier the venture can tie to a person, so the harness cannot
    /// look a subject up from anything else it stores — and a reader might
    /// conclude these tables hold nobody. They do not hold a person, but
    /// they do hold a key: the install id is **pseudonymous, with no
    /// stored link to a person**, and the person's own client prints it in
    /// `telemetry status`. So an erasure request that supplies the id
    /// deletes exactly their rows — the same person can act on their own
    /// data without the venture ever learning who they are. That makes the
    /// subject the install id and the disposition plain `Erase`;
    /// declaring `none` here would be the lie that breaks the first
    /// erasure request that names a real id.
    ///
    /// **The honest consequence, written down rather than buried.** The id
    /// rotates every [`consent::ROTATION_DAYS`] days and nothing anywhere
    /// stores the link between one id and the next — that is the point of
    /// rotating it — so rows under an id that has already rotated away are
    /// not reachable from a later one. Rotation bounds what an erasure can
    /// reach, and that is the price of not keeping a link between
    /// rotations; the retention purge bounds how long the unreachable tail
    /// outlives the request.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        static SETS: OnceLock<Vec<PersonalDataSet>> = OnceLock::new();
        SETS.get_or_init(|| {
            // The description quotes the rotation interval for the person
            // deciding whether to trust the table, and
            // `PersonalDataSet::description` is `&'static str`, which no
            // compile-time formatting can fill from
            // [`consent::ROTATION_DAYS`]. The sentence is therefore built
            // once, here, and the text leaked — a process-sized handful of
            // bytes — so the interval is written down in the constant
            // alone rather than spelled a second time as a literal that
            // could drift from it.
            let events_description: &'static str = Box::leak(
                format!(
                    "Counts of what your client did — which of this venture's named \
                     events ran, how they ended, in which duration bucket and on which \
                     build — totalled per day under a random install id your client \
                     mints and replaces every {} days. There is no field here that \
                     could hold anything you wrote, named or typed.",
                    consent::ROTATION_DAYS
                )
                .into_boxed_str(),
            );
            vec![
                PersonalDataSet {
                    table: "telemetry_events",
                    subject: "install_id",
                    kind: DataKind::Usage,
                    disposition: Disposition::Erase,
                    description: events_description,
                    redacted: &[],
                    subject_via: None,
                },
                PersonalDataSet {
                    table: "telemetry_modules",
                    subject: "install_id",
                    kind: DataKind::Usage,
                    disposition: Disposition::Erase,
                    description: "Which of this venture's modules your client reported \
                        composing, per day, under the same random install id.",
                    redacted: &[],
                    subject_via: None,
                },
            ]
        })
        .as_slice()
    }

    /// The event a composed venture can subscribe to: an accepted batch.
    fn emits(&self) -> &'static [&'static str] {
        &[handlers::EVENT_RECORDED]
    }

    /// The ingest route is public by design and still not an open write
    /// path: it accepts one thing only — a batch whose every value already
    /// passed a closed grammar, capped by the batch ceiling and the
    /// `RateLimiter` port — and it is how a CLI reports, with no browser and
    /// no session (issue #413, after module-linkedin's reasoning). It stays
    /// a `false` here because `public_writes` feeds the captcha gate in
    /// `route_policy.rs`, and a captcha on a machine-posted batch is not
    /// satisfiable: the honest controls are the ones the route actually
    /// has, and they are all mechanical.
    fn public_writes(&self) -> bool {
        false
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("telemetry", cfg);
        let mut errors = ConfigError::default();

        // Retention: a positive whole number of days, and no more than a
        // century of them. The negated form is the point: `is_ok_and`
        // alone would let a value that does not parse at all — "nonsense",
        // "-5", "12.5" — slip through and silently take the runtime
        // default in the purge, which is a decision the config never
        // made. The upper bound turns a fat-fingered number of smaller
        // units into an error here instead of a date the purge cannot
        // compute (see [`MAX_RETENTION_DAYS`]).
        if let Some(raw) = module
            .get_opt("RETENTION_DAYS")
            .map(|raw| raw.parse::<u32>())
            && !raw.is_ok_and(|days| days > 0 && days <= MAX_RETENTION_DAYS)
        {
            errors.push(format!(
                "telemetry: {} must be a whole number of days from 1 to {}",
                module.key("RETENTION_DAYS"),
                MAX_RETENTION_DAYS
            ));
        }

        // The batch ceiling: a positive integer, never above the schema
        // ceiling of 64. Wider than the grammar would let a venture widen
        // what a single request can carry, which is exactly the bound the
        // ceiling exists to be (issue #413).
        let ceiling = u32::try_from(crate::payload::MAX_EVENTS_PER_BATCH).unwrap_or_default();
        if let Some(raw) = module
            .get_opt("MAX_EVENTS_PER_BATCH")
            .map(|raw| raw.parse::<u32>())
            && !raw.is_ok_and(|max| max > 0 && max <= ceiling)
        {
            errors.push(format!(
                "telemetry: {} must be a positive integer no greater than {}",
                module.key("MAX_EVENTS_PER_BATCH"),
                crate::payload::MAX_EVENTS_PER_BATCH
            ));
        }

        // The declared vocabularies are venture-chosen names, the one part
        // of the store that is not a closed value: an empty or
        // control-character name is a config bug, and a name carrying `|`
        // would ride the bucket key's separator (see the store). Checking
        // here fails the harness at build time, where the fix is made,
        // rather than at the first write.
        for (which, names) in [
            ("event", &self.settings.vocabulary.events),
            ("module", &self.settings.vocabulary.modules),
        ] {
            for name in names {
                let admissible = !name.trim().is_empty()
                    && !name.contains('|')
                    && !name.chars().any(char::is_control);
                if !admissible {
                    errors.push(format!(
                        "telemetry: declared {which} names must be non-empty, with no \
                         `|` and no control characters; {name:?} is not"
                    ));
                }
            }
        }

        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(ctx, self.settings.clone())
    }

    /// The retention purge: buckets in either table whose day is older
    /// than the window are deleted, mirroring the waitlist's scheduled
    /// purge. Idempotent, so running it more often than the cron fires is
    /// harmless.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            let Some(db) = ctx.ports.db.clone() else {
                return Ok(());
            };
            let cfg = ModuleConfig::new("telemetry", &*ctx.config);
            let days = i64::from(cfg.get_u32("RETENTION_DAYS", self.settings.retention_days));
            // "Now" through the Clock port when present, SystemClock
            // otherwise (issue #413).
            let now = handlers::now_of(ctx);
            let cutoff = handlers::day_of(retention_cutoff(now, days)?);
            let deleted = store::purge_older_than(&*db, &cutoff)
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            if deleted > 0 {
                tracing::info!(deleted, cron, "purged telemetry buckets past retention");
            }
            Ok(())
        })
    }
}

/// The oldest day the retention window still keeps: `now` shifted back
/// `days` days. The shift is checked because `days` is an operator's
/// number, reached here without a `validate_config` in between: past the
/// calendar's edge a plain subtraction panics, and a fat-fingered value
/// must cost a failed run with the number named, not a panic (issue
/// #413).
fn retention_cutoff(now: OffsetDateTime, days: i64) -> Result<OffsetDateTime, AnyError> {
    now.checked_sub(time::Duration::days(days)).ok_or_else(|| {
        AnyError::from(format!(
            "telemetry: the retention window of {days} days reaches outside the \
             calendar"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn defaults_fail_closed() {
        let module = Telemetry::new();
        assert!(
            module.settings.vocabulary.events.is_empty(),
            "no declared events"
        );
        assert!(
            module.settings.vocabulary.modules.is_empty(),
            "no declared modules"
        );
        assert_eq!(
            module.settings.vocabulary.max_events,
            crate::payload::MAX_EVENTS_PER_BATCH
        );
        assert_eq!(module.settings.retention_days, 180);
        assert_eq!(module.settings.opt_out_command, "fz telemetry off");
        assert_eq!(module.settings.status_command, "fz telemetry status");
    }

    #[test]
    fn the_builder_sets_the_settings_it_names() {
        let module = Telemetry::new()
            .events(["run", "report"])
            .modules(["telemetry"])
            .retention_days(90)
            .max_events_per_batch(8)
            .opt_out_command("acme off")
            .status_command("acme status");
        assert_eq!(module.settings.vocabulary.events, ["run", "report"]);
        assert_eq!(module.settings.vocabulary.modules, ["telemetry"]);
        assert_eq!(module.settings.retention_days, 90);
        assert_eq!(module.settings.vocabulary.max_events, 8);
        assert_eq!(module.settings.opt_out_command, "acme off");
        assert_eq!(module.settings.status_command, "acme status");
    }

    #[test]
    fn module_metadata() {
        let module = Telemetry::new();
        assert_eq!(module.name(), "telemetry");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(module.requires(), [Port::Db]);
        assert_eq!(module.optional(), [Port::Clock, Port::RateLimiter]);
        assert_eq!(module.tables(), ["telemetry_events", "telemetry_modules"]);
        assert_eq!(module.emits(), ["telemetry.recorded"]);
        assert!(!module.public_writes());
        assert!(
            module.migrations().postgres.is_empty(),
            "sqlite migrations only"
        );
        assert_eq!(module.migrations().sqlite.len(), 1);
    }

    #[test]
    fn a_widened_batch_ceiling_is_clamped_to_the_schema_ceiling() {
        let module = Telemetry::new().max_events_per_batch(1_000);
        assert_eq!(
            module.settings.vocabulary.max_events,
            crate::payload::MAX_EVENTS_PER_BATCH,
            "the ceiling is part of the grammar and cannot be widened"
        );
    }

    #[test]
    fn valid_config_passes_and_invalid_config_names_its_keys() {
        let module = Telemetry::new();
        let ok: Arc<dyn Config> = Arc::new(cratefield_core::MapConfig::from_pairs([
            ("TELEMETRY_RETENTION_DAYS".to_owned(), "30".to_owned()),
            ("TELEMETRY_MAX_EVENTS_PER_BATCH".to_owned(), "16".to_owned()),
        ]));
        assert!(module.validate_config(&*ok).is_ok());

        let bad: Arc<dyn Config> = Arc::new(cratefield_core::MapConfig::from_pairs([
            ("TELEMETRY_RETENTION_DAYS".to_owned(), "0".to_owned()),
            ("TELEMETRY_MAX_EVENTS_PER_BATCH".to_owned(), "65".to_owned()),
        ]));
        let errors = module
            .validate_config(&*bad)
            .expect_err("both keys are invalid");
        let text = format!("{errors}");
        assert!(text.contains("TELEMETRY_RETENTION_DAYS"), "{text}");
        assert!(text.contains("TELEMETRY_MAX_EVENTS_PER_BATCH"), "{text}");
    }

    /// A value that does not parse at all must be rejected, not silently
    /// exchanged for the runtime default: the config said something, and
    /// "nonsense" is not the 180 days nobody chose.
    #[test]
    fn a_retention_that_is_not_a_whole_number_of_days_is_rejected() {
        let module = Telemetry::new();
        for raw in ["nonsense", "-5", "12.5", "36501"] {
            let bad: Arc<dyn Config> = Arc::new(cratefield_core::MapConfig::from_pairs([(
                "TELEMETRY_RETENTION_DAYS".to_owned(),
                raw.to_owned(),
            )]));
            let errors = module
                .validate_config(&*bad)
                .expect_err("the value is not a usable number of days");
            let text = format!("{errors}");
            assert!(
                text.contains("TELEMETRY_RETENTION_DAYS"),
                "{raw}: the error must name the variable: {text}"
            );
        }
    }

    /// The declared vocabularies are the one venture-chosen part of the
    /// store, so they must still be names: a `|` would ride the bucket
    /// key's separator, an empty name is not a name, and a control
    /// character is a payload with a newline in it.
    #[test]
    fn declared_names_must_be_names() {
        let no_config: Arc<dyn Config> = Arc::new(cratefield_core::MapConfig::from_pairs(Vec::<(
            String,
            String,
        )>::new(
        )));

        let separator = Telemetry::new().events(["run|ok"]);
        let errors = separator
            .validate_config(&*no_config)
            .expect_err("a `|` would ride the bucket key's separator");
        assert!(format!("{errors}").contains("run|ok"), "{errors}");

        let blank = Telemetry::new().events([""]);
        let errors = blank
            .validate_config(&*no_config)
            .expect_err("an empty name is not a name");
        assert!(format!("{errors}").contains("non-empty"), "{errors}");

        let control = Telemetry::new().modules(["telemetry\n"]);
        let errors = control
            .validate_config(&*no_config)
            .expect_err("a control character is not a name");
        assert!(
            format!("{errors}").contains("control characters"),
            "{errors}"
        );
    }

    /// The builder cannot return an error, so an impossible value is
    /// narrowed to the nearest workable one — and the doc comment says so.
    /// Zero retention deletes every bucket the day it is written; a zero
    /// batch ceiling is a collector that rejects everything for exceeding
    /// a ceiling of nothing; past `MAX_RETENTION_DAYS` the purge's date
    /// arithmetic cannot run.
    #[test]
    fn builder_zeroes_and_oversized_values_are_narrowed_not_honoured() {
        let module = Telemetry::new().retention_days(0).max_events_per_batch(0);
        assert_eq!(module.settings.retention_days, 1);
        assert_eq!(module.settings.vocabulary.max_events, 1);

        let module = Telemetry::new().retention_days(u32::MAX);
        assert_eq!(module.settings.retention_days, MAX_RETENTION_DAYS);
    }

    /// The purge's shift is checked: an operator number past the
    /// calendar's edge — the size of a fat-fingered milliseconds value —
    /// comes back as an error naming the problem, not a panic on every
    /// cron fire.
    #[test]
    fn an_impossible_retention_is_an_error_not_a_panic() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
        let sane = retention_cutoff(now, 30).expect("a month is inside the calendar");
        assert_eq!(
            handlers::day_of(sane),
            handlers::day_of(now - time::Duration::days(30))
        );
        assert!(
            retention_cutoff(now, 4_400_000).is_err(),
            "past the calendar's edge the cutoff must error, not panic"
        );
    }
}
