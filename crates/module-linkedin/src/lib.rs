//! `fz-module-linkedin`: run a LinkedIn Company Page from the harness
//! (issues #4 to #17).
//!
//! ```no_run
//! use fz_module_linkedin::Linkedin;
//!
//! let module = Linkedin::new()
//!     .api_version("202608")
//!     .default_visibility("PUBLIC")
//!     .refresh_lead_days(7);
//! ```
//!
//! **Publishing is never inline.** A create writes a row and answers `202`;
//! the five-minute cron claims it with a lease, posts it, then confirms the
//! post reached `PUBLISHED` before saying so. LinkedIn has no idempotency key
//! on create, so a publish whose response is lost is reconciled through the
//! author finder rather than retried blind.
//!
//! **What LinkedIn does not allow** is documented rather than worked around:
//! a published post can only change in four organic fields, no endpoint
//! creates a showcase page, and no documented endpoint writes a page's logo.
//! See `README.md`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod client;
mod handlers;
mod imagehdr;
mod images;
mod little;
mod oauth;
mod pages;
mod posts;
mod scheduled;
mod store;
mod token;
mod tokens;
mod urn;

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DataKind, Disposition, EventHandler, EventName,
    Migrations, Module, ModuleConfig, ModuleContext, PersonalDataSet, Port, SqlMigration,
};
use std::sync::{Arc, OnceLock};

pub use handlers::{
    EVENT_CONNECTED, EVENT_PAGES_SYNCED, EVENT_POST_FAILED, EVENT_POST_PUBLISHED,
    EVENT_TOKEN_EXPIRED, EVENT_TOKEN_EXPIRING, EVENT_TOKEN_REFRESHED,
};
pub use little::{escape as escape_commentary, hashtag, mention};
pub use scheduled::{CRON_DAILY_HINT, CRON_PUBLISHER_HINT};

/// The module's one migration: six tables in the portable SQL subset
/// (ADR 0004).
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
    transactional: true,
};

/// LinkedIn's newest Marketing version at the time of writing. Pinned, never
/// floating: an unversioned call is an error and a sunset version is a hard
/// failure, so moving this is a deliberate change with a changelog to read.
pub const DEFAULT_API_VERSION: &str = "202608";

/// The four scopes the module needs, compiled in rather than configured:
/// changing the scope set invalidates every token LinkedIn has issued us, so
/// it is a code change plus a re-consent, not a config flag. No `openid` or
/// `profile`: the person URN arrives with the ACL listing, and a second API
/// product on the app would collide with Community Management access.
pub const SCOPES: [&str; 4] = [
    "rw_organization_admin",
    "r_organization_admin",
    "r_organization_social",
    "w_organization_social",
];

/// The visibility values LinkedIn documents for `MemberNetworkVisibility`.
/// `CONNECTIONS` is a member-network concept and will be refused for an
/// organization author, but the schema does not say so, so the module
/// validates the enum and lets LinkedIn rule on the rest.
const VISIBILITIES: [&str; 4] = ["PUBLIC", "LOGGED_IN", "CONNECTIONS", "CONTAINER"];

/// Runs a LinkedIn Company Page: connect, post, edit, delete, upload media.
pub struct Linkedin {
    settings: handlers::Settings,
    /// Parked at `router()` so the `linkedin.connected` handler has a context
    /// to work with. `Module::events()` is called at build time, before any
    /// context exists, which is the same problem `cratefield-module-email-signup`
    /// solves the same way.
    ctx_cell: Arc<OnceLock<Arc<ModuleContext>>>,
}

impl Default for Linkedin {
    fn default() -> Self {
        Self::new()
    }
}

impl Linkedin {
    /// Defaults: the pinned API version, `PUBLIC` posts, a 7-day refresh
    /// lead, an 8 MiB image ceiling and a 10-minute publish lease.
    pub fn new() -> Self {
        Self {
            settings: handlers::Settings {
                api_version: DEFAULT_API_VERSION.to_owned(),
                default_visibility: "PUBLIC".to_owned(),
                refresh_lead_days: 7,
                max_image_bytes: 8 * 1024 * 1024,
                publish_lease_secs: 600,
                asset_poll_secs: 60,
                connect_ttl_secs: 600,
            },
            ctx_cell: Arc::new(OnceLock::new()),
        }
    }

    /// The `LinkedIn-Version` header value (`YYYYMM`).
    #[must_use]
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.settings.api_version = version.into();
        self
    }

    /// Default post visibility when a create does not name one.
    #[must_use]
    pub fn default_visibility(mut self, visibility: impl Into<String>) -> Self {
        self.settings.default_visibility = visibility.into();
        self
    }

    /// Refresh an access token this many days before it expires.
    #[must_use]
    pub fn refresh_lead_days(mut self, days: u32) -> Self {
        self.settings.refresh_lead_days = days;
        self
    }

    /// Largest image body accepted by the upload route. The route overrides
    /// core's 64 KiB `/v1/*` body cap with this value.
    #[must_use]
    pub fn max_image_bytes(mut self, bytes: usize) -> Self {
        self.settings.max_image_bytes = bytes;
        self
    }

    /// How long a publish lease is honoured before another pass may reclaim
    /// the row (and reconcile it against LinkedIn first).
    #[must_use]
    pub fn publish_lease_secs(mut self, secs: i64) -> Self {
        self.settings.publish_lease_secs = secs;
        self
    }
}

impl Module for Linkedin {
    fn name(&self) -> &'static str {
        "linkedin"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // Defer is required, not optional: EventBus::emit_in needs a Scope and
        // Module::scheduled is handed none, so cron work builds a synthetic
        // Scope from this port. Under NoopDefer every scheduled event would be
        // dropped with a warning instead of reaching a handler.
        &[
            Port::Db,
            Port::HttpClient,
            Port::Clock,
            Port::Signer,
            Port::IdGen,
            Port::Defer,
        ]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::RateLimiter]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[
            "linkedin_accounts",
            "linkedin_pages",
            "linkedin_posts",
            "linkedin_assets",
            "linkedin_oauth_states",
            "linkedin_request_budget",
        ]
    }

    /// One person in six tables, and two columns an export must never copy
    /// (issue #265).
    ///
    /// The person is the LinkedIn member who connected the venture — one
    /// row of `linkedin_accounts`, keyed on `person_urn`, LinkedIn's own
    /// identifier for them. Everything else this module stores is
    /// organisational: pages belong to companies, posts and the images
    /// attached to them are the venture's own publications on those pages,
    /// and the last two tables are a connect attempt in flight and a counter
    /// of API calls. Those five are declared `none` **with** their reason,
    /// because a reader cannot tell an omission from an oversight, and four
    /// of them would otherwise look exactly like the omission this rule
    /// exists to catch.
    ///
    /// `access_token` and `refresh_token` are redacted. They are LinkedIn
    /// bearer credentials in the clear — whoever holds one can post as the
    /// venture until it expires — and `GET /v1/privacy/export` is a
    /// `SELECT *` written to a file people forward, so a token in the row
    /// would be a token in that file (ADR 0015). Naming them with
    /// `[redacted]` rather than dropping them keeps the answer honest: they
    /// are held, they are not handed over, and erasing the row still takes
    /// them with it.
    ///
    /// `person_urn` is `NULL` until the first page sync learns it, so a
    /// connection that never synced is not reachable by subject. That is
    /// the truth about the row rather than a reason to invent a key for it.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet {
                table: "linkedin_accounts",
                subject: "person_urn",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "The LinkedIn member who connected this venture's account: \
                              LinkedIn's own identifier for you, what you gave us permission to \
                              do, when that permission runs out, and whether the connection is \
                              still live.",
                redacted: &["access_token", "refresh_token"],
            },
            PersonalDataSet::none(
                "linkedin_pages",
                "The company and showcase pages the connected account administers: each page's \
                 name, its LinkedIn identifier and what may be posted to it. It describes \
                 organisations, not people.",
            ),
            PersonalDataSet::none(
                "linkedin_posts",
                "The posts this venture has published, or is about to publish, on its own \
                 company pages: the wording, when it went out and whether LinkedIn accepted it. \
                 It is the venture's publication record, filed under a page.",
            ),
            PersonalDataSet::none(
                "linkedin_assets",
                "Images uploaded to LinkedIn for those posts, with their size and alt text. \
                 Filed under the page they were uploaded for; no column in it names a person.",
            ),
            PersonalDataSet::none(
                "linkedin_oauth_states",
                "One row per connect attempt still in progress: an opaque identifier and the \
                 minute it stops being valid. It is created before anybody has signed in and \
                 deleted the moment it is used, and it names nobody at any point.",
            ),
            PersonalDataSet::none(
                "linkedin_request_budget",
                "How many requests this deployment has spent against LinkedIn's daily cap, one \
                 row per day. A count of what we did, not of who anybody is.",
            ),
        ];
        SETS
    }

    fn emits(&self) -> &'static [&'static str] {
        &[
            EVENT_CONNECTED,
            EVENT_PAGES_SYNCED,
            EVENT_POST_PUBLISHED,
            EVENT_POST_FAILED,
            EVENT_TOKEN_REFRESHED,
            EVENT_TOKEN_EXPIRING,
            EVENT_TOKEN_EXPIRED,
        ]
    }

    fn public_writes(&self) -> bool {
        // The OAuth callback is the only public route. It writes, but it is
        // not an open write path: it is reachable only with a signed,
        // single-use state this module issued, which is the same shape as an
        // email confirm link rather than an anonymous form post.
        false
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("linkedin", cfg);
        let mut errors = ConfigError::default();

        for key in ["CLIENT_ID", "CLIENT_SECRET"] {
            match cfg.get(&module.key(key)) {
                Some(value) if !value.trim().is_empty() => {}
                Some(_) => errors.push(format!("linkedin: {} must not be empty", module.key(key))),
                None => errors.push(format!(
                    "linkedin: {} is required (a Worker secret, never wrangler.toml)",
                    module.key(key)
                )),
            }
        }

        match cfg.get(&module.key("TOKEN_KEY")) {
            Some(raw) => {
                if token::SealKey::from_config(&raw, 1).is_err() {
                    errors.push(format!(
                        "linkedin: {} must be {} bytes of base64",
                        module.key("TOKEN_KEY"),
                        token::KEY_LEN
                    ));
                }
            }
            None => errors.push(format!(
                "linkedin: {} is required ({} random bytes, base64)",
                module.key("TOKEN_KEY"),
                token::KEY_LEN
            )),
        }

        if let Some(raw) = cfg.get(&module.key("TOKEN_KEY_ID"))
            && raw.parse::<u8>().is_err()
        {
            errors.push(format!(
                "linkedin: {} must be an integer 0-255, got {raw:?}",
                module.key("TOKEN_KEY_ID")
            ));
        }

        if let Some(raw) = cfg.get(&module.key("API_VERSION"))
            && !(raw.len() == 6
                && raw.starts_with("20")
                && raw.bytes().all(|b| b.is_ascii_digit())
                && matches!(raw[4..].parse::<u8>(), Ok(1..=12)))
        {
            errors.push(format!(
                "linkedin: {} must be a LinkedIn version in YYYYMM form, got {raw:?}",
                module.key("API_VERSION")
            ));
        }

        if let Some(raw) = cfg.get(&module.key("REDIRECT_URI"))
            && !raw.starts_with("https://")
            && !raw.starts_with("http://localhost")
            && !raw.starts_with("http://127.0.0.1")
        {
            errors.push(format!(
                "linkedin: {} must be https (or a localhost URL for wrangler dev), got {raw:?}",
                module.key("REDIRECT_URI")
            ));
        }

        if let Some(raw) = cfg.get(&module.key("DEFAULT_VISIBILITY"))
            && !VISIBILITIES.contains(&raw.as_str())
        {
            errors.push(format!(
                "linkedin: {} must be one of {}, got {raw:?}",
                module.key("DEFAULT_VISIBILITY"),
                VISIBILITIES.join(", ")
            ));
        }

        for key in ["REFRESH_LEAD_DAYS", "MAX_IMAGE_BYTES", "PUBLISH_LEASE_SECS"] {
            match cfg.get(&module.key(key)).map(|raw| raw.parse::<u64>()) {
                Some(Ok(value)) if value > 0 => {}
                Some(_) => errors.push(format!(
                    "linkedin: {} must be a positive integer",
                    module.key(key)
                )),
                None => {}
            }
        }

        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let shared = Arc::new(ctx);
        // First build wins; on Workers every request rebuilds the router with
        // equivalent ports, so the parked context stays valid.
        let _ = self.ctx_cell.set(Arc::clone(&shared));
        handlers::router(shared, self.settings.clone())
    }

    /// The module listens to its own `linkedin.connected`, so building the
    /// page directory does not have to be wired into the OAuth callback.
    /// Connecting stays one job and syncing stays another.
    fn events(&self) -> Vec<(EventName, EventHandler)> {
        let cell = Arc::clone(&self.ctx_cell);
        let base = self.settings.clone();
        let handler: EventHandler = Arc::new(move |scope, _payload| {
            let cell = Arc::clone(&cell);
            let base = base.clone();
            let scope = scope.clone();
            Box::pin(async move {
                let Some(ctx) = cell.get().cloned() else {
                    tracing::warn!("linkedin.connected fired before the router was built");
                    return Ok(());
                };
                let settings = handlers::settings_of(&ctx, &base);
                match pages::sync(&ctx, &settings, &scope).await {
                    Ok(outcome) => tracing::info!(
                        pages = outcome.pages,
                        showcases = outcome.showcases,
                        "page directory built after connecting"
                    ),
                    Err(trouble) => tracing::warn!(
                        trouble = ?trouble,
                        "could not build the page directory after connecting"
                    ),
                }
                Ok(())
            })
        });
        vec![(EVENT_CONNECTED.to_owned(), handler)]
    }

    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        let settings = self.settings.clone();
        Box::pin(async move { scheduled::run(ctx, &settings, cron).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    fn valid_config() -> Vec<(String, String)> {
        vec![
            ("LINKEDIN_CLIENT_ID".to_owned(), "client".to_owned()),
            ("LINKEDIN_CLIENT_SECRET".to_owned(), "secret".to_owned()),
            (
                "LINKEDIN_TOKEN_KEY".to_owned(),
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_owned(),
            ),
        ]
    }

    fn config(pairs: Vec<(String, String)>) -> MapConfig {
        MapConfig::from_pairs(pairs)
    }

    #[test]
    fn declares_its_ports_tables_and_events() {
        let module = Linkedin::new();
        assert_eq!(module.name(), "linkedin");
        assert!(
            module.requires().contains(&Port::Defer),
            "cron cannot emit without Defer"
        );
        assert!(module.requires().contains(&Port::HttpClient));
        assert_eq!(module.optional(), [Port::RateLimiter]);
        assert_eq!(module.tables().len(), 6);
        assert_eq!(module.emits().len(), 7);
        assert!(!module.public_writes());
    }

    #[test]
    fn accepts_a_valid_configuration() {
        assert!(
            Linkedin::new()
                .validate_config(&config(valid_config()))
                .is_ok()
        );
    }

    #[test]
    fn reports_every_missing_key_at_once() {
        let error = Linkedin::new()
            .validate_config(&config(Vec::new()))
            .expect_err("empty config is invalid");
        assert_eq!(error.problems.len(), 3, "{error}");
        assert!(error.to_string().contains("LINKEDIN_CLIENT_ID"));
        assert!(error.to_string().contains("LINKEDIN_CLIENT_SECRET"));
        assert!(error.to_string().contains("LINKEDIN_TOKEN_KEY"));
    }

    #[test]
    fn rejects_a_token_key_that_is_not_32_bytes() {
        let mut pairs = valid_config();
        pairs.retain(|(key, _)| key != "LINKEDIN_TOKEN_KEY");
        pairs.push(("LINKEDIN_TOKEN_KEY".to_owned(), "c2hvcnQ=".to_owned()));
        let error = Linkedin::new()
            .validate_config(&config(pairs))
            .expect_err("short key is invalid");
        assert!(error.to_string().contains("32 bytes of base64"), "{error}");
    }

    #[test]
    fn rejects_an_unusable_api_version() {
        for bad in ["2026-08", "202699", "20268", "latest"] {
            let mut pairs = valid_config();
            pairs.push(("LINKEDIN_API_VERSION".to_owned(), bad.to_owned()));
            assert!(
                Linkedin::new().validate_config(&config(pairs)).is_err(),
                "{bad} was accepted"
            );
        }
        let mut pairs = valid_config();
        pairs.push(("LINKEDIN_API_VERSION".to_owned(), "202601".to_owned()));
        assert!(Linkedin::new().validate_config(&config(pairs)).is_ok());
    }

    #[test]
    fn rejects_a_visibility_linkedin_does_not_define() {
        let mut pairs = valid_config();
        pairs.push((
            "LINKEDIN_DEFAULT_VISIBILITY".to_owned(),
            "FRIENDS".to_owned(),
        ));
        assert!(Linkedin::new().validate_config(&config(pairs)).is_err());
    }

    #[test]
    fn rejects_a_plaintext_redirect_uri_outside_localhost() {
        let mut pairs = valid_config();
        pairs.push((
            "LINKEDIN_REDIRECT_URI".to_owned(),
            "http://example.com/cb".to_owned(),
        ));
        assert!(Linkedin::new().validate_config(&config(pairs)).is_err());

        let mut pairs = valid_config();
        pairs.push((
            "LINKEDIN_REDIRECT_URI".to_owned(),
            "http://localhost:8787/v1/linkedin/callback".to_owned(),
        ));
        assert!(Linkedin::new().validate_config(&config(pairs)).is_ok());
    }
}
