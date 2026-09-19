//! `cratefield-module-changelog`: a project's releases, mirrored into the
//! venture's own database and served over an API.
//!
//! ```no_run
//! use cratefield_module_changelog::Changelog;
//!
//! let module = Changelog::new()
//!     .repo("owner/name")
//!     .locale("en");
//! ```
//!
//! **The read path never leaves the database.** A refresh pulls GitHub (the
//! Releases API, or a Keep-a-Changelog file) and stores each release —
//! byte-for-byte from the Releases API; the `CHANGELOG.md` parser normalises
//! line endings and trims section edges. `GET /` and `GET /{version}` then
//! serve only what is stored, so GitHub being down, rate-limited or
//! misconfigured costs a refresh, not the changelog. Before the first
//! refresh the list is simply empty — a 200 with no releases, never an
//! error and never an empty error page.
//!
//! **A refresh rewrites nothing it does not have to.** Each fetch is
//! compared against the stored rows field by field: a release upstream has
//! not touched keeps its `updated_at`, and a fetch that saw the whole list
//! alone may prune rows upstream deleted — a walk that hit the page cap
//! applies what it fetched and prunes nothing. There is no LLM in this
//! module — rewriting and translation arrive later behind a `TextModel`
//! port that does not exist yet, and until then every response reports
//! `rendering.style = "original"`.
//!
//! See `README.md` for the configuration keys and the response shapes.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod cache;
mod handlers;
mod source;
mod store;

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext,
    PersonalDataSet, Port, SqlMigration,
};
use std::sync::Arc;

/// The one migration: `changelog_release` and `changelog_source`, in the
/// portable SQL subset (ADR 0004).
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// Where the release notes come from. `github-releases` reads the Releases
/// API (titles, bodies, prerelease and draft flags, an etag); `changelog-md`
/// reads one Keep-a-Changelog file out of the repository and splits it into
/// sections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SourceKind {
    /// `/repos/{owner}/{name}/releases` — the default.
    #[default]
    GithubReleases,
    /// `/repos/{owner}/{name}/contents/{path}` read raw, sectioned by `## `
    /// headings.
    ChangelogMd,
}

impl SourceKind {
    /// The value the `CHANGELOG_SOURCE` configuration key spells it with —
    /// also what `source.kind` reports in every response.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GithubReleases => "github-releases",
            Self::ChangelogMd => "changelog-md",
        }
    }

    /// Reads the `CHANGELOG_SOURCE` value. `None` for anything else, so a
    /// typo is a configuration error rather than a silent fallback.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "github-releases" => Some(Self::GithubReleases),
            "changelog-md" => Some(Self::ChangelogMd),
            _ => None,
        }
    }
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The module's settings as composed: the builder's values, overlaid with
/// the `CHANGELOG_*` configuration keys per request ([`source::resolved`]).
/// Configuration wins when a key is set, so a venture that only sets
/// configuration and composes [`Changelog::new()`] is complete.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) repo: Option<String>,
    pub(crate) source: SourceKind,
    pub(crate) path: String,
    pub(crate) git_ref: Option<String>,
    pub(crate) token: Option<String>,
    pub(crate) api_base: String,
    pub(crate) include_prereleases: bool,
    pub(crate) include_drafts: bool,
    pub(crate) locale: String,
    pub(crate) cache_ttl_secs: u64,
}

impl Settings {
    /// The `owner` and `name` of the configured repository, or `None` when
    /// `CHANGELOG_REPO` is unset or malformed.
    pub(crate) fn repo_parts(&self) -> Option<(&str, &str)> {
        let (owner, name) = self.repo.as_deref()?.split_once('/')?;
        Some((owner.trim(), name.trim()))
    }

    /// The kind upstream, as responses and problems spell it.
    pub(crate) fn kind(&self) -> &'static str {
        self.source.as_str()
    }

    /// The stable identity of the configured source — the key every
    /// `changelog_release` and `changelog_source` row is filed under.
    /// Changing the configuration changes the identity, so yesterday's rows
    /// cannot be silently served as today's source.
    pub(crate) fn source_id(&self) -> String {
        let (owner, name) = self.repo_parts().unwrap_or(("", ""));
        match self.source {
            SourceKind::GithubReleases => format!("{}:{owner}/{name}", self.source.as_str()),
            SourceKind::ChangelogMd => format!(
                "{}:{owner}/{name}:{}@{}",
                self.source.as_str(),
                self.path,
                self.git_ref.as_deref().unwrap_or("default"),
            ),
        }
    }
}

/// A GitHub repository segment: GitHub allows letters, digits, `.`, `-` and
/// `_`, up to 100 bytes.
pub(crate) fn is_repo_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 100
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// `owner/name`, both segments well-formed.
pub(crate) fn is_repo(repo: &str) -> bool {
    match repo.split_once('/') {
        Some((owner, name)) => is_repo_segment(owner) && is_repo_segment(name),
        None => false,
    }
}

/// A changelog module: mirror a project's releases into the venture's own
/// database and serve them.
#[derive(Debug, Clone)]
pub struct Changelog {
    settings: Settings,
}

impl Default for Changelog {
    fn default() -> Self {
        Self::new()
    }
}

impl Changelog {
    /// Defaults: the GitHub Releases API at `api.github.com`, anonymous,
    /// `CHANGELOG.md` for a `changelog-md` source, original notes in `en`,
    /// drafts and prereleases excluded, a 60-second read cache. Without
    /// [`Changelog::repo`] or a configured `CHANGELOG_REPO` the module has
    /// no source: reads serve an empty list and refresh explains what is
    /// missing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: Settings {
                repo: None,
                source: SourceKind::default(),
                path: "CHANGELOG.md".to_owned(),
                git_ref: None,
                token: None,
                api_base: "https://api.github.com".to_owned(),
                include_prereleases: false,
                include_drafts: false,
                locale: "en".to_owned(),
                cache_ttl_secs: 60,
            },
        }
    }

    /// The repository to mirror, `owner/name`. `CHANGELOG_REPO` overrides
    /// this when set.
    #[must_use]
    pub fn repo(mut self, repo: impl Into<String>) -> Self {
        self.settings.repo = Some(repo.into());
        self
    }

    /// Which upstream to read: [`SourceKind::GithubReleases`] (the default)
    /// or [`SourceKind::ChangelogMd`]. `CHANGELOG_SOURCE` overrides this
    /// when set.
    #[must_use]
    pub fn source(mut self, source: SourceKind) -> Self {
        self.settings.source = source;
        self
    }

    /// The file a `changelog-md` source reads. `CHANGELOG_PATH` overrides
    /// this when set.
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.settings.path = path.into();
        self
    }

    /// The git ref a `changelog-md` source reads from; unset means the
    /// repository's default branch. `CHANGELOG_REF` overrides this when set.
    #[must_use]
    pub fn git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.settings.git_ref = Some(git_ref.into());
        self
    }

    /// A GitHub token, raising the rate limit above anonymous. Stored in
    /// settings only; it is read from configuration in production, where it
    /// belongs to the secret store rather than the binary.
    /// `CHANGELOG_TOKEN` overrides this when set.
    #[must_use]
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.settings.token = Some(token.into());
        self
    }

    /// Where GitHub's API lives, so tests and GitHub Enterprise point
    /// elsewhere. `CHANGELOG_API_BASE` overrides this when set.
    #[must_use]
    pub fn api_base(mut self, api_base: impl Into<String>) -> Self {
        self.settings.api_base = api_base.into();
        self
    }

    /// Mirror prereleases too. `CHANGELOG_INCLUDE_PRERELEASES` overrides
    /// this when set.
    #[must_use]
    pub fn include_prereleases(mut self, include: bool) -> Self {
        self.settings.include_prereleases = include;
        self
    }

    /// Mirror drafts too. `CHANGELOG_INCLUDE_DRAFTS` overrides this when
    /// set.
    #[must_use]
    pub fn include_drafts(mut self, include: bool) -> Self {
        self.settings.include_drafts = include;
        self
    }

    /// The locale the original notes are written in, reported in
    /// `rendering.locale`. `CHANGELOG_LOCALE` overrides this when set.
    #[must_use]
    pub fn locale(mut self, locale: impl Into<String>) -> Self {
        self.settings.locale = locale.into();
        self
    }

    /// The `KeyValue` read cache's TTL in seconds; `0` disables the cache
    /// entirely. `CHANGELOG_CACHE_TTL_SECONDS` overrides this when set.
    #[must_use]
    pub fn cache_ttl_secs(mut self, secs: u64) -> Self {
        self.settings.cache_ttl_secs = secs;
        self
    }
}

impl Module for Changelog {
    fn name(&self) -> &'static str {
        "changelog"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // HttpClient is for the refresh path only; the reads never need it,
        // but a changelog that cannot be refreshed is not a mirror, so it is
        // required rather than optional.
        &[Port::Db, Port::HttpClient, Port::Clock]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::KeyValue]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["changelog_release", "changelog_source"]
    }

    /// A changelog holds nothing about a person — it holds what a project
    /// published, and a project is not a person.
    ///
    /// Declared rather than left silent: an export that skipped these tables
    /// and an export that had never heard of them look identical from the
    /// outside, and only one of them is a decision. The reason below is what
    /// `GET /v1/privacy/manifest` publishes, so it is written for the person
    /// reading it.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet::none(
                "changelog_release",
                "The releases this venture mirrors from its project's repository, one row per \
                 version: the author's own title and markdown body, a link, and when it was \
                 published. It describes software, not people — no column in it names a person.",
            ),
            PersonalDataSet::none(
                "changelog_source",
                "One row per configured source, recording how the last mirror went: an etag, a \
                 cache generation, a timestamp and a status. It is bookkeeping about a fetch, \
                 and it names nobody.",
            ),
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
        let module = ModuleConfig::new("changelog", cfg);
        let mut errors = ConfigError::default();

        match cfg.get(&module.key("REPO")) {
            Some(repo) if is_repo(repo.trim()) => {}
            Some(repo) => errors.push(format!(
                "changelog: {} must be `owner/name` (letters, digits, '.', '-', '_'), got {repo:?}",
                module.key("REPO"),
            )),
            None => errors.push(format!(
                "changelog: {} is required (the repository whose releases to mirror)",
                module.key("REPO"),
            )),
        }

        if let Some(raw) = cfg.get(&module.key("SOURCE"))
            && SourceKind::parse(&raw).is_none()
        {
            errors.push(format!(
                "changelog: {} must be `github-releases` or `changelog-md`, got {raw:?}",
                module.key("SOURCE"),
            ));
        }

        if let Some(raw) = cfg.get(&module.key("CACHE_TTL_SECONDS"))
            && raw.trim().parse::<u64>().is_err()
        {
            errors.push(format!(
                "changelog: {} must be a whole number of seconds, got {raw:?}",
                module.key("CACHE_TTL_SECONDS"),
            ));
        }

        if let Some(base) = cfg.get(&module.key("API_BASE"))
            && !base.starts_with("https://")
            && !base.starts_with("http://")
        {
            errors.push(format!(
                "changelog: {} must be an http(s) URL, got {base:?}",
                module.key("API_BASE"),
            ));
        }

        if let Some(locale) = cfg.get(&module.key("LOCALE"))
            && locale.trim().is_empty()
        {
            errors.push(format!(
                "changelog: {} must not be empty (it is reported in `rendering.locale`)",
                module.key("LOCALE"),
            ));
        }

        errors.into_result()
    }

    /// Problems the module can find in **itself**: how the venture composed
    /// it in code, checked against nothing but its own rules. No network, no
    /// configuration — the deploy config does not exist at `fz doctor` time.
    /// Each problem names the source it was found on and the knob to turn.
    fn self_check(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let source = self.settings.source.as_str();
        if let Some(repo) = &self.settings.repo
            && !is_repo(repo.trim())
        {
            problems.push(format!(
                "changelog: the composed repo is not `owner/name`, so refresh will refuse to \
                 run (source {source})"
            ));
        }
        if self.settings.source == SourceKind::ChangelogMd && self.settings.path.trim().is_empty() {
            problems.push(format!(
                "changelog: source {source} needs a file to read — set `.path(..)` or \
                 CHANGELOG_PATH"
            ));
        }
        problems
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(Arc::new(ctx), self.settings.clone())
    }

    fn surface(&self) -> cratefield_core::Surface {
        handlers::surface()
    }

    /// Every wired cron pulls once. A pull is cheap — an etag'd GET that
    /// answers 304 when nothing moved — and any failure is logged, never
    /// raised: a failed refresh costs fresh data for one interval, not the
    /// deployment.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        let base = self.settings.clone();
        Box::pin(async move {
            let settings = source::resolved(ctx, &base);
            match source::refresh(ctx, &settings).await {
                Ok(report) if report.not_modified => {
                    tracing::debug!(cron = %cron, "changelog: upstream not modified");
                }
                Ok(report) => tracing::info!(
                    cron = %cron,
                    fetched = report.fetched,
                    inserted = report.inserted,
                    updated = report.updated,
                    removed = report.removed,
                    "changelog refreshed"
                ),
                Err(trouble) => {
                    tracing::warn!(cron = %cron, trouble = ?trouble, "scheduled changelog refresh failed");
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    fn config(pairs: &[(&str, &str)]) -> MapConfig {
        MapConfig::from_pairs(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
        )
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let module = Changelog::new();
        assert_eq!(module.name(), "changelog");
        assert_eq!(module.requires(), [Port::Db, Port::HttpClient, Port::Clock]);
        assert_eq!(module.optional(), [Port::KeyValue]);
        assert_eq!(module.settings.source, SourceKind::GithubReleases);
        assert_eq!(module.settings.path, "CHANGELOG.md");
        assert_eq!(module.settings.api_base, "https://api.github.com");
        assert_eq!(module.settings.locale, "en");
        assert_eq!(module.settings.cache_ttl_secs, 60);
        assert!(!module.settings.include_prereleases);
        assert!(!module.settings.include_drafts);
        assert!(module.settings.repo.is_none());
    }

    #[test]
    fn the_source_id_changes_when_the_configuration_does() {
        let mut settings = Changelog::new().repo("owner/name").settings;
        assert_eq!(settings.source_id(), "github-releases:owner/name");
        settings.source = SourceKind::ChangelogMd;
        assert_eq!(
            settings.source_id(),
            "changelog-md:owner/name:CHANGELOG.md@default"
        );
        settings.git_ref = Some("main".to_owned());
        assert_eq!(
            settings.source_id(),
            "changelog-md:owner/name:CHANGELOG.md@main"
        );
        settings.path = "docs/CHANGES.md".to_owned();
        assert_eq!(
            settings.source_id(),
            "changelog-md:owner/name:docs/CHANGES.md@main"
        );
    }

    #[test]
    fn repos_are_strictly_owner_slash_name() {
        assert!(is_repo("owner/name"));
        assert!(is_repo("crate-field/harness.rs"));
        assert!(!is_repo("owner"));
        assert!(!is_repo("owner/"));
        assert!(!is_repo("/name"));
        assert!(!is_repo("owner/a/b"));
        assert!(!is_repo("owner/na me"));
        assert!(!is_repo(""));
    }

    #[test]
    fn source_kinds_round_trip_their_config_values() {
        assert_eq!(
            SourceKind::parse("github-releases"),
            Some(SourceKind::GithubReleases)
        );
        assert_eq!(
            SourceKind::parse("changelog-md"),
            Some(SourceKind::ChangelogMd)
        );
        assert_eq!(
            SourceKind::parse(" changelog-md "),
            Some(SourceKind::ChangelogMd)
        );
        assert_eq!(SourceKind::parse("rss"), None);
        assert_eq!(SourceKind::GithubReleases.to_string(), "github-releases");
    }

    #[test]
    fn a_valid_configuration_is_accepted() {
        let cfg = config(&[("CHANGELOG_REPO", "owner/name")]);
        assert!(Changelog::new().validate_config(&cfg).is_ok());
    }

    #[test]
    fn a_missing_repo_is_the_one_required_key() {
        let error = Changelog::new()
            .validate_config(&config(&[]))
            .expect_err("no repo is invalid");
        assert!(error.to_string().contains("CHANGELOG_REPO"), "{error}");
    }

    #[test]
    fn every_bad_value_is_reported_at_once() {
        let cfg = config(&[
            ("CHANGELOG_REPO", "owner"),
            ("CHANGELOG_SOURCE", "rss"),
            ("CHANGELOG_CACHE_TTL_SECONDS", "soon"),
            ("CHANGELOG_API_BASE", "api.github.com"),
            ("CHANGELOG_LOCALE", "  "),
        ]);
        let error = Changelog::new()
            .validate_config(&cfg)
            .expect_err("all five values are invalid");
        let message = error.to_string();
        for key in [
            "CHANGELOG_REPO",
            "CHANGELOG_SOURCE",
            "CHANGELOG_CACHE_TTL_SECONDS",
            "CHANGELOG_API_BASE",
            "CHANGELOG_LOCALE",
        ] {
            assert!(message.contains(key), "{key} missing from {message}");
        }
    }

    #[test]
    fn self_check_reports_an_unusable_composition() {
        let module = Changelog::new().repo("owner");
        let problems = module.self_check();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("github-releases"), "{problems:?}");

        assert!(
            Changelog::new().self_check().is_empty(),
            "the default composition has nothing to report"
        );
    }

    #[test]
    fn a_pathless_changelog_md_source_is_a_self_check_problem() {
        let mut module = Changelog::new()
            .repo("owner/name")
            .source(SourceKind::ChangelogMd);
        module.settings.path = String::new();
        let problems = module.self_check();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("CHANGELOG_PATH"), "{problems:?}");
    }
}
