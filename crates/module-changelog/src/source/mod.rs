//! Fetching release notes from the configured source and mirroring them
//! into the database. Only the refresh path lives here: the read routes
//! never leave the store, by design.
//!
//! Two sources, one contract: a fetch either says **not modified** (the etag
//! matched; nothing is written at all) or comes back as an ordered batch
//! plus a new etag, and says whether it saw the **whole** source. Anything
//! else — a 404, a rate limit, a 5xx, a transport error, a body that does
//! not parse — is a [`FetchError`], which carries the status worth recording
//! in `changelog_source.last_status` alongside the `Problem` the caller will
//! hand back. Nothing less than a complete fetch may prune rows, and a fetch
//! that stopped at the page cap applies what it got and prunes nothing.

mod github;
mod markdown;

use cratefield_core::{HttpClient, ModuleContext, Problem, ProblemDef};
use http::{Response, StatusCode};
use serde_json::Value;

use crate::cache::ReadCache;
use crate::store::{self, UpstreamRelease};
use crate::{Settings, SourceKind};

/// GitHub answered 404: the configured repository (or its releases) is not
/// there, which is a configuration mistake and says so.
pub(crate) const SOURCE_NOT_FOUND: ProblemDef = ProblemDef {
    slug: "changelog-source-not-found",
    status: StatusCode::NOT_FOUND,
    title: "No such source",
    description: "The configured repository has no releases, or does not exist. \
                  Check CHANGELOG_REPO.",
};

/// Upstream failed: forbidden, a 5xx, a transport error, or a body that does
/// not parse. The stored releases are untouched; the detail says what
/// upstream answered.
pub(crate) const UPSTREAM: ProblemDef = ProblemDef {
    slug: "changelog-upstream",
    status: StatusCode::BAD_GATEWAY,
    title: "The source could not be fetched",
    description: "The upstream source failed; nothing stored was changed. \
                  The detail carries what upstream answered.",
};

/// Why a fetch gave up, kept beside the problem so the caller can record
/// `last_status` before the problem is handed on.
pub(crate) struct FetchError {
    /// A short stable code for `changelog_source.last_status`:
    /// `"404"`, `"429"`, `"503"`, `"transport"`, `"decode"`.
    pub last_status: String,
    pub problem: Problem,
}

/// What a source fetch produced.
pub(crate) enum Fetched {
    /// The stored etag matched: upstream has nothing new, and nothing at all
    /// is written.
    NotModified,
    /// A successful fetch. `skipped` counts entries upstream offered that
    /// could not become a release (no version, a duplicate heading); the
    /// include flags are applied later, where their skips are counted too.
    /// `complete` says whether the fetch saw the whole source — the whole
    /// list of releases, for the Releases API — because only a complete
    /// fetch may prune what upstream no longer reports.
    Fresh {
        /// The etag to store for next time; empty when upstream sent none
        /// or when the fetch spanned more than one response, where an etag
        /// would describe one page and not the whole.
        etag: String,
        releases: Vec<UpstreamRelease>,
        skipped: u64,
        /// Whether the walk saw the end of the list. A walk cut off at the
        /// page cap is not: it fetched a prefix, and a prefix cannot say
        /// what upstream deleted.
        complete: bool,
    },
}

/// What a refresh reports to the admin who asked for it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RefreshReport {
    pub fetched: u64,
    pub inserted: u64,
    pub updated: u64,
    pub unchanged: u64,
    pub skipped: u64,
    pub removed: u64,
    pub not_modified: bool,
    /// Whether the fetch behind this refresh saw the whole source. `false`
    /// means the walk hit the page cap: what it fetched was applied, but
    /// nothing was pruned, and the mirror may hold releases upstream has
    /// moved past its first pages.
    pub complete: bool,
}

impl RefreshReport {
    fn not_modified() -> Self {
        Self {
            not_modified: true,
            // The `304` shortcut is only ever taken on an etag a complete
            // single-page fetch stored, so "not modified" certifies the
            // mirror matches the whole source.
            complete: true,
            ..Self::default()
        }
    }
}

/// The settings as configured: the composed values with the `CHANGELOG_*`
/// keys applied over them. Configuration wins when a key is set, so a
/// venture that only composes `Changelog::new()` and sets configuration is
/// complete.
pub(crate) fn resolved(ctx: &ModuleContext, base: &Settings) -> Settings {
    let cfg = cratefield_core::ModuleConfig::new("changelog", ctx.config.as_ref());
    let mut settings = base.clone();

    if let Some(repo) = cfg
        .get_opt("REPO")
        .map(|repo| repo.trim().to_owned())
        .filter(|repo| !repo.is_empty())
    {
        settings.repo = Some(repo);
    }
    if let Some(kind) = cfg
        .get_opt("SOURCE")
        .and_then(|raw| SourceKind::parse(&raw))
    {
        settings.source = kind;
    }
    if let Some(path) = cfg
        .get_opt("PATH")
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty())
    {
        settings.path = path;
    }
    if let Some(git_ref) = cfg
        .get_opt("REF")
        .map(|git_ref| git_ref.trim().to_owned())
        .filter(|git_ref| !git_ref.is_empty())
    {
        settings.git_ref = Some(git_ref);
    }
    if let Some(token) = cfg
        .get_opt("TOKEN")
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
    {
        settings.token = Some(token);
    }
    if let Some(api_base) = cfg.get_opt("API_BASE") {
        api_base
            .trim_end_matches('/')
            .clone_into(&mut settings.api_base);
    }
    settings.include_prereleases =
        cfg.get_bool("INCLUDE_PRERELEASES", settings.include_prereleases);
    settings.include_drafts = cfg.get_bool("INCLUDE_DRAFTS", settings.include_drafts);
    if let Some(locale) = cfg
        .get_opt("LOCALE")
        .map(|locale| locale.trim().to_owned())
        .filter(|locale| !locale.is_empty())
    {
        settings.locale = locale;
    }
    if let Some(ttl) = cfg
        .get_opt("CACHE_TTL_SECONDS")
        .and_then(|raw| raw.trim().parse::<u64>().ok())
    {
        settings.cache_ttl_secs = ttl;
    }
    settings
}

/// Pulls from the configured source now and mirrors it into the database.
/// This is the whole write path; the read routes never come here.
pub(crate) async fn refresh(
    ctx: &ModuleContext,
    settings: &Settings,
) -> Result<RefreshReport, Problem> {
    let Some(db) = ctx.ports.db.as_deref() else {
        return Err(Problem::not_ready("the changelog module needs a database"));
    };
    let Some(http) = ctx.ports.http.as_deref() else {
        return Err(Problem::not_ready(
            "the changelog module needs an http client",
        ));
    };
    let Some(clock) = ctx.ports.clock.as_deref() else {
        return Err(Problem::not_ready("the changelog module needs a clock"));
    };

    let Some((owner, name)) = settings.repo_parts() else {
        return Err(Problem::validation_failed(
            "CHANGELOG_REPO is required as `owner/name`; there is nothing to pull from",
        ));
    };
    let source_id = settings.source_id();
    let now = store::now_iso(clock);

    // The stored etag is what makes an unchanged upstream cost one request.
    let prior = store::source_state(db, &source_id)
        .await
        .map_err(|_| Problem::internal())?;
    let etag = prior
        .as_ref()
        .map(|state| state.etag.as_str())
        .filter(|etag| !etag.is_empty());

    let outcome = match settings.source {
        SourceKind::GithubReleases => github::fetch(http, settings, owner, name, etag).await,
        SourceKind::ChangelogMd => markdown::fetch(http, settings, owner, name, etag).await,
    };

    match outcome {
        Ok(Fetched::NotModified) => Ok(RefreshReport::not_modified()),
        Err(error) => {
            // Record that the attempt happened — and nothing else. The
            // stored etag, the generation and every release row stay
            // exactly as they were.
            if let Err(record) =
                store::record_status(db, &source_id, &error.last_status, &now).await
            {
                tracing::warn!(error = %record, "changelog: could not record the failed refresh");
            }
            Err(error.problem)
        }
        Ok(Fetched::Fresh {
            etag,
            releases,
            skipped: dropped,
            complete,
        }) => {
            let fetched = releases.len() as u64;
            let (kept, hidden) = keep(settings, releases);
            // `complete` is what makes pruning safe: a walk that hit the
            // page cap fetched a prefix of upstream's list, and pruning
            // against a prefix would take every release past the cap with
            // it. The prefix's inserts and updates still apply.
            let counts = store::apply_refresh(db, &source_id, &kept, &now, complete)
                .await
                .map_err(|_| Problem::internal())?;

            // A new generation only when something actually moved, so an
            // unchanged refresh does not throw away the read cache.
            let generation = if counts.changed() {
                let generation = new_generation();
                ReadCache::of(ctx, settings.cache_ttl_secs)
                    .publish_generation(&generation)
                    .await;
                generation
            } else {
                prior.map(|state| state.generation).unwrap_or_default()
            };

            store::record_source(db, &source_id, &etag, &generation, &now, "200")
                .await
                .map_err(|_| Problem::internal())?;

            Ok(RefreshReport {
                fetched,
                inserted: counts.inserted,
                updated: counts.updated,
                unchanged: counts.unchanged,
                skipped: dropped + hidden,
                removed: counts.removed,
                not_modified: false,
                complete,
            })
        }
    }
}

/// Applies the include flags: a draft or a prerelease is dropped unless its
/// flag says otherwise. Returns what survived and how many were hidden.
fn keep(settings: &Settings, releases: Vec<UpstreamRelease>) -> (Vec<UpstreamRelease>, u64) {
    let mut kept = Vec::new();
    let mut hidden = 0u64;
    for release in releases {
        let excluded = (release.draft && !settings.include_drafts)
            || (release.prerelease && !settings.include_prereleases);
        if excluded {
            hidden += 1;
        } else {
            kept.push(release);
        }
    }
    (kept, hidden)
}

/// A fresh generation ULID. The `IdGen` port is deliberately not declared,
/// so the module generates its own — a generation is module-private
/// bookkeeping, and the value never leaves the cache keys it names.
fn new_generation() -> String {
    ulid::Ulid::generate().to_string()
}

/// The shared failure mapping for both sources: the status a caller records,
/// and the problem a caller answers with. GitHub's 403 is a rate limit as
/// often as it is a permission, and the detail says which it looked like.
pub(crate) fn upstream_error(status: u16, body: &Value) -> FetchError {
    let message = body
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| !message.is_empty())
        .unwrap_or("no detail");
    match status {
        404 => FetchError {
            last_status: "404".to_owned(),
            problem: Problem::new(&SOURCE_NOT_FOUND),
        },
        403 => FetchError {
            last_status: "403".to_owned(),
            problem: Problem::new(&UPSTREAM).with_detail(format!(
                "GitHub answered 403: {message} (anonymous rate limits end here too; \
                 set CHANGELOG_TOKEN to raise the limit)"
            )),
        },
        429 => FetchError {
            last_status: "429".to_owned(),
            problem: Problem::new(&cratefield_core::SLUGS.rate_limited).with_detail(
                "GitHub rate limited this refresh; set CHANGELOG_TOKEN to raise the limit",
            ),
        },
        other => FetchError {
            last_status: other.to_string(),
            problem: Problem::new(&UPSTREAM)
                .with_detail(format!("GitHub answered {other}: {message}")),
        },
    }
}

/// Maps a port failure onto the same shape: the cap, the deadline and a
/// refused destination are all "GitHub is not answering" to a caller that
/// cannot act on the difference.
pub(crate) fn transport_error(error: impl std::fmt::Display) -> FetchError {
    FetchError {
        last_status: "transport".to_owned(),
        problem: Problem::new(&UPSTREAM).with_detail(format!("GitHub did not answer: {error}")),
    }
}

/// A body that parsed but was not the shape the contract says.
pub(crate) fn decode_error(detail: impl std::fmt::Display) -> FetchError {
    FetchError {
        last_status: "decode".to_owned(),
        problem: Problem::new(&UPSTREAM)
            .with_detail(format!("unexpected response from GitHub: {detail}")),
    }
}

/// Reads an `ETag` header, empty when upstream sent none.
pub(crate) fn etag_of(response: &Response<bytes::Bytes>) -> String {
    response
        .headers()
        .get(http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// Parses one GitHub release object loosely — `Value` in, hand-picked fields
/// out — the way `module-linkedin` reads LinkedIn's payloads. A release with
/// no usable `tag_name` is `None`; the caller counts it as skipped.
pub(crate) fn release_from_json(value: &Value) -> Option<UpstreamRelease> {
    let version = value
        .get("tag_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|tag| !tag.is_empty())?;
    Some(UpstreamRelease {
        version: version.to_owned(),
        // A missing, empty or blank `name` titles the release with its tag —
        // the same fallback the `CHANGELOG.md` parser applies to a heading
        // with no title.
        title: value
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| version.to_owned(), str::to_owned),
        body: value
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        url: value
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        // A draft has no `published_at`; fall back to `created_at`, then to
        // empty, which the ordering sorts last rather than dropping.
        published_at: value
            .get("published_at")
            .and_then(Value::as_str)
            .filter(|date| !date.is_empty())
            .or_else(|| value.get("created_at").and_then(Value::as_str))
            .unwrap_or_default()
            .to_owned(),
        prerelease: value
            .get("prerelease")
            .and_then(Value::as_bool)
            .unwrap_or_default(),
        draft: value
            .get("draft")
            .and_then(Value::as_bool)
            .unwrap_or_default(),
    })
}

/// The `HttpClient` port, mapped. Every send goes through here so the two
/// sources cannot forget the transport arm.
pub(crate) async fn send(
    http: &dyn HttpClient,
    request: http::Request<bytes::Bytes>,
) -> Result<Response<bytes::Bytes>, FetchError> {
    http.send(request).await.map_err(transport_error)
}
