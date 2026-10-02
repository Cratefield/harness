//! `cratefield-adapter-github-app`: GitHub App authentication (issue #623).
//!
//! A GitHub App authenticates in two steps. The app proves who it is with a
//! short-lived **RS256 JWT** signed by its private key (`iss` = the App ID,
//! `iat`/`exp` minutes apart); it exchanges that JWT for an **installation
//! token** (`ghs_…`) scoped to one installation, its permissions and its
//! repositories. A venture that acts *for a user* adds a third: the
//! **user-to-server** OAuth code exchange (`ghu_…`), and
//! [`GithubApp::user_can_access_installation`] is the check it runs before
//! linking an installation to an account.
//!
//! Everything goes through the runtime's [`HttpClient`] and [`Clock`] ports —
//! no vendor SDK, no `reqwest`, no `tokio`, no `std::time` — so the same
//! client runs on Cloudflare Workers and natively (ADR 0002: the ports are
//! core's, the vendor client is this crate's). Signing reuses
//! `cratefield-push-auth`'s [`Rs256Signer`] and its keyed [`CachedToken`],
//! because it is the same construction the push adapters already ship.
//!
//! **Nothing here logs a secret.** The `Debug` impls redact the key and every
//! token, the error messages carry no key material, and the only `tracing`
//! calls emit metadata (the installation id, the status) and never a token.
//!
//! [`HttpClient`]: cratefield_core::HttpClient
//! [`Clock`]: cratefield_core::Clock
//! [`Rs256Signer`]: cratefield_push_auth::Rs256Signer
//! [`CachedToken`]: cratefield_push_auth::CachedToken

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, HttpError};
use cratefield_push_auth::{CachedToken, Rs256Signer};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ETAG, IF_NONE_MATCH, LINK, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The REST API root GitHub App requests default to.
pub const DEFAULT_API_BASE: &str = "https://api.github.com";
/// The web root the user-to-server OAuth endpoint lives on. It is *not* the
/// API host: `/login/oauth/access_token` is served by github.com (or the
/// GitHub Enterprise Server web host).
pub const DEFAULT_WEB_BASE: &str = "https://github.com";

/// GitHub's current REST API version, pinned the way their docs say to.
const API_VERSION: &str = "2022-11-28";
/// The media type GitHub's App endpoints answer with.
const ACCEPT_VALUE: &str = "application/vnd.github+json";
/// GitHub rejects requests without a `User-Agent`.
const USER_AGENT_VALUE: &str = "cratefield-adapter-github-app";
/// The header that pins the REST API version.
const API_VERSION_HEADER: &str = "x-github-api-version";

/// How long a minted installation token is reused. A GitHub installation
/// token lives one hour; re-minting at 55 minutes leaves margin without
/// churning.
const TOKEN_TTL: Duration = Duration::from_mins(55);
/// How far before an installation token's own expiry it is treated as dead:
/// a token that expires while a request is in flight is worse than one extra
/// exchange.
const TOKEN_SAFETY_MARGIN: time::Duration = time::Duration::minutes(5);
/// The JWT is backdated this far, so a clock a minute fast on the app's host
/// still has it accepted.
const JWT_BACKDATE_SECS: i64 = 60;
/// The JWT lives this long. GitHub caps an App JWT at 10 minutes.
const JWT_LIFETIME_SECS: i64 = 540;
/// Pages of 100 installations followed before `user_can_access_installation`
/// gives up. Ten pages is a thousand installations — past that, "not on the
/// list" is the honest answer for one page cap rather than an unbounded walk.
const INSTALLATIONS_PAGE_CAP: usize = 10;

/// GitHub App auth over the [`HttpClient`] and [`Clock`] ports.
///
/// The `private_key_pem` is optional on purpose: a deployment without a key
/// (a preview environment, a test) constructs the client and every operation
/// **that needs the key** — [`GithubApp::app_jwt`],
/// [`GithubApp::installation_token`], [`GithubApp::request`],
/// [`GithubApp::paginate`] — answers [`GithubAppError::NotConfigured`] without
/// touching the network, so a venture can wire it unconditionally and let the
/// absence decide. The user-to-server pair,
/// [`GithubApp::exchange_user_code`] and
/// [`GithubApp::user_can_access_installation`], carries the caller's own
/// credential and runs without one.
///
/// [`HttpClient`]: cratefield_core::HttpClient
/// [`Clock`]: cratefield_core::Clock
pub struct GithubApp {
    /// The App ID, kept as the string `iss` reads. GitHub's docs show the
    /// numeric id for an app; both the number and its decimal string are
    /// accepted, and the string is what is sent.
    app_id: u64,
    /// The parsed key, or why there is not one.
    key: AppKey,
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    /// The REST API root, without a trailing slash.
    api_base: String,
    /// The web root the OAuth endpoint lives on, without a trailing slash.
    web_base: String,
    /// Minted installation tokens, keyed by `(installation id, scope)`.
    tokens: CachedToken<(u64, String)>,
    /// Single-flight guard around "check cache → exchange → store": held
    /// across the exchange so two concurrent cold calls make one request.
    /// A single app-wide lock is the whole optimisation here — re-minting a
    /// token is rare, so per-key locks would buy nothing for the extra state.
    exchange: futures_util::lock::Mutex<()>,
}

/// What a constructor's `private_key_pem` argument resolved to. Parsed once
/// so every operation is a cheap match, and so a malformed PEM is a stable
/// [`GithubAppError::InvalidKey`] rather than a re-parse per call.
enum AppKey {
    /// No key was supplied, or it was empty.
    Absent,
    /// A key was supplied and did not parse. The underlying parser message is
    /// deliberately dropped: it is not worth the risk that one build of the
    /// `rsa` crate echoes input.
    Invalid,
    /// A usable signer.
    Signer(Box<Rs256Signer>),
}

impl AppKey {
    fn is_signer(&self) -> bool {
        matches!(self, AppKey::Signer(_))
    }
}

impl std::fmt::Debug for GithubApp {
    /// Never prints the key or a token. The `http`, `clock`, cache and lock
    /// fields are omitted wholesale rather than summarised.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubApp")
            .field("app_id", &self.app_id)
            .field("api_base", &self.api_base)
            .field("web_base", &self.web_base)
            .field("configured", &self.key.is_signer())
            .finish_non_exhaustive()
    }
}

impl GithubApp {
    /// A client for `app_id`, signing with `private_key_pem` (PKCS#1 or
    /// PKCS#8 PEM; `None` or empty means "not configured"). `api_base` is the
    /// REST root — pass [`DEFAULT_API_BASE`] unless targeting GitHub
    /// Enterprise Server or a fake in tests. The OAuth endpoint's host
    /// defaults to [`DEFAULT_WEB_BASE`]; override it with
    /// [`GithubApp::with_web_base`].
    #[must_use]
    pub fn new(
        app_id: u64,
        private_key_pem: Option<String>,
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        api_base: impl Into<String>,
    ) -> Self {
        let api_base = api_base.into();
        let key = match private_key_pem {
            Some(pem) if !pem.trim().is_empty() => match Rs256Signer::from_pem(&pem) {
                Ok(signer) => AppKey::Signer(Box::new(signer)),
                Err(_) => AppKey::Invalid,
            },
            _ => AppKey::Absent,
        };
        Self {
            app_id,
            key,
            http,
            clock,
            api_base: trim_base(&api_base),
            web_base: DEFAULT_WEB_BASE.to_owned(),
            tokens: CachedToken::new(TOKEN_TTL),
            exchange: futures_util::lock::Mutex::new(()),
        }
    }

    /// Points the user-to-server OAuth exchange at another web host — GitHub
    /// Enterprise Server, or a fake in tests — instead of
    /// `https://github.com`.
    #[must_use]
    pub fn with_web_base(mut self, web_base: impl Into<String>) -> Self {
        let web_base = web_base.into();
        self.web_base = trim_base(&web_base);
        self
    }

    /// The App ID this client signs for.
    #[must_use]
    pub fn app_id(&self) -> u64 {
        self.app_id
    }

    /// Whether a usable private key was supplied.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.key.is_signer()
    }

    /// The signing key, or the reason there is none. The single gate every
    /// operation passes first, so an unconfigured client never reaches the
    /// network.
    fn signer(&self) -> Result<&Rs256Signer, GithubAppError> {
        match &self.key {
            AppKey::Signer(signer) => Ok(signer),
            AppKey::Absent => Err(GithubAppError::NotConfigured),
            AppKey::Invalid => Err(GithubAppError::InvalidKey),
        }
    }

    /// A signed app JWT: header `{"alg":"RS256","typ":"JWT"}`, claims
    /// `iat` = now − 60s, `exp` = now + 540s (nine minutes, inside GitHub's
    /// ten-minute cap), and `iss` = the App ID as a string.
    ///
    /// # Errors
    ///
    /// [`GithubAppError::NotConfigured`] when no key was supplied,
    /// [`GithubAppError::InvalidKey`] when the key did not parse. Neither
    /// message contains key material.
    pub fn app_jwt(&self) -> Result<String, GithubAppError> {
        let signer = self.signer()?;
        let now = self.clock.now().unix_timestamp();
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({
            "iat": now - JWT_BACKDATE_SECS,
            "exp": now + JWT_LIFETIME_SECS,
            "iss": self.app_id.to_string(),
        });
        Ok(signer.sign_jwt(&header, &claims))
    }

    /// An installation token, minted once and cached per installation and
    /// scope.
    ///
    /// `permissions` and `repositories` narrow the token the way GitHub's
    /// `POST /app/installations/{id}/access_tokens` does; both are omitted
    /// from the request body when `None`, and the pair forms the cache key, so
    /// a token scoped to one repository is never handed to a call scoped to
    /// another. `Some` of an empty map or list is *not* `None`: GitHub reads
    /// the first as "grant nothing" and the second as "grant everything", and
    /// the two get separate cache entries.
    ///
    /// Concurrent calls for the same installation and scope make **one**
    /// exchange for the whole client: one app-wide async mutex is held across
    /// check-cache, exchange and store, so a second caller arriving mid-flight
    /// waits and then reads the token the first one stored. A token minted
    /// already inside the five-minute safety margin (GitHub's answer minus
    /// five minutes is not in the future) is returned but not cached — there
    /// is nothing worth storing.
    ///
    /// # Errors
    ///
    /// [`GithubAppError::NotConfigured`] / [`GithubAppError::InvalidKey`]
    /// before any network call; [`GithubAppError::Http`] on a transport
    /// failure; [`GithubAppError::Status`] when GitHub refuses the exchange
    /// (carrying the status and the rate-limit headers); and
    /// [`GithubAppError::Decode`] when a 2xx body cannot be read. No message
    /// or logged field contains the token or the key.
    pub async fn installation_token(
        &self,
        installation_id: u64,
        permissions: Option<&BTreeMap<String, String>>,
        repositories: Option<&[String]>,
    ) -> Result<InstallationToken, GithubAppError> {
        self.signer()?;
        let key = (installation_id, scope_key(permissions, repositories));

        // Held across the exchange: the whole point is that a second caller
        // arriving mid-exchange waits and then reads the token the first one
        // stored, rather than presenting GitHub a second JWT.
        let _single_flight = self.exchange.lock().await;

        if let Some(cached) = self.tokens.cached(self.clock.as_ref(), &key) {
            if let Ok(wire) = serde_json::from_str::<CachedTokenWire>(&cached) {
                return Ok(wire.into_token());
            }
            // A cached value we cannot read is worse than none: drop it and
            // mint.
            self.tokens.invalidate(&key);
        }

        let token = self
            .exchange_installation_token(installation_id, permissions, repositories)
            .await?;

        // Reuse it until five minutes before GitHub says it dies; below that
        // margin there is nothing worth caching, so store nothing.
        let now = self.clock.now();
        let usable = token.expires_at - TOKEN_SAFETY_MARGIN - now;
        if let Ok(lifetime) = std::time::Duration::try_from(usable)
            && lifetime > Duration::ZERO
            && let Ok(json) = serde_json::to_string(&CachedTokenWire::from(&token))
        {
            self.tokens.store(self.clock.as_ref(), &key, json, lifetime);
        }
        tracing::info!(
            provider = "github-app",
            installation = installation_id,
            outcome = "token-minted",
            "github app token"
        );
        Ok(token)
    }

    /// One installation-token exchange, with no cache in front of it.
    async fn exchange_installation_token(
        &self,
        installation_id: u64,
        permissions: Option<&BTreeMap<String, String>>,
        repositories: Option<&[String]>,
    ) -> Result<InstallationToken, GithubAppError> {
        let jwt = self.app_jwt()?;
        let body = serde_json::to_vec(&TokenRequest {
            permissions,
            repositories,
        })
        .map_err(|err| GithubAppError::Decode(err.to_string()))?;
        let uri: Uri = format!(
            "{}/app/installations/{installation_id}/access_tokens",
            self.api_base
        )
        .parse()
        .map_err(|_| GithubAppError::InvalidHeader)?;
        let auth = HeaderValue::from_str(&format!("Bearer {jwt}"))
            .map_err(|_| GithubAppError::InvalidHeader)?;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(AUTHORIZATION, auth)
            .header(ACCEPT, ACCEPT_VALUE)
            .header(CONTENT_TYPE, "application/json")
            .header(API_VERSION_HEADER, API_VERSION)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .body(Bytes::from(body))
            .map_err(|_| GithubAppError::InvalidHeader)?;

        let response = self.http.send(request).await?;
        let status = response.status();
        let rate_limit = RateLimit::from_headers(response.headers());
        if !status.is_success() {
            tracing::warn!(
                provider = "github-app",
                installation = installation_id,
                code = status.as_u16(),
                outcome = "token-refused",
                "github app token"
            );
            return Err(GithubAppError::Status { status, rate_limit });
        }
        let wire: InstallationTokenWire = serde_json::from_slice(response.body())
            .map_err(|err| GithubAppError::Decode(err.to_string()))?;
        wire.into_token()
    }

    /// Sends an API request authenticated with an installation token.
    ///
    /// The request's URI may be absolute (`https://api.github.com/repos/...`)
    /// or relative (`/repos/...`); a relative one is resolved against the
    /// client's API base. An absolute URI on another origin than the API base
    /// is refused with [`GithubAppError::ForeignOrigin`] — before any token is
    /// minted — whenever this method would attach the installation token: the
    /// token never leaves the API's origin, whichever path the URL came by
    /// (a caller-built one, [`GithubApp::paginate`]'s first page, a URL read
    /// out of a payload). `Authorization`, `Accept`,
    /// `X-GitHub-Api-Version` and `User-Agent` are set unless the caller
    /// already set them — so a caller can pass their own credential and this
    /// method will not overwrite it (and will not mint an installation token
    /// at all).
    ///
    /// A `401` on a request **this method** authenticated means the
    /// installation token went stale: the cached one is dropped, a fresh one
    /// is minted, and the request is replayed exactly once. A second `401`
    /// (or any other non-2xx, `304` included) is returned as an ordinary
    /// [`GithubResponse`] for the caller to read — this method does not
    /// classify those.
    ///
    /// # Errors
    ///
    /// As [`GithubApp::installation_token`], plus
    /// [`GithubAppError::InvalidHeader`] if a token cannot be put on the wire
    /// as a header value, and [`GithubAppError::ForeignOrigin`] for an
    /// off-origin URI this method would have authenticated.
    pub async fn request(
        &self,
        installation_id: u64,
        request: Request<Bytes>,
    ) -> Result<GithubResponse, GithubAppError> {
        self.signer()?;
        let caller_authenticated = request.headers().contains_key(AUTHORIZATION);
        if !caller_authenticated {
            let target = resolve_uri(&self.api_base, request.uri())?;
            if !same_origin(&self.api_base, &target.to_string()) {
                tracing::warn!(
                    provider = "github-app",
                    installation = installation_id,
                    outcome = "foreign-origin-refused",
                    "github app request"
                );
                return Err(GithubAppError::ForeignOrigin);
            }
        }

        let mut credential = if caller_authenticated {
            None
        } else {
            Some(
                self.installation_token(installation_id, None, None)
                    .await?
                    .token,
            )
        };
        let first = self.prepare(request.clone(), credential.as_deref())?;
        let response = self.http.send(first).await?;

        if response.status() != StatusCode::UNAUTHORIZED || credential.is_none() {
            return Ok(GithubResponse::new(response));
        }

        // The token this method minted was refused. Drop it, mint a fresh one
        // and replay exactly once — a loop here would turn a permanent 401
        // into an unbounded one.
        let key = (installation_id, default_scope_key());
        self.tokens.invalidate(&key);
        let fresh = self.installation_token(installation_id, None, None).await?;
        credential = Some(fresh.token);
        tracing::warn!(
            provider = "github-app",
            installation = installation_id,
            status = 401,
            outcome = "token-refreshed",
            "github app request"
        );
        let replay = self.prepare(request, credential.as_deref())?;
        Ok(GithubResponse::new(self.http.send(replay).await?))
    }

    /// Resolves a relative URI, and fills in the default headers.
    fn prepare(
        &self,
        mut request: Request<Bytes>,
        credential: Option<&str>,
    ) -> Result<Request<Bytes>, GithubAppError> {
        *request.uri_mut() = resolve_uri(&self.api_base, request.uri())?;
        let headers = request.headers_mut();
        if let Some(token) = credential
            && !headers.contains_key(AUTHORIZATION)
        {
            let value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| GithubAppError::InvalidHeader)?;
            headers.insert(AUTHORIZATION, value);
        }
        insert_static(headers, ACCEPT, ACCEPT_VALUE);
        insert_static(
            headers,
            HeaderName::from_static(API_VERSION_HEADER),
            API_VERSION,
        );
        insert_static(headers, USER_AGENT, USER_AGENT_VALUE);
        Ok(request)
    }

    /// Follows `Link: …; rel="next"` from `first_url`, returning at most
    /// `max_pages` responses. The walk stops when a page carries no `next`
    /// link or the cap is reached; every page after the first is requested
    /// through [`GithubApp::request`], so it carries the same installation
    /// token and the same `401` replay.
    ///
    /// A `next` link is followed only when it is on `api_base`'s origin
    /// (scheme, host and port). A cross-origin link ends the walk instead: the
    /// next page would be fetched with the installation token in
    /// `Authorization`, and a `Link` header is the one part of a response an
    /// upstream gets to choose.
    ///
    /// # Errors
    ///
    /// As [`GithubApp::request`] — so a `first_url` on another origin is
    /// [`GithubAppError::ForeignOrigin`].
    pub async fn paginate(
        &self,
        installation_id: u64,
        first_url: impl Into<String>,
        max_pages: usize,
    ) -> Result<Vec<GithubResponse>, GithubAppError> {
        let mut pages = Vec::new();
        let mut next = Some(first_url.into());
        while let Some(url) = next {
            if pages.len() >= max_pages {
                break;
            }
            let request = Request::builder()
                .method(http::Method::GET)
                .uri(url)
                .body(Bytes::new())
                .map_err(|_| GithubAppError::InvalidHeader)?;
            let response = self.request(installation_id, request).await?;
            next = next_page(response.response.headers())
                .filter(|url| same_origin(&self.api_base, url));
            pages.push(response);
        }
        Ok(pages)
    }

    /// Exchanges a user-to-server authorization `code` for a user access
    /// token (`ghu_…`).
    ///
    /// GitHub answers `200` with `{"error": …}` for both success and failure,
    /// so the body decides: an `error` field becomes
    /// [`GithubAppError::OAuth`] carrying only GitHub's error *code*, never
    /// the body — which would echo the client secret back. A non-success
    /// status without an `error` field is a plain
    /// [`GithubAppError::Status`], whether or not the body is JSON (an HTML
    /// error page must not be mistaken for a decode failure), and a
    /// successful response whose body is not JSON is
    /// [`GithubAppError::Decode`].
    ///
    /// This flow authenticates with the client id and secret, not the app's
    /// private key, so it works on a client constructed without a key.
    ///
    /// # Errors
    ///
    /// [`GithubAppError::Http`] on transport failure,
    /// [`GithubAppError::OAuth`] on a GitHub-reported error,
    /// [`GithubAppError::Status`] on a non-2xx without one, and
    /// [`GithubAppError::Decode`] when a 2xx body cannot be read.
    pub async fn exchange_user_code(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: Option<&str>,
    ) -> Result<UserToken, GithubAppError> {
        let body = serde_json::to_vec(&OAuthRequest {
            client_id,
            client_secret,
            code,
            redirect_uri,
        })
        .map_err(|err| GithubAppError::Decode(err.to_string()))?;
        let uri: Uri = format!("{}/login/oauth/access_token", self.web_base)
            .parse()
            .map_err(|_| GithubAppError::InvalidHeader)?;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(USER_AGENT, USER_AGENT_VALUE)
            .body(Bytes::from(body))
            .map_err(|_| GithubAppError::InvalidHeader)?;

        let response = self.http.send(request).await?;
        let status = response.status();
        let rate_limit = RateLimit::from_headers(response.headers());

        // Parse the body once, but tolerate it not being JSON: GitHub's OAuth
        // endpoint answers `200` with `{"error": …}` on the "these are not the
        // codes" path, so an `error` field wins over the status — while a
        // non-2xx body that is not JSON at all (an HTML error page) is a
        // status, not a decode failure.
        let value = serde_json::from_slice::<serde_json::Value>(response.body()).ok();
        if let Some(error) = value
            .as_ref()
            .and_then(|value| value.get("error"))
            .and_then(serde_json::Value::as_str)
        {
            tracing::warn!(
                provider = "github-app",
                code = status.as_u16(),
                outcome = "oauth-refused",
                "github app oauth"
            );
            return Err(GithubAppError::OAuth(error.to_owned()));
        }
        if !status.is_success() {
            return Err(GithubAppError::Status { status, rate_limit });
        }
        let value = value
            .ok_or_else(|| GithubAppError::Decode("the OAuth answer was not JSON".to_owned()))?;
        let wire: UserTokenWire =
            serde_json::from_value(value).map_err(|err| GithubAppError::Decode(err.to_string()))?;
        Ok(wire.into_token())
    }

    /// Whether `user_token` can reach `installation_id`, by walking
    /// `GET {api_base}/user/installations?per_page=100` and looking for the id
    /// (following `Link` pages, up to a fixed page cap).
    ///
    /// This is the check a venture runs before linking an installation to an
    /// account: a user token can only see the installations that user
    /// authorised.
    ///
    /// A `next` link is followed only when it is on `api_base`'s origin. A
    /// cross-origin one ends the walk and the answer is `false` — the call
    /// exists to grant access, so an unverifiable walk fails closed rather
    /// than granting it.
    ///
    /// This flow presents the caller's own user token, not the app's private
    /// key, so it works on a client constructed without a key.
    ///
    /// # Errors
    ///
    /// [`GithubAppError::Http`] on transport failure, and
    /// [`GithubAppError::Status`] / [`GithubAppError::Decode`] on a bad page.
    pub async fn user_can_access_installation(
        &self,
        user_token: &str,
        installation_id: u64,
    ) -> Result<bool, GithubAppError> {
        let mut next = Some(format!("{}/user/installations?per_page=100", self.api_base));
        let mut visited = 0;
        while let Some(url) = next {
            if visited >= INSTALLATIONS_PAGE_CAP {
                break;
            }
            visited += 1;
            let auth = HeaderValue::from_str(&format!("Bearer {user_token}"))
                .map_err(|_| GithubAppError::InvalidHeader)?;
            let request = Request::builder()
                .method(http::Method::GET)
                .uri(url)
                .header(AUTHORIZATION, auth)
                .header(ACCEPT, ACCEPT_VALUE)
                .header(API_VERSION_HEADER, API_VERSION)
                .header(USER_AGENT, USER_AGENT_VALUE)
                .body(Bytes::new())
                .map_err(|_| GithubAppError::InvalidHeader)?;
            let response = self.http.send(request).await?;
            let status = response.status();
            if !status.is_success() {
                return Err(GithubAppError::Status {
                    status,
                    rate_limit: RateLimit::from_headers(response.headers()),
                });
            }
            let page: InstallationsPage = serde_json::from_slice(response.body())
                .map_err(|err| GithubAppError::Decode(err.to_string()))?;
            if page
                .installations
                .iter()
                .any(|one| one.id == installation_id)
            {
                return Ok(true);
            }
            next = next_page(response.headers()).filter(|url| same_origin(&self.api_base, url));
        }
        Ok(false)
    }
}

/// A shortcut for adding `If-None-Match: <etag>` to a request, so a caller
/// can do a conditional `GET` and recognise [`GithubResponse::not_modified`].
#[must_use]
pub fn with_etag(mut request: Request<Bytes>, etag: &str) -> Request<Bytes> {
    if let Ok(value) = HeaderValue::from_str(etag) {
        request.headers_mut().insert(IF_NONE_MATCH, value);
    }
    request
}

/// An installation token: the credential (`ghs_…`), when GitHub says it dies,
/// and the permissions it carries. `Debug` never prints the token.
pub struct InstallationToken {
    /// The `ghs_…` token.
    pub token: String,
    /// GitHub's stated expiry.
    pub expires_at: OffsetDateTime,
    /// The permissions GitHub granted this token.
    pub permissions: BTreeMap<String, String>,
}

impl std::fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallationToken")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("permissions", &self.permissions)
            .finish()
    }
}

impl InstallationToken {
    /// The token, for a caller about to present it somewhere other than this
    /// client.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.token
    }
}

/// A user-to-server access token (`ghu_…`) and its refresh material. `Debug`
/// never prints a token.
pub struct UserToken {
    /// The `ghu_…` token.
    pub access_token: String,
    /// Seconds until `access_token` expires, when GitHub says.
    pub expires_in: Option<u64>,
    /// The refresh token (`ghr_…`), when this app issues expiring tokens.
    pub refresh_token: Option<String>,
    /// Seconds until `refresh_token` expires, when present.
    pub refresh_token_expires_in: Option<u64>,
    /// The token type GitHub reported (`bearer`).
    pub token_type: Option<String>,
}

impl std::fmt::Debug for UserToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserToken")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

impl UserToken {
    /// The token, for a caller about to present it somewhere other than this
    /// client.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.access_token
    }
}

/// GitHub's rate-limit headers, read off any response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimit {
    /// `X-RateLimit-Remaining`.
    pub remaining: Option<u32>,
    /// `X-RateLimit-Reset`, a UNIX timestamp.
    pub reset: Option<OffsetDateTime>,
    /// `Retry-After`, in seconds.
    pub retry_after: Option<Duration>,
}

impl RateLimit {
    /// Reads the three headers, ignoring any that is absent or malformed.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let remaining = headers
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u32>().ok());
        let reset = headers
            .get("x-ratelimit-reset")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok());
        let retry_after = headers
            .get(http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs);
        Self {
            remaining,
            reset,
            retry_after,
        }
    }
}

/// A GitHub API response and the rate-limit information it carried. This
/// crate does not classify a non-2xx status (other than a replayed `401`):
/// the caller reads [`GithubResponse::status`] and decides.
pub struct GithubResponse {
    /// The response, body and all.
    pub response: Response<Bytes>,
    /// The rate-limit headers that came with it.
    pub rate_limit: RateLimit,
}

impl GithubResponse {
    fn new(response: Response<Bytes>) -> Self {
        let rate_limit = RateLimit::from_headers(response.headers());
        Self {
            response,
            rate_limit,
        }
    }

    /// The status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    /// Whether GitHub answered `304 Not Modified` — the recognisable outcome
    /// of a conditional `GET` sent with [`with_etag`].
    #[must_use]
    pub fn not_modified(&self) -> bool {
        self.response.status() == StatusCode::NOT_MODIFIED
    }

    /// The response headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        self.response.body()
    }

    /// The `ETag` header, for a caller to feed back through [`with_etag`].
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
    }
}

/// The URL of the `rel="next"` link in a `Link` header, if there is one.
/// Handles several comma-separated links and the quoted `rel` they carry;
/// commas inside a `<…>` URL are not separators.
///
/// The URL is returned as it appears in the header, whatever host it names.
/// A caller about to send it somewhere must check the origin first —
/// [`GithubApp::paginate`] and
/// [`GithubApp::user_can_access_installation`] do.
#[must_use]
pub fn next_page(headers: &HeaderMap) -> Option<String> {
    headers.get_all(LINK).iter().find_map(|value| {
        links(value.to_str().ok()?).into_iter().find_map(|link| {
            let open = link.find('<')?;
            let rest = &link[open + 1..];
            let close = rest.find('>')?;
            is_next_link(&rest[close + 1..]).then(|| rest[..close].to_owned())
        })
    })
}

/// Splits a `Link` header into its links, on the commas that are not inside a
/// `<…>` URL. An unmatched `<` swallows the rest of the header, which is what
/// a malformed one gets.
fn links(text: &str) -> Vec<&str> {
    let (mut links, mut start, mut in_url) = (Vec::new(), 0, false);
    for (at, ch) in text.char_indices() {
        match ch {
            '<' => in_url = true,
            '>' => in_url = false,
            ',' if !in_url => {
                links.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    links.push(&text[start..]);
    links
}

/// Whether a link's parameter list (everything after `>`) names `rel="next"`.
fn is_next_link(params: &str) -> bool {
    params.split(';').any(|param| {
        let Some((name, value)) = param.split_once('=') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("rel") && value.trim().trim_matches('"') == "next"
    })
}

/// Whether `url` names the same origin — scheme, host and port — as
/// `api_base`. A `Link` page is followed only within that origin, because it
/// is fetched with a credential in `Authorization`.
fn same_origin(api_base: &str, url: &str) -> bool {
    match (api_base.parse::<Uri>(), url.parse::<Uri>()) {
        (Ok(base), Ok(target)) => origin(&base).is_some() && origin(&base) == origin(&target),
        _ => false,
    }
}

/// A URI's `(scheme, host, port)` with the default port filled in, or `None`
/// when it is not an absolute `http`/`https` URL.
fn origin(uri: &Uri) -> Option<(&str, &str, u16)> {
    let scheme = uri.scheme_str()?;
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    Some((scheme, uri.host()?, uri.port_u16().unwrap_or(default_port)))
}

/// The cache key for a scope: permissions sorted (a `BTreeMap` already is)
/// then repositories sorted, so the same set in any order is one cache entry.
///
/// `None` and `Some`-of-nothing are different keys. GitHub reads an omitted
/// field as "no narrowing" and a present empty one as "narrow to nothing", so
/// an absent side renders as `-` — which no permission pair or repository
/// name contains — and a present-but-empty side renders as the empty string.
fn scope_key(
    permissions: Option<&BTreeMap<String, String>>,
    repositories: Option<&[String]>,
) -> String {
    let permissions = permissions.map_or_else(
        || "-".to_owned(),
        |map| {
            map.iter()
                .map(|(name, level)| format!("{name}:{level}"))
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    let repositories = repositories.map_or_else(
        || "-".to_owned(),
        |list| {
            let mut sorted = list.to_vec();
            sorted.sort();
            sorted.join(",")
        },
    );
    format!("p={permissions};r={repositories}")
}

/// The scope key a plain [`GithubApp::request`] uses — no permissions, no
/// repositories — so its `401` invalidation names the same entry
/// [`GithubApp::installation_token`] stored.
fn default_scope_key() -> String {
    scope_key(None, None)
}

/// Strips a trailing slash so `{base}/path` never doubles it.
fn trim_base(base: &str) -> String {
    base.trim_end_matches('/').to_owned()
}

/// Resolves a request URI against `api_base` when it has no scheme; an
/// absolute URI is left alone (so a `Link` URL, which is absolute, is
/// followed as-is).
fn resolve_uri(api_base: &str, uri: &Uri) -> Result<Uri, GithubAppError> {
    if uri.scheme().is_some() {
        return Ok(uri.clone());
    }
    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let separator = if path.starts_with('/') { "" } else { "/" };
    format!("{api_base}{separator}{path}")
        .parse()
        .map_err(|_| GithubAppError::InvalidHeader)
}

/// Inserts `name: value` unless the caller already set that header.
fn insert_static(headers: &mut HeaderMap, name: HeaderName, value: &'static str) {
    if !headers.contains_key(&name) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

/// The JSON body of an installation-token exchange: only the fields the
/// caller supplied.
#[derive(serde::Serialize)]
struct TokenRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repositories: Option<&'a [String]>,
}

/// The JSON body of the user-to-server code exchange.
#[derive(serde::Serialize)]
struct OAuthRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<&'a str>,
}

/// GitHub's installation-token response.
#[derive(serde::Deserialize)]
struct InstallationTokenWire {
    token: String,
    expires_at: String,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
}

impl InstallationTokenWire {
    fn into_token(self) -> Result<InstallationToken, GithubAppError> {
        let expires_at = OffsetDateTime::parse(&self.expires_at, &Rfc3339)
            .map_err(|err| GithubAppError::Decode(err.to_string()))?;
        Ok(InstallationToken {
            token: self.token,
            expires_at,
            permissions: self.permissions,
        })
    }
}

/// The in-cache form: a [`InstallationToken`] with the expiry as a UNIX
/// timestamp, because `time`'s serde support is off by workspace policy.
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedTokenWire {
    token: String,
    expires_at_unix: i64,
    permissions: BTreeMap<String, String>,
}

impl From<&InstallationToken> for CachedTokenWire {
    fn from(token: &InstallationToken) -> Self {
        Self {
            token: token.token.clone(),
            expires_at_unix: token.expires_at.unix_timestamp(),
            permissions: token.permissions.clone(),
        }
    }
}

impl CachedTokenWire {
    fn into_token(self) -> InstallationToken {
        let expires_at = OffsetDateTime::from_unix_timestamp(self.expires_at_unix)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        InstallationToken {
            token: self.token,
            expires_at,
            permissions: self.permissions,
        }
    }
}

/// GitHub's user-to-server token response.
#[derive(serde::Deserialize)]
struct UserTokenWire {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    refresh_token_expires_in: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
}

impl UserTokenWire {
    fn into_token(self) -> UserToken {
        UserToken {
            access_token: self.access_token,
            expires_in: self.expires_in,
            refresh_token: self.refresh_token,
            refresh_token_expires_in: self.refresh_token_expires_in,
            token_type: self.token_type,
        }
    }
}

/// One page of `GET /user/installations`.
#[derive(serde::Deserialize)]
struct InstallationsPage {
    #[serde(default)]
    installations: Vec<InstallationRef>,
}

/// The only field of an installation this check reads.
#[derive(serde::Deserialize)]
struct InstallationRef {
    id: u64,
}

/// Everything that can go wrong. Every message this crate builds carries no
/// token, client secret, JWT or part of the private key — with one exception,
/// [`GithubAppError::Decode`], which carries the JSON parser's own words.
#[derive(Debug, thiserror::Error)]
pub enum GithubAppError {
    /// No private key was configured, so there is nothing to sign with.
    #[error("the GitHub App is not configured: no private key")]
    NotConfigured,
    /// A private key was configured but did not parse. The underlying parser
    /// message is deliberately not carried.
    #[error("the GitHub App private key is not a valid RSA PEM")]
    InvalidKey,
    /// A value could not be put on the wire as an HTTP header.
    #[error("a request header value is not valid")]
    InvalidHeader,
    /// [`GithubApp::request`] was asked to send the installation token to a
    /// URI outside the API base's origin (scheme, host and port). Nothing was
    /// minted or sent.
    #[error("refusing to send the installation token outside the GitHub API origin")]
    ForeignOrigin,
    /// The transport failed.
    #[error("github app request failed: {0}")]
    Http(#[from] HttpError),
    /// GitHub answered a token or API call with a non-success status.
    #[error("github app request was refused with {status}")]
    Status {
        /// The status GitHub returned.
        status: StatusCode,
        /// The rate-limit headers that came with it.
        rate_limit: RateLimit,
    },
    /// A body could not be read. The detail is the JSON parser's own message
    /// (a field name and a position), and a parser that meets an unexpected
    /// value may quote it — so this is diagnostic text, not a guarantee that
    /// no part of the body appears. It is never logged by this crate; a caller
    /// that prints it is printing something a response chose.
    #[error("github app answer could not be decoded: {0}")]
    Decode(String),
    /// GitHub's OAuth endpoint reported an error. Carries GitHub's error
    /// *code* only.
    #[error("github oauth error: {0}")]
    OAuth(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_keys_are_order_independent_and_scope_sensitive() {
        let a = BTreeMap::from([
            ("contents".to_owned(), "read".to_owned()),
            ("issues".to_owned(), "write".to_owned()),
        ]);
        let b = BTreeMap::from([
            ("issues".to_owned(), "write".to_owned()),
            ("contents".to_owned(), "read".to_owned()),
        ]);
        assert_eq!(scope_key(Some(&a), None), scope_key(Some(&b), None));

        let unsorted = vec!["acme/zeta".to_owned(), "acme/alpha".to_owned()];
        let sorted = vec!["acme/alpha".to_owned(), "acme/zeta".to_owned()];
        assert_eq!(
            scope_key(None, Some(&unsorted)),
            scope_key(None, Some(&sorted))
        );
        // A narrow scope never shares a key with the default one.
        assert_ne!(scope_key(None, None), scope_key(Some(&a), None));
        assert_eq!(scope_key(None, None), default_scope_key());

        // `None` and `Some`-of-nothing are different requests — GitHub reads
        // the first as "no narrowing", the second as "narrow to nothing" — so
        // they must be different cache entries.
        let empty_map = BTreeMap::new();
        let empty_list: Vec<String> = Vec::new();
        assert_ne!(scope_key(None, None), scope_key(Some(&empty_map), None));
        assert_ne!(scope_key(None, None), scope_key(None, Some(&empty_list)));
        assert_ne!(
            scope_key(None, None),
            scope_key(Some(&empty_map), Some(&empty_list))
        );
        assert_eq!(scope_key(None, None), default_scope_key());
    }

    #[test]
    fn a_link_header_yields_its_next_url() {
        let mut headers = HeaderMap::new();
        headers.insert(
            LINK,
            HeaderValue::from_static(
                "<https://api.github.test/user/installations?per_page=100&page=2>; rel=\"next\", \
                 <https://api.github.test/user/installations?per_page=100&page=5>; rel=\"last\"",
            ),
        );
        assert_eq!(
            next_page(&headers).as_deref(),
            Some("https://api.github.test/user/installations?per_page=100&page=2")
        );
    }

    #[test]
    fn a_link_header_without_next_is_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            LINK,
            HeaderValue::from_static("<https://api.github.test/x?page=1>; rel=\"prev\""),
        );
        assert_eq!(next_page(&headers), None);
        assert_eq!(next_page(&HeaderMap::new()), None);
    }

    #[test]
    fn a_comma_inside_a_link_url_is_not_a_separator() {
        // A pathological URL carrying a comma must not be split in two.
        let mut headers = HeaderMap::new();
        headers.insert(
            LINK,
            HeaderValue::from_static("<https://api.github.test/a,b>; rel=\"next\""),
        );
        assert_eq!(
            next_page(&headers).as_deref(),
            Some("https://api.github.test/a,b")
        );
        assert_eq!(
            links("<https://x/a,b>; rel=\"next\""),
            vec!["<https://x/a,b>; rel=\"next\""]
        );
    }

    #[test]
    fn a_next_link_is_only_same_origin() {
        assert!(same_origin(
            "https://api.github.test",
            "https://api.github.test/user/installations?page=2"
        ));
        // A defaulted port is the same origin as an explicit one.
        assert!(same_origin(
            "https://api.github.test",
            "https://api.github.test:443/x"
        ));
        // Scheme, host and port each break it.
        assert!(!same_origin(
            "https://api.github.test",
            "http://api.github.test/x"
        ));
        assert!(!same_origin(
            "https://api.github.test",
            "https://evil.example.com/x"
        ));
        assert!(!same_origin(
            "https://api.github.test",
            "https://api.github.test:8443/x"
        ));
        // A relative or unparseable URL is not followed either.
        assert!(!same_origin(
            "https://api.github.test",
            "/user/installations?page=2"
        ));
        assert!(!same_origin(
            "https://api.github.test",
            "ftp://api.github.test/x"
        ));
        assert!(!same_origin("not a base", "https://api.github.test/x"));
    }

    #[test]
    fn rate_limit_headers_are_parsed_and_garbage_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("4999"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("1700000000"));
        headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("42"));
        let limit = RateLimit::from_headers(&headers);
        assert_eq!(limit.remaining, Some(4999));
        assert_eq!(limit.reset.unwrap().unix_timestamp(), 1_700_000_000);
        assert_eq!(limit.retry_after, Some(Duration::from_secs(42)));

        let mut bad = HeaderMap::new();
        bad.insert("x-ratelimit-remaining", HeaderValue::from_static("soon"));
        bad.insert("x-ratelimit-reset", HeaderValue::from_static("not-a-time"));
        bad.insert(http::header::RETRY_AFTER, HeaderValue::from_static("-1"));
        assert_eq!(RateLimit::from_headers(&bad), RateLimit::default());
    }

    #[test]
    fn a_relative_uri_resolves_against_the_api_base() {
        let absolute: Uri = "https://elsewhere.test/repos".parse().unwrap();
        assert_eq!(
            resolve_uri("https://api.github.test", &absolute).unwrap(),
            absolute
        );
        let relative: Uri = "/repos/acme/widgets".parse().unwrap();
        assert_eq!(
            resolve_uri("https://api.github.test", &relative)
                .unwrap()
                .to_string(),
            "https://api.github.test/repos/acme/widgets"
        );
    }

    #[test]
    fn the_debug_of_an_installation_token_hides_the_token() {
        let token = InstallationToken {
            token: "ghs_secretvalue".to_owned(),
            expires_at: OffsetDateTime::UNIX_EPOCH,
            permissions: BTreeMap::new(),
        };
        let printed = format!("{token:?}");
        assert!(!printed.contains("ghs_"), "{printed}");
        assert!(printed.contains("redacted"), "{printed}");
        assert_eq!(token.expose(), "ghs_secretvalue");
    }
}
