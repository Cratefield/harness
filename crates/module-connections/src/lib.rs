#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;
pub mod presets;
mod seal;
mod service;
mod store;

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use time::Duration;
use zeroize::Zeroizing;

use cratefield_core::{
    Action, AnyError, BoxFuture, Config, ConfigError, DataKind, Disposition, Migrations, Module,
    ModuleContext, Outcome, PersonalDataSet, Port, Problem, RoutePolicy, SqlMigration, Surface,
};

use cratefield_oauth_client::{ClientAuth, OAuthError};
use handlers::Settings;

/// The module's one migration: the `connection` and `connection_state` tables
/// in the portable SQL subset (ADR 0004). Portable means it is also the set
/// the Postgres runner applies, so a `postgres` override is only needed if the
/// SQL ever truly diverges.
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The lowercase-hex SHA-256 of a value. The `state` reaches the database
/// only through this, so a dump, a backup or a query log holds nothing that
/// can be replayed as one.
#[must_use]
pub(crate) fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// The origin of `url`: `scheme://host[:port]`, lower-cased, with a default
/// port dropped. `None` for anything that is not an absolute `http`/`https`
/// URL a browser would treat as one — which is what refuses `//evil.com`
/// (no scheme), `javascript:...` (not a web scheme) and
/// `https://app.example.com@evil.com` (userinfo, so the host is `evil.com`).
#[must_use]
pub(crate) fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty())?;
    if authority.contains('@') {
        // `https://app.example.com@evil.com/` names `evil.com`; refusing the
        // userinfo form outright is the only reading that cannot be tricked.
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    let host = authority.strip_suffix(default_port).unwrap_or(&authority);
    Some(format!("{scheme}://{host}"))
}

/// Percent-encodes one query pair for `application/x-www-form-urlencoded`,
/// leaving the unreserved set alone. `append_query` uses this to build the
/// callback's `Location`, and the callback's own `Query` extractor decodes it
/// back with the same rules, so a `state` or a `connection` id survives the
/// round trip even when it holds a character a naive concatenation would let
/// rewrite the URL.
pub(crate) fn encode_pair(name: &str, value: &str) -> String {
    use std::fmt::Write as _;
    fn encode(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for byte in text.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                _ => {
                    let _ = write!(out, "%{byte:02X}");
                }
            }
        }
        out
    }
    format!("{}={}", encode(name), encode(value))
}

/// A short, printable ASCII token drawn from untrusted text, or `other`.
///
/// Both the OAuth `error` code and the callback's `error` query parameter are
/// provider-controlled and end up in a log line, so anything that is not a
/// short `[A-Za-z0-9._-]` run — embedded newlines, a huge blob, the refused
/// token itself — is replaced wholesale rather than truncated.
#[must_use]
pub(crate) fn safe_token(text: &str) -> &str {
    let tokenish = !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if tokenish { text } else { "other" }
}

/// `url` with one query pair appended — before any `#fragment`, choosing `?`
/// or `&` from what is already in the path.
#[must_use]
pub(crate) fn append_query(url: &str, name: &str, value: &str) -> String {
    let pair = encode_pair(name, value);
    let (head, fragment) = url
        .split_once('#')
        .map_or((url, ""), |(head, fragment)| (head, fragment));
    let separator = if head.contains('?') { '&' } else { '?' };
    if fragment.is_empty() {
        format!("{head}{separator}{pair}")
    } else {
        format!("{head}{separator}{pair}#{fragment}")
    }
}

// ---------------------------------------------------------------------------
// The provider spec

/// One provider a venture lets people connect: where its endpoints live, how
/// it wants the client authenticated, and how it behaves on a refresh.
///
/// Build one from [`presets`] and adjust, or fill in a provider the presets
/// do not carry. No secret lives here — the client id and secret are read
/// from `CONNECTIONS_<KEY>_CLIENT_ID` / `CONNECTIONS_<KEY>_CLIENT_SECRET` at
/// call time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub(crate) key: String,
    pub(crate) authorize_url: String,
    pub(crate) token_url: String,
    pub(crate) revoke_url: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) scope_separator: &'static str,
    pub(crate) client_auth: ClientAuth,
    pub(crate) authorize_params: Vec<(String, String)>,
    pub(crate) rotating_refresh: bool,
    pub(crate) pkce: bool,
}

impl Provider {
    /// A provider keyed `key`, with the given endpoints and space-separated
    /// scopes; `client_secret_post` and no PKCE. Every other knob is set with
    /// the `with_*` methods.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            revoke_url: None,
            scopes: Vec::new(),
            scope_separator: " ",
            client_auth: ClientAuth::ClientSecretPost,
            authorize_params: Vec::new(),
            rotating_refresh: false,
            pkce: false,
        }
    }

    /// The provider's key — the `<key>` in the callback path, the
    /// `CONNECTIONS_<KEY>_*` config prefix and the `provider` on a
    /// [`Connection`].
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Replaces the scope list, e.g.
    /// `presets::gitlab().with_scopes(["read_user", "api"])`.
    #[must_use]
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// The revocation endpoint (RFC 7009), if the provider documents one.
    #[must_use]
    pub fn with_revoke_url(mut self, url: impl Into<String>) -> Self {
        self.revoke_url = Some(url.into());
        self
    }

    /// How the scope list is joined on the wire. Space unless the provider
    /// says otherwise (Linear uses a comma).
    #[must_use]
    pub fn with_scope_separator(mut self, separator: &'static str) -> Self {
        self.scope_separator = separator;
        self
    }

    /// Where the client credentials ride on token calls.
    #[must_use]
    pub fn with_client_auth(mut self, auth: ClientAuth) -> Self {
        self.client_auth = auth;
        self
    }

    /// An extra parameter for the authorize URL — a provider's out-of-band
    /// switch, like Google's `access_type=offline`.
    #[must_use]
    pub fn with_authorize_param(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.authorize_params.push((name.into(), value.into()));
        self
    }

    /// Whether the provider issues a **new** refresh token on every refresh,
    /// which the stored one must be replaced with.
    #[must_use]
    pub fn with_rotating_refresh(mut self, rotating: bool) -> Self {
        self.rotating_refresh = rotating;
        self
    }

    /// Whether to send an S256 PKCE challenge.
    #[must_use]
    pub fn with_pkce(mut self, pkce: bool) -> Self {
        self.pkce = pkce;
        self
    }

    /// The config-key prefix this provider's secrets live under.
    pub(crate) fn env_key(&self) -> String {
        service::env_key(&self.key)
    }

    /// Whether the provider rotates its refresh token. Read by the docs and
    /// the tests; the refresh path does the right thing either way, because
    /// `TokenResponse::rotated_refresh_token` reports what actually happened.
    #[must_use]
    pub fn rotates_refresh(&self) -> bool {
        self.rotating_refresh
    }
}

// ---------------------------------------------------------------------------
// The public types

/// Where a connection stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionStatus {
    /// Tokens are usable; the module will refresh them before they lapse.
    Active,
    /// The provider refused the refresh token; a person must authorize again.
    NeedsReconnect,
    /// Revoked: both tokens are cleared and nothing more can be issued.
    Revoked,
}

impl ConnectionStatus {
    /// The storage value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::NeedsReconnect => "needs_reconnect",
            Self::Revoked => "revoked",
        }
    }

    /// Reads a storage value. A value this crate did not write is treated as
    /// needing a reconnect rather than as active — the safe reading of an
    /// unknown state is "do not use its tokens".
    #[must_use]
    pub(crate) fn parse(raw: &str) -> Self {
        match raw {
            "active" => Self::Active,
            "revoked" => Self::Revoked,
            _ => Self::NeedsReconnect,
        }
    }
}

/// A connected account, as a venture reads it. **It never carries a token** —
/// the access token is a separate call ([`ConnectionsApi::access_token`]),
/// so a token cannot leak by someone serializing a `Connection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// The connection's id — stable, and what every other call takes.
    pub id: String,
    /// The subject this connection belongs to.
    pub subject: String,
    /// The provider key.
    pub provider: String,
    /// The provider-side account id, once a venture has learned it.
    pub external_account_id: Option<String>,
    /// The name to show a person for this account.
    pub display_name: Option<String>,
    /// The scopes the provider actually granted.
    pub scopes: Vec<String>,
    /// Where the connection stands.
    pub status: ConnectionStatus,
    /// When the access token lapses, RFC 3339 UTC. `None` when the provider
    /// stated no lifetime.
    pub access_expires_at: Option<String>,
    /// When the refresh token lapses, when the provider said.
    pub refresh_expires_at: Option<String>,
    /// Why the connection needs a reconnect, when it does.
    pub last_error: Option<String>,
    /// When the connection was made.
    pub created_at: String,
    /// When it last changed.
    pub updated_at: String,
}

impl From<store::ConnectionRow> for Connection {
    fn from(row: store::ConnectionRow) -> Self {
        Self {
            id: row.id,
            subject: row.subject,
            provider: row.provider,
            external_account_id: row.external_account_id,
            display_name: row.display_name,
            scopes: store::scopes_of(&row.scopes),
            status: ConnectionStatus::parse(&row.status),
            access_expires_at: row.access_expires_at,
            refresh_expires_at: row.refresh_expires_at,
            last_error: row.last_error,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// A live access token for one connection. It is wiped on drop and its
/// `Debug` prints nothing, so a token cannot reach a log or a panic message
/// by accident. Its value is only reachable through [`AccessToken::expose`],
/// which is the one place a caller has to mean it.
pub struct AccessToken {
    connection_id: String,
    token: Zeroizing<String>,
    expires_at: Option<String>,
}

impl AccessToken {
    pub(crate) fn new(
        connection_id: String,
        token: Zeroizing<String>,
        expires_at: Option<String>,
    ) -> Self {
        Self {
            connection_id,
            token,
            expires_at,
        }
    }

    /// The connection this token belongs to.
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// The bearer token itself. Deliberately not `Deref`: taking it should be
    /// a call a reader can see.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.token
    }

    /// Takes the token out, to hand to an
    /// [`HttpClient`](cratefield_core::HttpClient) header and drop.
    #[must_use]
    pub fn into_secret(self) -> Zeroizing<String> {
        self.token
    }

    /// When the token lapses, RFC 3339 UTC.
    #[must_use]
    pub fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("connection_id", &self.connection_id)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The URL a browser opens to start a connection, and the deadline on the
/// `state` that goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeUrl {
    /// The provider authorization URL, with state, PKCE challenge and scopes.
    pub url: String,
    /// When the state stops being usable, RFC 3339 UTC.
    pub expires_at: String,
    /// The provider key this URL is for.
    pub provider: String,
}

/// A failed provider call, reduced to the two facts this module will show or
/// record: the HTTP status it answered with and the RFC 6749 §5.2 `error`
/// code. The oauth client's own error carries the provider's
/// `error_description` and raw body, and a token endpoint can echo the very
/// token it refused in that prose — so none of it is kept. This type is
/// therefore safe to log, to store in `last_error`, and to hand to a venture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFailure {
    /// The HTTP status the provider answered with; `None` when the call never
    /// reached it (a transport or decode failure).
    pub status: Option<u16>,
    /// The §5.2 `error` code when it was short ASCII token-ish text, else
    /// `other`; `transport`, `decode`, `config` or `no_revoke_endpoint` for a
    /// failure that is ours rather than the provider's.
    pub code: String,
}

impl ProviderFailure {
    /// Reduces the oauth client's error to the fields that are safe to keep.
    #[must_use]
    pub fn of(error: &OAuthError) -> Self {
        match error {
            OAuthError::Provider(inner) => Self {
                status: Some(inner.status),
                code: safe_token(&inner.code).to_owned(),
            },
            OAuthError::Transport(_) => Self {
                status: None,
                code: "transport".to_owned(),
            },
            OAuthError::Decode(_) => Self {
                status: None,
                code: "decode".to_owned(),
            },
            OAuthError::Config(_) => Self {
                status: None,
                code: "config".to_owned(),
            },
            OAuthError::NoRevokeEndpoint => Self {
                status: None,
                code: "no_revoke_endpoint".to_owned(),
            },
        }
    }
}

impl std::fmt::Display for ProviderFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => write!(f, "the provider answered {status} (error `{}`)", self.code),
            None => write!(f, "the provider call failed ({})", self.code),
        }
    }
}

impl std::error::Error for ProviderFailure {}

/// What a connection call can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectionError {
    /// The provider key is not one this venture configured.
    #[error("`{0}` is not a configured provider")]
    UnknownProvider(String),
    /// The `return_to` is not on an allowed origin.
    #[error("`{0}` is not on an allowed origin")]
    OriginNotAllowed(String),
    /// The state is unknown, spent or expired.
    #[error("the connect state is unknown, spent or expired")]
    BadState,
    /// No connection carries the id.
    #[error("no connection with id `{0}`")]
    NotFound(String),
    /// The provider requires a fresh authorization.
    #[error("the connection needs to be reconnected: {0}")]
    NeedsReconnect(String),
    /// The connection was revoked.
    #[error("the connection was revoked")]
    Revoked,
    /// The provider's token endpoint failed or answered with a non-token.
    #[error(transparent)]
    Provider(ProviderFailure),
    /// The module is misconfigured, or a sealed value could not be read.
    #[error("connections is misconfigured: {0}")]
    Config(String),
    /// A database failure.
    #[error(transparent)]
    Db(#[from] cratefield_core::DbError),
}

impl ConnectionError {
    /// The RFC 9457 `type` slug this failure maps to, so a route the venture
    /// writes can answer the callback's `error=<slug>` convention.
    #[must_use]
    pub fn slug(&self) -> &'static str {
        handlers::problem_for(self).slug
    }

    /// The problem body a caller should answer with.
    #[must_use]
    pub fn problem(&self) -> Problem {
        handlers::problem_for(self)
    }

    /// The structured, safe facts of a provider failure, when this is one —
    /// what a log line records instead of the error's `Display`.
    #[must_use]
    pub fn provider_failure(&self) -> Option<&ProviderFailure> {
        match self {
            Self::Provider(failure) => Some(failure),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The module and its builder

/// The connections module (issue #624). Compose it with
/// [`Connections::builder`], and reach the lifecycle through
/// [`Connections::api`].
pub struct Connections {
    settings: Settings,
    /// The context of the first `router` build. A module is mounted twice in
    /// some deployments; the first wins, so the API handle never disagrees
    /// with the routes about which ports it has.
    ctx: Arc<OnceLock<Arc<ModuleContext>>>,
}

impl Default for Connections {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Connections {
    /// A builder with no providers and no allowed origins.
    #[must_use]
    pub fn builder() -> ConnectionsBuilder {
        ConnectionsBuilder::new()
    }

    /// A handle for calling the lifecycle from anywhere else in the venture —
    /// a route, a scheduled job, an event handler. It shares the module's
    /// settings, so it can only reach the providers this venture configured.
    #[must_use]
    pub fn api(&self) -> ConnectionsApi {
        ConnectionsApi {
            ctx: Arc::clone(&self.ctx),
            settings: self.settings.clone(),
        }
    }
}

/// Builds a [`Connections`].
pub struct ConnectionsBuilder {
    settings: Settings,
}

impl ConnectionsBuilder {
    fn new() -> Self {
        Self {
            settings: Settings {
                providers: Vec::new(),
                allowed_origins: Vec::new(),
                refresh_lead_secs: service::DEFAULT_REFRESH_LEAD_SECS,
            },
        }
    }

    /// Adds a provider. Two providers with the same key: the later wins, so
    /// a venture can override a preset's scopes by adding its own after it.
    #[must_use]
    pub fn provider(mut self, provider: Provider) -> Self {
        self.settings
            .providers
            .retain(|existing| existing.key != provider.key);
        self.settings.providers.push(provider);
        self
    }

    /// Adds several providers at once.
    #[must_use]
    pub fn providers<I>(mut self, providers: I) -> Self
    where
        I: IntoIterator<Item = Provider>,
    {
        for provider in providers {
            self = self.provider(provider);
        }
        self
    }

    /// An origin a `return_to` may live on, e.g. `https://app.example.com`. A
    /// `return_to` off every allowed origin is refused before a state is
    /// written and again before any redirect, so a stolen `state` cannot be
    /// turned into an open redirect. Only the origin is kept: a path, query or
    /// fragment is dropped.
    ///
    /// # Panics
    ///
    /// Panics when `origin` is not an absolute `http(s)` origin — a bare host,
    /// a relative path, a non-web scheme. Such a value could never match a
    /// `return_to`, which always parses to an origin, so accepting it would
    /// silently refuse every start; failing at the call site names the mistake
    /// where it was made.
    #[must_use]
    pub fn allowed_origin(mut self, origin: impl AsRef<str>) -> Self {
        let raw = origin.as_ref();
        let normalized = origin_of(raw).unwrap_or_else(|| {
            panic!("connections: `{raw}` is not an absolute http(s) origin, e.g. https://app.example.com")
        });
        if !self.settings.allowed_origins.contains(&normalized) {
            self.settings.allowed_origins.push(normalized);
        }
        self
    }

    /// How long before an access token lapses to refresh it. A negative lead
    /// is clamped to zero, which makes a refresh due only at expiry.
    #[must_use]
    pub fn refresh_lead(mut self, lead: Duration) -> Self {
        self.settings.refresh_lead_secs = lead.whole_seconds().max(0);
        self
    }

    /// Finishes the module.
    #[must_use]
    pub fn build(self) -> Connections {
        Connections {
            settings: self.settings,
            ctx: Arc::new(OnceLock::new()),
        }
    }
}

/// The venture-facing lifecycle handle. Every method names its subject or
/// connection explicitly — there is no "current caller" here.
#[derive(Clone)]
pub struct ConnectionsApi {
    ctx: Arc<OnceLock<Arc<ModuleContext>>>,
    settings: Settings,
}

impl ConnectionsApi {
    fn ctx(&self) -> Result<Arc<ModuleContext>, ConnectionError> {
        self.ctx.get().cloned().ok_or_else(|| {
            ConnectionError::Config(
                "the connections module has not been mounted yet; build the harness first"
                    .to_owned(),
            )
        })
    }

    /// Starts a connection for `subject`, returning the URL to send the
    /// browser to. Refuses a `return_to` off the venture's allowed origins.
    /// # Errors
    /// See [`ConnectionError`].
    pub async fn start(
        &self,
        subject: &str,
        provider: &str,
        return_to: &str,
    ) -> Result<AuthorizeUrl, ConnectionError> {
        service::start(
            self.ctx()?.as_ref(),
            &self.settings,
            subject,
            provider,
            return_to,
        )
        .await
    }

    /// Completes a connection from the callback's `state` and `code`. Exactly
    /// one caller per state succeeds.
    /// # Errors
    /// See [`ConnectionError`].
    pub async fn complete(&self, state: &str, code: &str) -> Result<Connection, ConnectionError> {
        service::complete(self.ctx()?.as_ref(), &self.settings, state, code).await
    }

    /// A subject's connections.
    /// # Errors
    /// See [`ConnectionError`].
    pub async fn list(&self, subject: &str) -> Result<Vec<Connection>, ConnectionError> {
        service::list(self.ctx()?.as_ref(), subject).await
    }

    /// One connection by id.
    /// # Errors
    /// See [`ConnectionError`].
    pub async fn get(&self, connection_id: &str) -> Result<Connection, ConnectionError> {
        service::get(self.ctx()?.as_ref(), connection_id).await
    }

    /// A live access token for `connection_id`, refreshed first when due.
    /// # Errors
    /// See [`ConnectionError`].
    pub async fn access_token(&self, connection_id: &str) -> Result<AccessToken, ConnectionError> {
        service::access_token(self.ctx()?.as_ref(), &self.settings, connection_id).await
    }

    /// Revokes a connection: the provider is asked to drop the tokens, the
    /// row is marked revoked and its ciphertexts are cleared.
    /// # Errors
    /// See [`ConnectionError`].
    pub async fn revoke(&self, connection_id: &str) -> Result<(), ConnectionError> {
        service::revoke(self.ctx()?.as_ref(), &self.settings, connection_id).await
    }

    /// Marks a connection as needing a new authorization.
    /// # Errors
    /// See [`ConnectionError`].
    pub async fn mark_needs_reconnect(
        &self,
        connection_id: &str,
        reason: &str,
    ) -> Result<(), ConnectionError> {
        service::mark_needs_reconnect(self.ctx()?.as_ref(), connection_id, reason).await
    }

    /// Records the provider-side account id and display name for a
    /// connection.
    /// # Errors
    /// See [`ConnectionError`].
    pub async fn set_account(
        &self,
        connection_id: &str,
        external_account_id: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<(), ConnectionError> {
        service::set_account(
            self.ctx()?.as_ref(),
            connection_id,
            external_account_id,
            display_name,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// The module

#[async_trait]
impl Module for Connections {
    fn name(&self) -> &'static str {
        "connections"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// The connections live in a database, and both the connect and the
    /// refresh legs talk to the provider: without `HttpClient` there is no
    /// connection to make and without `Db` none to keep.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::HttpClient]
    }

    /// `Clock` decides "now" for expiry and the refresh lead; `IdGen` mints
    /// connection ids; `Defer` is what events are emitted through. Each has a
    /// working default, so none is required.
    fn optional(&self) -> &'static [Port] {
        &[Port::Clock, Port::IdGen, Port::Defer]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["connection", "connection_state"]
    }

    /// Both tables are a subject's. `connection` is the account they
    /// connected — the provider, the provider-side account id and the name to
    /// show them — and the two token columns are held but never exported: a
    /// token is a bearer credential, so a copy in an export file is a copy of
    /// the credential (ADR 0015). `connection_state` is an attempt in flight,
    /// which names the subject too; its `state` is present only as a hash and
    /// its PKCE verifier only as ciphertext, both redacted.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        static SETS: OnceLock<Vec<PersonalDataSet>> = OnceLock::new();
        SETS.get_or_init(|| {
            vec![
                PersonalDataSet {
                    table: "connection",
                    subject: "subject",
                    kind: DataKind::Identifier,
                    disposition: Disposition::Erase,
                    description: "A third-party account you connected: the provider, the \
                        account id and name it gave us, the scopes, and the live status. The \
                        access and refresh tokens are held only as ciphertext and are never \
                        copied into an export or a response.",
                    redacted: &["access_token_sealed", "refresh_token_sealed"],
                    subject_via: None,
                },
                PersonalDataSet {
                    table: "connection_state",
                    subject: "subject",
                    kind: DataKind::Identifier,
                    disposition: Disposition::Erase,
                    description: "A connection attempt still in flight: where the browser was \
                        sent and when it lapses. The anti-forgery state is held only as a \
                        SHA-256 hash and the PKCE verifier only as ciphertext. Once spent, or \
                        ten minutes old, the row is deleted.",
                    redacted: &["state_hash", "verifier_sealed"],
                    subject_via: None,
                },
            ]
        })
        .as_slice()
    }

    /// The four transitions a venture may want to react to. Payloads name the
    /// connection id, the subject and the provider — never a token.
    fn emits(&self) -> &'static [&'static str] {
        &[
            handlers::EVENT_CONNECTED,
            handlers::EVENT_REFRESHED,
            handlers::EVENT_REVOKED,
            handlers::EVENT_NEEDS_RECONNECT,
        ]
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    /// `CONNECTIONS_TOKEN_KEY` (32 bytes of base64) is required, and so is a
    /// client id and secret for every provider the venture composed — a
    /// provider with no secret cannot exchange a code, so it is a build
    /// error rather than a callback that fails in production.
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        handlers::validate(&self.settings, cfg).into_result()
    }

    /// The composition a build must refuse: no providers to connect, no
    /// origins to return to, or a provider key that cannot be a path segment.
    fn self_check(&self) -> Vec<String> {
        handlers::self_check(&self.settings)
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let ctx = Arc::new(ctx);
        // A module can be mounted twice (in-process and as a sidecar); the
        // first context wins, so the API handle and the routes always agree
        // about which ports they hold.
        let _ = self.ctx.set(Arc::clone(&ctx));
        handlers::router(ctx, self.settings.clone())
    }

    /// The one route: the provider's redirect target.
    ///
    /// It is a public write, and declared `Open` on purpose. A provider's
    /// redirect is exactly what it is — the browser carries a `state` this
    /// module minted and a `code` for a request this module started, and the
    /// route authenticates itself by spending that single-use `state`. There
    /// is nothing for a CAPTCHA to gate and no cookie to check: the state is
    /// the whole proof, and a spent or unknown one answers a problem.
    fn surface(&self) -> Surface {
        Surface::new().action(
            Action::get("callback", "/callback/{provider}")
                .policy(RoutePolicy::Open)
                .outcome(Outcome::Redirect),
        )
    }

    /// The scheduled pass: purge spent and expired states, then refresh the
    /// connections due within the lead, one `try_spend(1)` per unit so the
    /// invocation's budget is respected (ADR 0023).
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            if let Err(error) = service::maintain(ctx, &self.settings).await {
                let failure = error.provider_failure();
                tracing::warn!(
                    cron,
                    slug = error.slug(),
                    status = ?failure.and_then(|failure| failure.status),
                    code = failure.map_or("-", |failure| failure.code.as_str()),
                    "the scheduled connections pass did not complete"
                );
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pair is appended before a fragment, so a `return_to` that carries one
    /// (`.../settings#tab`) keeps it.
    #[test]
    fn a_query_pair_goes_before_the_fragment() {
        assert_eq!(
            append_query("https://app.example.com/settings#tab", "connection", "c-1"),
            "https://app.example.com/settings?connection=c-1#tab"
        );
        assert_eq!(
            append_query("https://app.example.com/settings?a=1#tab", "b", "2"),
            "https://app.example.com/settings?a=1&b=2#tab"
        );
        assert_eq!(
            append_query("https://app.example.com/s", "b", "2"),
            "https://app.example.com/s?b=2"
        );
    }

    /// Only a short ASCII token survives: anything a provider could put in an
    /// `error` field — a newline, a huge blob, the refused token — is `other`.
    #[test]
    fn only_a_short_token_survives_sanitising() {
        assert_eq!(safe_token("access_denied"), "access_denied");
        assert_eq!(safe_token("invalid_grant"), "invalid_grant");
        assert_eq!(safe_token("line\nbreak"), "other");
        assert_eq!(safe_token(""), "other");
        assert_eq!(safe_token(&"x".repeat(65)), "other");
    }

    /// A value that is not an origin is refused where it is written, rather
    /// than stored so that every `start` is then silently refused.
    #[test]
    #[should_panic(expected = "is not an absolute http(s) origin")]
    fn a_bad_allowed_origin_panics() {
        let _ = Connections::builder().allowed_origin("app.example.com");
    }
}
