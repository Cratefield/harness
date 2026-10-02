//! The OAuth 2.0 device authorization grant (RFC 8628) as a harness
//! module (issue #587): a client with no browser and no keyboard shows a
//! short code, a signed-in person approves it in a browser, and the
//! venture's own issuer mints the credential.
//!
//! The module owns the three things RFC 8628 leaves to the server — the
//! code pair, the polling state machine and the approval page — and
//! delegates the two things only a venture can answer, each behind a
//! builder-set hook:
//!
//! - [`Approver`] answers *who is asking to approve*: a subject, or a
//!   redirect to sign in. [`CallerApprover`] is the stock implementation
//!   over the `Auth` port.
//! - [`Issuer`] answers *what credential does this client get*: it is
//!   called exactly once, when a poll wins the consume, and returns the
//!   JSON body the client receives.
//!
//! See `docs/DEVICE-AUTH.md` for the flow, the endpoints and the worked
//! example; the client side of the flow lives in
//! `cratefield_oauth_client::device`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod handlers;
mod store;

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use time::Duration;

use cratefield_core::{
    Action, AnyError, Audience, Auth, BoxFuture, Caller, Config, ConfigError, DataKind,
    Disposition, Migrations, Module, ModuleContext, Outcome, PersonalDataSet, Port, RandomBytes,
    RoutePolicy, SqlMigration, Surface, View,
};

/// How long a device code stays usable by default: ten minutes.
pub const DEFAULT_EXPIRES_IN: Duration = Duration::seconds(600);

/// The interval RFC 8628 §3.5 asks a client to poll at by default.
pub const DEFAULT_INTERVAL: Duration = Duration::seconds(5);

/// The wrong-entry allowance per approver before the limiter refuses,
/// by default.
pub const DEFAULT_MAX_WRONG_ENTRIES: u32 = 5;

/// The module's one migration: the `device_auth_codes` table in the
/// portable SQL subset (ADR 0004).
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

// ---------------------------------------------------------------------------
// The codes

/// The lowercase-hex SHA-256 of a value. Both device codes reach the
/// database only through this function, so a dump, a backup or a query log
/// holds nothing that can be replayed as a code.
#[must_use]
pub(crate) fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// The storage form of a device code.
#[must_use]
pub(crate) fn device_code_hash(code: &str) -> String {
    sha256_hex(code)
}

/// The storage form of a user code.
#[must_use]
pub(crate) fn user_code_hash(code: &str) -> String {
    sha256_hex(code)
}

/// A user code as it is compared and stored: upper-cased, with the
/// separator and any whitespace a person or a terminal introduced removed.
/// The alphabet has no digits or punctuation, so anything else a person
/// typed is not part of a code and does not survive either.
#[must_use]
pub(crate) fn normalize_user_code(raw: &str) -> String {
    raw.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

// ---------------------------------------------------------------------------
// Hooks

/// What an [`Approver`] says about the person behind a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// The person is signed in, as this subject. It becomes the
    /// `approver_subject` the credential is issued for.
    Subject(String),
    /// The person must sign in first; the browser is sent to this URL,
    /// which the approver built so that it comes back to the device page.
    SignIn { location: String },
}

/// Why an approver could not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the approver could not answer: {0}")]
pub struct ApproverError(String);

impl ApproverError {
    /// An error carrying the approver's own words.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Decides who may approve a device. The browser cannot reach the approval
/// page or submit a decision without passing through one of these.
#[async_trait]
pub trait Approver: Send + Sync {
    /// Identifies the caller, or says where to send them to sign in.
    ///
    /// `headers` is the whole browser request's headers — a session cookie
    /// lives there and in nowhere else. `return_to` is the same-site path
    /// and query of the device page (never an absolute URL, which a sign-in
    /// flow would refuse as an open redirect), including the `user_code`
    /// query when there is one, so a sign-in flow can come straight back to
    /// the decision.
    ///
    /// # Errors
    ///
    /// Whatever a sign-in implementation could not answer.
    async fn approve(
        &self,
        headers: &HeaderMap,
        return_to: &str,
    ) -> Result<Approval, ApproverError>;
}

/// The stock approver: the `Auth` port's [`Caller`]. A verified caller is
/// a subject; an anonymous one is sent to `sign_in_url` with `return_to`
/// appended.
pub struct CallerApprover {
    auth: Arc<dyn Auth>,
    sign_in_url: String,
}

impl CallerApprover {
    /// An approver over `auth` that sends anonymous visitors to
    /// `sign_in_url`.
    #[must_use]
    pub fn new(auth: Arc<dyn Auth>, sign_in_url: impl Into<String>) -> Self {
        Self {
            auth,
            sign_in_url: sign_in_url.into(),
        }
    }
}

#[async_trait]
impl Approver for CallerApprover {
    async fn approve(
        &self,
        headers: &HeaderMap,
        return_to: &str,
    ) -> Result<Approval, ApproverError> {
        match self.auth.identify(headers).await {
            Ok(Caller::Subject(subject)) => Ok(Approval::Subject(subject.id)),
            Ok(Caller::Anonymous) => Ok(Approval::SignIn {
                location: sign_in_location(&self.sign_in_url, return_to),
            }),
            // `Caller` is `#[non_exhaustive]`: a variant this crate does
            // not know is not a person, so it is refused rather than
            // guessed at.
            Ok(_) => Err(ApproverError::new(
                "the auth port returned a caller this approver does not recognise",
            )),
            Err(err) => Err(ApproverError::new(err.to_string())),
        }
    }
}

/// `sign_in_url` with `return_to` appended as a query parameter, using the
/// same encoder the form endpoints read.
fn sign_in_location(sign_in_url: &str, return_to: &str) -> String {
    #[derive(serde::Serialize)]
    struct ReturnTo<'a> {
        return_to: &'a str,
    }
    let separator = if sign_in_url.contains('?') { '&' } else { '?' };
    let query = serde_urlencoded::to_string(ReturnTo { return_to }).unwrap_or_default();
    format!("{sign_in_url}{separator}{query}")
}

/// What an [`Issuer`] is asked to mint a credential for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRequest {
    /// The subject that approved the device.
    pub subject: String,
    /// The client the code was issued to.
    pub client_id: String,
    /// The device label the client supplied, when it did.
    pub name: Option<String>,
    /// The scopes the client asked for, all of them allowed.
    pub scopes: Vec<String>,
}

/// Why an issuer could not mint a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the issuer could not mint a credential: {0}")]
pub struct IssuerError(String);

impl IssuerError {
    /// An error carrying the issuer's own words.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Mints the credential a client receives once its device code is
/// approved.
///
/// It is called **exactly once** per approved request — the poll that wins
/// the guarded `approved` → `consumed` update calls it, and a poll that
/// loses the race is told `expired_token` rather than given a second
/// credential. An issuer that fails leaves the code spent and the
/// credential unminted: the person re-runs the client. That is deliberate;
/// see `docs/DEVICE-AUTH.md`.
#[async_trait]
pub trait Issuer: Send + Sync {
    /// Mints the credential, returning the JSON body the client receives.
    ///
    /// # Errors
    ///
    /// Whatever the venture's key-minting could not do. The caller answers
    /// `500` and the device code stays consumed.
    async fn issue(&self, request: IssueRequest) -> Result<serde_json::Value, IssuerError>;
}

// ---------------------------------------------------------------------------
// A client

/// One client allowed to run the device grant. Declaring it is what makes
/// its `client_id` valid and its scopes the only scopes it may ask for.
#[derive(Debug, Clone)]
pub struct DeviceClient {
    id: String,
    scopes: Vec<String>,
}

impl DeviceClient {
    /// A client with this id and no scopes.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            scopes: Vec::new(),
        }
    }

    /// Declares the whole scope list. Replaces any previous list.
    #[must_use]
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// The client id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The scopes this client may ask for.
    #[must_use]
    pub fn declared_scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Whether this client declared `scope`.
    #[must_use]
    pub(crate) fn declares_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|declared| declared == scope)
    }
}

// ---------------------------------------------------------------------------
// The module and its builder

/// The device authorization grant (RFC 8628) over the harness's own ports.
pub struct DeviceAuth {
    settings: handlers::Settings,
}

impl Default for DeviceAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceAuth {
    /// A builder with no clients, no hooks and the RFC 8628 defaults. It
    /// is not a working composition until `.client(..)`, `.issuer(..)` and
    /// `.random(..)` are set; [`Module::self_check`] names what is missing.
    #[must_use]
    pub fn builder() -> DeviceAuthBuilder {
        DeviceAuthBuilder::new()
    }

    /// Short for [`DeviceAuth::builder().build()`](DeviceAuth::builder).
    #[must_use]
    pub fn new() -> Self {
        DeviceAuthBuilder::new().build()
    }
}

/// Builds a [`DeviceAuth`]. Everything the module cannot decide for a
/// venture — who its clients are, who may approve, what a credential looks
/// like, where entropy comes from — is set here.
pub struct DeviceAuthBuilder {
    settings: handlers::Settings,
}

impl Default for DeviceAuthBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceAuthBuilder {
    /// The RFC 8628 defaults: a ten-minute code, a five-second poll
    /// interval and a five-wrong-entry allowance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            settings: handlers::Settings {
                clients: Vec::new(),
                approver: None,
                issuer: None,
                random: None,
                sign_in_url: None,
                expires_in_secs: DEFAULT_EXPIRES_IN.whole_seconds(),
                interval_secs: DEFAULT_INTERVAL.whole_seconds(),
                max_wrong_entries: DEFAULT_MAX_WRONG_ENTRIES,
            },
        }
    }

    /// Adds one client. Repeatable.
    #[must_use]
    pub fn client(mut self, client: DeviceClient) -> Self {
        self.settings.clients.push(client);
        self
    }

    /// Declares the whole client list. Replaces any previous one.
    #[must_use]
    pub fn clients(mut self, clients: impl IntoIterator<Item = DeviceClient>) -> Self {
        self.settings.clients = clients.into_iter().collect();
        self
    }

    /// Sets the approver hook. Without one, the module uses
    /// [`CallerApprover`] over the `Auth` port when a deployment mounts
    /// one.
    #[must_use]
    pub fn approver(mut self, approver: impl Approver + 'static) -> Self {
        self.settings.approver = Some(Arc::new(approver));
        self
    }

    /// Sets the issuer hook.
    #[must_use]
    pub fn issuer(mut self, issuer: impl Issuer + 'static) -> Self {
        self.settings.issuer = Some(Arc::new(issuer));
        self
    }

    /// Sets the entropy source the two codes are drawn from. Required:
    /// core carries no CSPRNG, so the venture supplies one (ADR 0002).
    #[must_use]
    pub fn random(mut self, random: impl RandomBytes + 'static) -> Self {
        self.settings.random = Some(Arc::new(random));
        self
    }

    /// Where the stock [`CallerApprover`] sends an anonymous browser.
    /// Defaults to `/login`.
    #[must_use]
    pub fn sign_in_url(mut self, url: impl Into<String>) -> Self {
        self.settings.sign_in_url = Some(url.into());
        self
    }

    /// How long a device code stays usable. Clamped to at least one
    /// second, and at most [`MAX_EXPIRES_IN`].
    #[must_use]
    pub fn expires_in(mut self, ttl: Duration) -> Self {
        self.settings.expires_in_secs =
            ttl.whole_seconds().clamp(1, MAX_EXPIRES_IN.whole_seconds());
        self
    }

    /// The poll interval a client is told to use, and the shortest gap a
    /// poll may arrive at. Clamped to at least one second.
    #[must_use]
    pub fn interval(mut self, interval: Duration) -> Self {
        self.settings.interval_secs = interval.whole_seconds().max(1);
        self
    }

    /// The wrong-entry allowance per approver before the limiter refuses.
    /// Clamped to at least one.
    #[must_use]
    pub fn max_wrong_entries(mut self, allowance: u32) -> Self {
        self.settings.max_wrong_entries = allowance.max(1);
        self
    }

    /// Builds the module.
    #[must_use]
    pub fn build(self) -> DeviceAuth {
        DeviceAuth {
            settings: self.settings,
        }
    }
}

/// The longest a device code may live: 24 hours. RFC 8628 §3.2's
/// `expires_in` is a hint to the client, and a code that outlives a
/// working day is one nobody is waiting for.
pub const MAX_EXPIRES_IN: Duration = Duration::seconds(24 * 60 * 60);

impl Module for DeviceAuth {
    fn name(&self) -> &'static str {
        "device-auth"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// The codes live in the database, and the polling route is public:
    /// the limiter is the abuse control it actually has. Both are
    /// requirements rather than options — a deployment without a limiter
    /// mounted would serve an unthrottled public poll endpoint, which is
    /// what production readiness exists to refuse (issue #562).
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::RateLimiter]
    }

    /// The Clock decides "now" for expiry and the poll interval. The Auth
    /// port is what the stock [`CallerApprover`] identifies callers with;
    /// a deployment that builds its own approver does not need it, so it
    /// is optional rather than required.
    fn optional(&self) -> &'static [Port] {
        &[Port::Clock, Port::Auth]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["device_auth_codes"]
    }

    /// One row per request, and the row is the approver's: it names who
    /// approved the device (`approver_subject`) and carries the label the
    /// client put on it (`name`, which is whatever the client chose to
    /// call the device — "Alice's laptop").
    ///
    /// The codes themselves are stored only as hashes and are not the
    /// subject: a `device_code` is a bearer credential with no person
    /// behind it, and a `user_code` is eight letters off a screen. The
    /// subject is the person who pressed Approve, and an erasure request
    /// that names them deletes the row.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        static SETS: OnceLock<Vec<PersonalDataSet>> = OnceLock::new();
        SETS.get_or_init(|| {
            vec![PersonalDataSet {
                table: "device_auth_codes",
                subject: "approver_subject",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "Who approved a device sign-in, for which client, when, and the \
                    label the client gave the device (`name`). The codes themselves are held \
                    only as SHA-256 hashes, so a row here cannot be replayed as a credential. \
                    Erasing the approver's rows deletes them; the scheduled purge removes \
                    every row past its expiry anyway.",
                redacted: &[],
                subject_via: None,
            }]
        })
        .as_slice()
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    /// No configuration keys of its own: the composition is what a
    /// venture decides, and `self_check` reports a composition that cannot
    /// serve a device sign-in.
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    /// The composition a build must refuse. A device grant with no clients
    /// can authorize nobody; one with no issuer mints nothing; one with no
    /// entropy source cannot draw a code. Reported here rather than in
    /// `validate_config` because none of it comes from the environment —
    /// it is what the venture composed, and the fix is in the composition.
    fn self_check(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.settings.clients.is_empty() {
            problems.push(
                "device-auth: no clients are declared, so no client_id will ever be accepted — \
                 add `.client(DeviceClient::new(\"…\"))` (RFC 8628 §3.1)"
                    .to_owned(),
            );
        }
        for (index, client) in self.settings.clients.iter().enumerate() {
            if client.id.trim().is_empty() || client.id.contains(char::is_whitespace) {
                problems.push(format!(
                    "device-auth: client #{index} has an id that is empty or contains \
                     whitespace; a client_id must be a single token"
                ));
            }
            if let Some(bad) = client
                .declared_scopes()
                .iter()
                .find(|scope| scope.is_empty() || scope.contains(char::is_whitespace))
            {
                problems.push(format!(
                    "device-auth: client `{}` declares the scope {bad:?}, which is empty or \
                     contains whitespace; scopes are space-separated tokens",
                    client.id()
                ));
            }
        }
        if self.settings.issuer.is_none() {
            problems.push(
                "device-auth: no issuer is set, so an approved device would mint nothing — add \
                 `.issuer(..)`"
                    .to_owned(),
            );
        }
        if self.settings.random.is_none() {
            problems.push(
                "device-auth: no entropy source is set, so no device or user code can be \
                 drawn — add `.random(..)`"
                    .to_owned(),
            );
        }
        problems
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(ctx, self.settings.clone())
    }

    /// The two machine routes, the browser page and the two decision
    /// forms.
    ///
    /// All four writes are [`RoutePolicy::Open`], and deliberately so.
    /// `/code` and `/token` are called by a program, so a CAPTCHA is
    /// meaningless and a signed link would demand a `Signer` key ring this
    /// module never issues from — their proof is the single-use
    /// `device_code` the module itself minted, and their abuse control is
    /// the `RateLimiter` the module requires (plus the poll interval
    /// `/token` enforces). `/approve` and `/deny` are the browser's, and
    /// the handler authenticates them itself: they need a signed-in
    /// approver, which is [`Audience::Subject`] here, and the same-origin
    /// check runs before the body is trusted.
    fn surface(&self) -> Surface {
        Surface::new()
            .action(
                Action::post("request-code", "/code")
                    .policy(RoutePolicy::Open)
                    .outcome(Outcome::Json)
                    .input_schema(cratefield_core::schema_for::<handlers::DeviceCodeParams>())
                    .output::<handlers::DeviceCodeResponse>(),
            )
            .action(
                Action::post("poll-token", "/token")
                    .policy(RoutePolicy::Open)
                    .outcome(Outcome::Json)
                    .input_schema(cratefield_core::schema_for::<handlers::DeviceTokenParams>()),
            )
            .action(
                Action::post("approve", "/approve")
                    .policy(RoutePolicy::Open)
                    .audience(Audience::Subject)
                    .input_schema(cratefield_core::schema_for::<handlers::DecisionParams>())
                    .accepted("Device approved. You can return to your terminal."),
            )
            .action(
                Action::post("deny", "/deny")
                    .policy(RoutePolicy::Open)
                    .audience(Audience::Subject)
                    .input_schema(cratefield_core::schema_for::<handlers::DecisionParams>())
                    .accepted("Request denied."),
            )
            .action(Action::get("page", "/").audience(Audience::Subject))
            .view(View::form("page"))
    }

    /// The scheduled purge: rows past their expiry are deleted, because
    /// an expired code is useless to both sides — the client is told
    /// `expired_token` and the approver is told the code is gone. One
    /// statement, so it spends one unit of the invocation's budget (ADR
    /// 0023) and leaves the rest to the modules behind it.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            if !ctx.scheduled.try_spend(1) {
                return Ok(());
            }
            let Some(db) = ctx.ports.db.clone() else {
                return Ok(());
            };
            let now = handlers::stamp(handlers::now_of(ctx));
            let deleted = store::purge_expired(&*db, &now)
                .await
                .map_err(|err| Box::new(err) as AnyError)?;
            if deleted > 0 {
                tracing::info!(
                    deleted,
                    cron,
                    "purged expired device authorization requests"
                );
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module() -> DeviceAuth {
        DeviceAuth::builder()
            .client(DeviceClient::new("sealb-cli").scopes(["read", "write"]))
            .build()
    }

    #[test]
    fn module_metadata() {
        let module = module();
        assert_eq!(module.name(), "device-auth");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(module.requires(), [Port::Db, Port::RateLimiter]);
        assert_eq!(module.optional(), [Port::Clock, Port::Auth]);
        assert_eq!(module.tables(), ["device_auth_codes"]);
        assert_eq!(module.migrations().sqlite.len(), 1);
        assert!(
            module.migrations().postgres.is_empty(),
            "sqlite migrations only"
        );
        assert!(!module.surface().is_empty());
    }

    #[test]
    fn the_defaults_are_the_rfc_8628_ones() {
        let module = DeviceAuth::new();
        assert_eq!(module.settings.expires_in_secs, 600);
        assert_eq!(module.settings.interval_secs, 5);
        assert_eq!(module.settings.max_wrong_entries, DEFAULT_MAX_WRONG_ENTRIES);
    }

    #[test]
    fn the_builder_sets_what_it_names() {
        let module = DeviceAuth::builder()
            .client(DeviceClient::new("a").scopes(["read"]))
            .clients([DeviceClient::new("b")])
            .expires_in(Duration::seconds(300))
            .interval(Duration::seconds(2))
            .max_wrong_entries(3)
            .sign_in_url("https://example.test/login")
            .build();
        assert_eq!(module.settings.clients.len(), 1, "clients() replaces");
        assert_eq!(module.settings.clients[0].id(), "b");
        assert_eq!(module.settings.expires_in_secs, 300);
        assert_eq!(module.settings.interval_secs, 2);
        assert_eq!(module.settings.max_wrong_entries, 3);
        assert_eq!(
            module.settings.sign_in_url.as_deref(),
            Some("https://example.test/login")
        );
    }

    #[test]
    fn builder_values_are_clamped_not_honoured() {
        let module = DeviceAuth::builder()
            .expires_in(Duration::ZERO)
            .interval(Duration::ZERO)
            .max_wrong_entries(0)
            .build();
        assert_eq!(module.settings.expires_in_secs, 1);
        assert_eq!(module.settings.interval_secs, 1);
        assert_eq!(module.settings.max_wrong_entries, 1);

        let module = DeviceAuth::builder()
            .expires_in(Duration::seconds(400 * 24 * 60 * 60))
            .build();
        assert_eq!(
            module.settings.expires_in_secs,
            MAX_EXPIRES_IN.whole_seconds()
        );
    }

    #[test]
    fn self_check_names_every_missing_piece() {
        let problems = DeviceAuth::new().self_check();
        let text = problems.join("\n");
        assert!(text.contains("no clients are declared"), "{text}");
        assert!(text.contains("no issuer is set"), "{text}");
        assert!(text.contains("no entropy source is set"), "{text}");
    }

    #[test]
    fn self_check_flags_a_malformed_client() {
        let module = DeviceAuth::builder()
            .client(DeviceClient::new("").scopes(["read write"]))
            .build();
        let text = module.self_check().join("\n");
        assert!(text.contains("empty or contains whitespace"), "{text}");
        assert!(text.contains("read write"), "{text}");
    }

    #[test]
    fn a_client_matches_on_an_exact_scope() {
        let client = DeviceClient::new("cli").scopes(["read", "write"]);
        assert!(client.declares_scope("read"));
        assert!(!client.declares_scope("admin"));
        assert!(!client.declares_scope("rea"));
        assert_eq!(client.declared_scopes(), ["read", "write"]);
    }

    #[test]
    fn user_codes_are_normalized_for_comparison() {
        assert_eq!(normalize_user_code("bcdf-ghjk"), "BCDFGHJK");
        assert_eq!(normalize_user_code("  BCDF GHJK "), "BCDFGHJK");
        assert_eq!(normalize_user_code("bcdf-ghjk\n"), "BCDFGHJK");
    }

    #[test]
    fn hashes_are_lowercase_sha256_hex() {
        let hash = sha256_hex("abc");
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(
            hash.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(device_code_hash("x"), user_code_hash("x"));
    }

    #[test]
    fn a_sign_in_location_carries_the_return_to_encoded() {
        let url = sign_in_location(
            "https://example.test/login",
            "https://x.test/v1/device-auth?user_code=AB",
        );
        assert!(
            url.starts_with("https://example.test/login?return_to="),
            "{url}"
        );
        assert!(url.contains("user_code%3DAB"), "{url}");
        let with_query = sign_in_location("https://example.test/login?next=1", "https://x.test/");
        assert!(with_query.contains("?next=1&return_to="), "{with_query}");
    }
}
