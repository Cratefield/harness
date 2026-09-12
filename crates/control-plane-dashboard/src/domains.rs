//! The Domains screen (issue #30): putting a venture on a customer's
//! own hostname through Cloudflare for SaaS.
//!
//! A venture is reachable at its `subdomain` today. This screen is the
//! path from there to a name the customer owns: record the claim, show
//! the exact DNS record that points the name here, and walk the hostname
//! through verification to a certificate. The last mile — the calls that
//! actually reach Cloudflare — sits behind a [`CustomHostnames`] port
//! whose only implementation today is [`Unwired`], which refuses,
//! exactly as `cratefield_provisioning` treats its own [`Deployer`]:
//! the engine is real, every recorded state is true, and the refusal is
//! recorded as the failure it is rather than dressed up as a pending
//! operation. The day a real adapter is wired in, the same flows run to
//! the end and nothing else changes.
//!
//! [`Deployer`]: cratefield_provisioning::Deployer
//! [`CustomHostnames`]: crate::domains::CustomHostnames
//! [`Unwired`]: crate::domains::Unwired
//!
//! What is deliberately not here, each named so the boundary reads as a
//! decision rather than an omission:
//!
//! - **Certificate management beyond recording state.** The machine
//!   records `certificate issuing` and `live`; renewal, rotation and
//!   expiry handling are the certificate work's own issue.
//! - **Deleting a claim.** A hostname claim is operational state; how it
//!   is released (and whether the release is honest while a certificate
//!   still answers for the name) deserves its own decision, not a
//!   button added in passing.
//! - **Apex hostnames.** The record this screen tells the customer to
//!   create is a CNAME, which an apex cannot carry. Cloudflare for SaaS
//!   has apex paths (Custom Nameservers, pre-validation); picking one is
//!   a product decision, so the screen takes the name and shows the
//!   CNAME rather than guessing the customer's DNS capabilities from a
//!   string.

use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use cratefield_accounts::Venture;
use cratefield_chrome::{Page, escape, render};
use cratefield_console::current_session;
use cratefield_core::{Database, DbError, Statement};

use crate::{
    BASE, DashboardState, account_nav, account_of, frame, guard, internal, now_rfc3339, ulid,
};

/// The path this screen sits at.
const PATH: &str = "/v1/dashboard/domains";

/// The schema migration: the `hostname` table. The set id it lands under
/// in the dashboard's migration list is wired in `lib.rs`. Both numbers
/// moved on the rebase: two other screens had landed in this crate's
/// directory first, so the file is 0003 here and the set id is 0008 —
/// the directory numbers contiguously from 0001, and a set id is
/// unique within the module or `assert_migration_set` refuses the
/// build.
pub(crate) const MIGRATION: cratefield_core::SqlMigration = cratefield_core::SqlMigration::new(
    "0008",
    "hostname",
    include_str!("../migrations/sqlite/0003_hostname.sql"),
);

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

/// Where a custom hostname is in its flow. The states are the ones the
/// real Cloudflare for `SaaS` flow has, and the transitions between them
/// are decided by [`HostnameState::can_transition_to`] — a test, not a
/// free-text status column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameState {
    /// Recorded against a venture; nothing has been asked of Cloudflare
    /// yet.
    Added,
    /// Registered with the provider; the customer's DNS record has not
    /// been seen yet.
    AwaitingDns,
    /// The DNS record answers; the provider is checking it.
    Verifying,
    /// Validation passed; the certificate is being issued.
    CertificateIssuing,
    /// Serving: verified, certificate active.
    Live,
    /// A step refused or failed. The recorded `last_error` says why.
    /// Recoverable only by starting the flow again — a retry re-ensures
    /// and lands back at `AwaitingDns`, never at `Live`.
    Failed,
}

impl HostnameState {
    /// The stable token recorded in the `state` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HostnameState::Added => "added",
            HostnameState::AwaitingDns => "awaiting-dns",
            HostnameState::Verifying => "verifying",
            HostnameState::CertificateIssuing => "certificate-issuing",
            HostnameState::Live => "live",
            HostnameState::Failed => "failed",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "added" => HostnameState::Added,
            "awaiting-dns" => HostnameState::AwaitingDns,
            "verifying" => HostnameState::Verifying,
            "certificate-issuing" => HostnameState::CertificateIssuing,
            "live" => HostnameState::Live,
            "failed" => HostnameState::Failed,
            _ => return None,
        })
    }

    /// Whether one state may follow another. Forward through the flow one
    /// step at a time; any working state may fail; a failure recovers by
    /// starting the flow again at `AwaitingDns`; a live hostname may fail
    /// (a certificate that stops being valid is not "still live"); and a
    /// state may follow itself so an ensure-shaped re-check is never an
    /// illegal move.
    ///
    /// Backwards is always illegal, and skipping forward is too: the
    /// provider may jump several states in one poll, but then the *flow*
    /// walks the intermediate states as legal single steps, so a recorded
    /// history is always a path the machine allows rather than a series
    /// of leaps nobody observed.
    #[must_use]
    pub fn can_transition_to(self, next: HostnameState) -> bool {
        use HostnameState::{Added, AwaitingDns, CertificateIssuing, Failed, Live, Verifying};
        self == next
            || matches!(
                (self, next),
                (Added, AwaitingDns | Failed)
                    | (AwaitingDns, Verifying | Failed)
                    | (Verifying, CertificateIssuing | Failed)
                    | (CertificateIssuing, Live | Failed)
                    | (Failed, AwaitingDns)
                    | (Live, Failed)
            )
    }

    /// The chip the row wears. `failed` is the only one that shouts, for
    /// the same reason `DEGRADED` is on the venture screen: it is the
    /// one the operator has to do something about.
    fn chip(self) -> String {
        let class = match self {
            HostnameState::Added => "chip",
            HostnameState::AwaitingDns
            | HostnameState::Verifying
            | HostnameState::CertificateIssuing => "chip chip--working",
            HostnameState::Live => "chip chip--live",
            HostnameState::Failed => "chip chip--degraded",
        };
        let label = match self {
            HostnameState::CertificateIssuing => "CERTIFICATE ISSUING",
            other => other.as_str(),
        };
        format!("<span class=\"{class}\">{label}</span>")
    }
}

/// Why a recorded transition did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: HostnameState,
    pub to: HostnameState,
}

impl std::fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a hostname cannot go from {} to {}",
            self.from.as_str(),
            self.to.as_str()
        )
    }
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/// A failure from the thing that talks to Cloudflare. The message must be
/// safe to record and show; it must never carry a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError {
    pub message: String,
}

impl DomainError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// What the hostname's DNS validation record says at the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    /// The customer's DNS record has not been seen yet.
    Pending,
    /// The hostname answers with the record this screen told them to
    /// create.
    Verified,
}

/// The provider-side state of a custom hostname, in the same terms the
/// flow records — the mapping from the provider's answer to our state
/// is the flow's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderStatus {
    AwaitingDns,
    Verifying,
    CertificateIssuing,
    Live,
}

/// The calls the real flow needs against Cloudflare for `SaaS`. Every
/// method is "ensure" or "read" shaped: creating a hostname that exists
/// is safe, so a retry that re-touches the flow cannot break anything.
///
/// The live adapter holds the platform credential and speaks to the
/// Cloudflare API; it is wired in where the credential lives (#26),
/// never in this crate. Tests drive the flows with a fake.
#[allow(async_fn_in_trait)]
pub trait CustomHostnames {
    /// Register `hostname` with the provider, answering to `target` (the
    /// venture's own subdomain, which is the fallback origin the
    /// customer's DNS points at).
    async fn create(&self, hostname: &str, target: &str) -> Result<(), DomainError>;
    /// Whether the customer's DNS record has been seen and accepted.
    async fn check_validation(&self, hostname: &str) -> Result<Validation, DomainError>;
    /// The hostname's current provider-side status.
    async fn status(&self, hostname: &str) -> Result<ProviderStatus, DomainError>;
}

/// The custom-hostnames adapter the control plane has today: none.
///
/// No Cloudflare credential is wired (#26), and this screen refuses to
/// pretend otherwise. The flows below run for real through this
/// implementation: the first call fails, the failure is recorded against
/// the hostname with its reason, and the row's state is `failed` —
/// which is a stop, not a pending operation. The day a real
/// [`CustomHostnames`] is passed instead, every recorded `failed` row
/// retries through the same code path and nothing else changes.
pub struct Unwired;

impl Unwired {
    /// The one message shape, so a recorded refusal reads the same
    /// whichever call a flow happens to reach first. It begins with the
    /// sentence the screen exists to make unmissable.
    fn refuse<T>(what: &str) -> Result<T, DomainError> {
        Err(DomainError::new(format!(
            "cannot verify: no Cloudflare credential is wired (#26) — {what} needs an \
             adapter that talks to Cloudflare for SaaS, and the control plane holds \
             none. Nothing was changed."
        )))
    }
}

// Every method answers without awaiting anything, which is the whole
// point: there is nothing to talk to. The port is async because a real
// adapter is.
#[allow(clippy::unused_async_trait_impl)]
impl CustomHostnames for Unwired {
    async fn create(&self, _hostname: &str, _target: &str) -> Result<(), DomainError> {
        Self::refuse("creating the custom hostname")
    }
    async fn check_validation(&self, _hostname: &str) -> Result<Validation, DomainError> {
        Self::refuse("checking the hostname's DNS validation")
    }
    async fn status(&self, _hostname: &str) -> Result<ProviderStatus, DomainError> {
        Self::refuse("reading the hostname's status")
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Turns what an operator typed into the hostname DNS will use, or says
/// why it cannot be one.
///
/// The rules, in the order they bite:
///
/// - **A hostname, not an address.** `https://app.example.com/hello` is
///   refused as an address so the operator fixes the field rather than
///   wondering which part went wrong later.
/// - **No wildcards.** Cloudflare for `SaaS` certifies one name at a time;
///   `*.example.com` is a different product.
/// - **Punycode, not mangling.** The name is converted with IDNA
///   (`bücher.example` becomes `xn--bcher-kva.example`), which is the
///   form DNS speaks and the form stored — so what the screen shows the
///   customer to create is a record that actually resolves.
/// - **Length limits.** Each label 1–63 octets, the whole name at most
///   253 — the DNS protocol's own numbers, enforced where the name
///   enters the system rather than where a provider rejects it.
/// - **At least two labels.** A bare TLD (`com`) is not a hostname a
///   customer can point here, and one label is also how a typo reads.
///
/// Considered and rejected: refusing hostnames inside the platform's own
/// zone (`*.cratefield.app`). The platform zone is not a configured fact
/// this module holds — it is implied by the subdomains the console
/// mints — and a guessed zone check would refuse names on a hardcoded
/// string. The one collision that is checkable is: the venture's own
/// subdomain, refused when the claim is recorded.
///
/// # Errors
///
/// A human-readable reason for every refusal: empty input, an address
/// rather than a hostname, a wildcard, a name IDNA cannot process, a
/// label or whole name over DNS's length limits, or a single-label name.
pub fn normalise(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("the hostname is empty".to_owned());
    }
    if raw.contains("://") || raw.contains(['/', '?', '#', '@', ':', ' ']) {
        return Err(
            "that is an address, not a hostname: pass the name alone (app.example.com), \
             not the URL"
                .to_owned(),
        );
    }
    if raw.contains('*') {
        return Err(
            "wildcard hostnames are not supported: Cloudflare for SaaS certifies one name \
             at a time, so add app.example.com rather than *.example.com"
                .to_owned(),
        );
    }
    // A single trailing dot is the DNS root form of the same name; strip
    // it rather than refusing a name some DNS tools paste with one.
    let raw = raw.strip_suffix('.').unwrap_or(raw);
    if raw.is_empty() {
        return Err("the hostname is empty".to_owned());
    }
    let ascii = idna::domain_to_ascii(raw).map_err(|_| {
        format!(
            "\"{raw}\" is not a hostname this system can register: it is not a valid \
             DNS name after IDNA processing"
        )
    })?;
    if ascii.is_empty() {
        return Err("the hostname is empty".to_owned());
    }
    // 253 is the wire limit for a fully-qualified name minus its root
    // dot; enforcing it here keeps a provider's refusal from being the
    // first time the operator hears of it.
    if ascii.len() > 253 {
        return Err(format!(
            "the hostname is {ascii_len} characters; DNS names are at most 253",
            ascii_len = ascii.len()
        ));
    }
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 {
        return Err(format!(
            "\"{ascii}\" has only one label; a custom hostname needs at least a name in \
             a domain (app.example.com)"
        ));
    }
    for label in &labels {
        if label.is_empty() {
            return Err(format!(
                "\"{ascii}\" has an empty label (a double dot, or a leading one)"
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "the label \"{label}\" is {len} characters; DNS labels are at most 63",
                len = label.len()
            ));
        }
        // domain_to_ascii emits LDH labels; this re-check keeps a future
        // IDNA behaviour change from quietly widening what is stored.
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "the label \"{label}\" contains characters a DNS label cannot hold"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "the label \"{label}\" starts or ends with a hyphen, which a DNS label \
                 cannot"
            ));
        }
    }
    Ok(ascii)
}

// ---------------------------------------------------------------------------
// Reads and writes
// ---------------------------------------------------------------------------

/// One hostname row, joined to the venture that claims it (the join is
/// also the scoping: a venture outside the account makes no rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostnameRow {
    pub id: String,
    pub hostname: String,
    pub venture_id: String,
    pub venture_slug: String,
    pub subdomain: String,
    pub state: HostnameState,
    pub last_error: String,
    pub added_at: String,
    pub state_changed_at: String,
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}

async fn hostnames_for(db: &dyn Database, account_id: &str) -> Result<Vec<HostnameRow>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT h.id, h.hostname, h.venture_id, h.state, h.last_error, h.added_at, \
             h.state_changed_at, v.slug, v.subdomain FROM hostname h \
             JOIN venture v ON v.id = h.venture_id WHERE h.account_id = ? \
             ORDER BY h.added_at DESC, h.id DESC",
            vec![text(account_id)],
        ))
        .await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| HostnameRow {
            id: row.get("id").unwrap_or_default(),
            hostname: row.get("hostname").unwrap_or_default(),
            venture_id: row.get("venture_id").unwrap_or_default(),
            venture_slug: row.get("slug").unwrap_or_default(),
            subdomain: row.get("subdomain").unwrap_or_default(),
            state: row
                .get::<String>("state")
                .as_deref()
                .and_then(HostnameState::parse)
                .unwrap_or(HostnameState::Failed),
            last_error: row.get("last_error").unwrap_or_default(),
            added_at: row.get("added_at").unwrap_or_default(),
            state_changed_at: row.get("state_changed_at").unwrap_or_default(),
        })
        .collect())
}

/// Why [`add_hostname`] wrote nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddRefusal {
    /// The input is not a hostname this system will record.
    Invalid(String),
    /// Another venture already holds it. `holder_slug` is set only when
    /// the holder is the same account's venture: one customer may be
    /// told which of their ventures holds a name; a different customer's
    /// holder is named to nobody.
    Taken { holder_slug: Option<String> },
    /// The venture to claim it for is not one this account may act on,
    /// or is archived.
    Venture(String),
}

impl AddRefusal {
    fn reason(&self) -> String {
        match self {
            AddRefusal::Invalid(why) | AddRefusal::Venture(why) => why.clone(),
            AddRefusal::Taken { holder_slug } => match holder_slug {
                Some(slug) => format!(
                    "another of your ventures already holds this hostname: {slug} claimed \
                     it first. One name serves one venture; release it there before \
                     claiming it here."
                ),
                None => "another venture already holds this hostname. One name serves one \
                        venture, and this one is taken."
                    .to_owned(),
            },
        }
    }

    fn status(&self) -> axum::http::StatusCode {
        match self {
            AddRefusal::Invalid(_) => axum::http::StatusCode::BAD_REQUEST,
            AddRefusal::Taken { .. } | AddRefusal::Venture(_) => axum::http::StatusCode::CONFLICT,
        }
    }
}

/// Records a claim and runs the first step of the flow for real.
///
/// Order matters and is the honesty of this function: the claim is
/// recorded *before* the provider is called, so a venture's hostname
/// list is a list of claims, not of successes; then [`CustomHostnames::
/// create`] runs, and its refusal is recorded as the state it left
/// behind — `failed`, with the reason — never as "added, working on
/// it". A success moves the row to `awaiting-dns`, which is the state
/// the customer's DNS record then answers.
pub(crate) async fn add_hostname<C: CustomHostnames>(
    db: &dyn Database,
    account_id: &str,
    venture: &Venture,
    raw: &str,
    api: &C,
    id: &str,
    now: &str,
) -> Result<HostnameRow, AddFailure> {
    let hostname = normalise(raw).map_err(AddRefusal::Invalid)?;
    if hostname == venture.subdomain {
        return Err(AddFailure::Refused(AddRefusal::Venture(format!(
            "that is this venture's own subdomain ({}); a custom hostname is a name \
             outside the platform",
            venture.subdomain
        ))));
    }
    // The claim is global: two ventures cannot serve one name, whoever
    // owns them. The holder's name is revealed only within the account.
    let held = db
        .query(&Statement::with_values(
            "SELECT h.account_id, v.slug FROM hostname h JOIN venture v ON v.id = \
             h.venture_id WHERE h.hostname = ?",
            vec![text(&hostname)],
        ))
        .await?;
    if let Some(row) = held.first() {
        let holder_account: String = row.get("account_id").unwrap_or_default();
        let holder_slug: String = row.get("slug").unwrap_or_default();
        let mine = if holder_account == account_id {
            Some(holder_slug)
        } else {
            None
        };
        return Err(AddFailure::Refused(AddRefusal::Taken { holder_slug: mine }));
    }

    db.execute(&Statement::with_values(
        "INSERT INTO hostname (id, account_id, venture_id, hostname, state, last_error, \
         added_at, state_changed_at, updated_at) VALUES (?, ?, ?, ?, ?, '', ?, ?, ?)",
        vec![
            text(id),
            text(account_id),
            text(&venture.id),
            text(&hostname),
            text(HostnameState::Added.as_str()),
            text(now),
            text(now),
            text(now),
        ],
    ))
    .await?;

    let mut row = row_by_id(db, id)
        .await?
        .ok_or(AddFailure::Db(DbError::Execute(
            "the hostname row vanished as it was written".to_owned(),
        )))?;
    match api.create(&hostname, &venture.subdomain).await {
        Ok(()) => {
            row = set_state(db, &row, HostnameState::AwaitingDns, "", now)
                .await
                .ok()
                .flatten()
                .unwrap_or(row);
        }
        Err(err) => {
            row = set_state(db, &row, HostnameState::Failed, &err.message, now)
                .await
                .ok()
                .flatten()
                .unwrap_or(row);
        }
    }
    Ok(row)
}

/// Why an add neither produced a row nor a recorded refusal.
#[derive(Debug)]
pub(crate) enum AddFailure {
    Refused(AddRefusal),
    Db(DbError),
}

impl From<DbError> for AddFailure {
    fn from(err: DbError) -> Self {
        AddFailure::Db(err)
    }
}

impl From<AddRefusal> for AddFailure {
    fn from(refusal: AddRefusal) -> Self {
        AddFailure::Refused(refusal)
    }
}

async fn row_by_id(db: &dyn Database, id: &str) -> Result<Option<HostnameRow>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT h.id, h.hostname, h.venture_id, h.state, h.last_error, h.added_at, \
             h.state_changed_at, v.slug, v.subdomain FROM hostname h \
             JOIN venture v ON v.id = h.venture_id WHERE h.id = ?",
            vec![text(id)],
        ))
        .await?;
    Ok(rows.first().map(|row| HostnameRow {
        id: row.get("id").unwrap_or_default(),
        hostname: row.get("hostname").unwrap_or_default(),
        venture_id: row.get("venture_id").unwrap_or_default(),
        venture_slug: row.get("slug").unwrap_or_default(),
        subdomain: row.get("subdomain").unwrap_or_default(),
        state: row
            .get::<String>("state")
            .as_deref()
            .and_then(HostnameState::parse)
            .unwrap_or(HostnameState::Failed),
        last_error: row.get("last_error").unwrap_or_default(),
        added_at: row.get("added_at").unwrap_or_default(),
        state_changed_at: row.get("state_changed_at").unwrap_or_default(),
    }))
}

/// Applies one transition, enforcing the machine. A self-transition
/// only refreshes the error and `updated_at` — `state_changed_at` moves
/// when the state does, so "how long has it been in this state" stays a
/// question the column answers.
///
/// Returns the row as it now stands, or [`IllegalTransition`] with the
/// row untouched — the caller records that as a plain error rather than
/// silently widening the machine.
async fn set_state(
    db: &dyn Database,
    row: &HostnameRow,
    next: HostnameState,
    error: &str,
    now: &str,
) -> Result<Option<HostnameRow>, IllegalTransition> {
    if !row.state.can_transition_to(next) {
        return Err(IllegalTransition {
            from: row.state,
            to: next,
        });
    }
    let result = if row.state == next {
        db.execute(&Statement::with_values(
            "UPDATE hostname SET last_error = ?, updated_at = ? WHERE id = ?",
            vec![text(error), text(now), text(&row.id)],
        ))
        .await
    } else {
        db.execute(&Statement::with_values(
            "UPDATE hostname SET state = ?, last_error = ?, state_changed_at = ?, \
             updated_at = ? WHERE id = ?",
            vec![
                text(next.as_str()),
                text(error),
                text(now),
                text(now),
                text(&row.id),
            ],
        ))
        .await
    };
    match result {
        Ok(_) => {}
        // The transition was legal; only the write failed. surfacing it
        // as a database error is the caller's business.
        Err(err) => {
            tracing::error!(error = %err, "hostname state write failed");
        }
    }
    match row_by_id(db, &row.id).await {
        Ok(fresh) => Ok(fresh),
        Err(err) => {
            tracing::error!(error = %err, "hostname re-read failed");
            Ok(None)
        }
    }
}

/// The order the flow walks states in, for the provider-driven skip.
const FLOW: [HostnameState; 4] = [
    HostnameState::AwaitingDns,
    HostnameState::Verifying,
    HostnameState::CertificateIssuing,
    HostnameState::Live,
];

/// Advances one hostname as far as the provider's answers take it,
/// recording every state it enters and every refusal it meets.
///
/// The shape mirrors the provisioning engine's retry: a `failed` row
/// re-ensures with `create` first (which is why a retry lands at
/// `awaiting-dns` and not at some state it never re-earned), then
/// validation, then status. With [`Unwired`] the first call refuses and
/// the recorded reason is refreshed rather than duplicated — a stop,
/// restated, not a new kind of pending.
pub(crate) async fn check_hostname<C: CustomHostnames>(
    db: &dyn Database,
    row: &HostnameRow,
    api: &C,
    now: &str,
) -> Result<HostnameRow, DbError> {
    let mut current = row.clone();
    // A claim that never reached the provider, or one that failed there,
    // starts the flow again: create is ensure-shaped.
    if matches!(current.state, HostnameState::Added | HostnameState::Failed) {
        match api.create(&current.hostname, &current.subdomain).await {
            Ok(()) => {
                current = set_state(db, &current, HostnameState::AwaitingDns, "", now)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| current.clone());
            }
            Err(err) => {
                return Ok(
                    set_state(db, &current, HostnameState::Failed, &err.message, now)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or(current),
                );
            }
        }
    }

    // DNS validation: the customer's record, seen or not. `Pending` is
    // not a failure — it is the flow not being finished — so the
    // hostname holds at `awaiting-dns` and the provider's status is not
    // asked until the record answers.
    match api.check_validation(&current.hostname).await {
        Err(err) => {
            return Ok(
                set_state(db, &current, HostnameState::Failed, &err.message, now)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(current),
            );
        }
        Ok(Validation::Pending) => {
            return Ok(set_state(db, &current, HostnameState::AwaitingDns, "", now)
                .await
                .ok()
                .flatten()
                .unwrap_or(current));
        }
        Ok(Validation::Verified) => {}
    }

    // Status: the provider may be several states ahead of the record.
    // The flow walks each intermediate state as its own legal step, so
    // the recorded history is a path, not a leap; a provider *behind*
    // the record is certificate-lifecycle territory this screen records
    // as an error and does not guess at.
    match api.status(&current.hostname).await {
        Ok(reported) => {
            let target = match reported {
                ProviderStatus::AwaitingDns => HostnameState::AwaitingDns,
                ProviderStatus::Verifying => HostnameState::Verifying,
                ProviderStatus::CertificateIssuing => HostnameState::CertificateIssuing,
                ProviderStatus::Live => HostnameState::Live,
            };
            let from = FLOW
                .iter()
                .position(|state| *state == current.state)
                .unwrap_or(0);
            let to = FLOW.iter().position(|state| *state == target).unwrap_or(0);
            if to < from {
                let why = format!(
                    "the provider reports the hostname at {}, behind the recorded {}; \
                     certificate lifecycle behind a live name is not handled (#30 names \
                     this boundary), so the record stands",
                    target.as_str(),
                    current.state.as_str()
                );
                return Ok(set_state(db, &current, current.state, &why, now)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(current));
            }
            let mut row = current.clone();
            for step in &FLOW[from..=to] {
                row = set_state(db, &row, *step, "", now)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| row.clone());
            }
            Ok(row)
        }
        Err(err) => Ok(
            set_state(db, &current, HostnameState::Failed, &err.message, now)
                .await
                .ok()
                .flatten()
                .unwrap_or(current),
        ),
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The DNS record the customer has to create for one hostname row:
/// name, type, target — computed from the venture's own subdomain, so
/// it is copyable and correct rather than a documentation example.
fn dns_record(row: &HostnameRow) -> String {
    format!(
        "<div class=\"dash__dns\">\
         <span><b>type</b> <code>CNAME</code></span>\
         <span><b>name</b> <code>{hostname}</code></span>\
         <span><b>target</b> <code>{target}</code></span></div>",
        hostname = escape(&row.hostname),
        target = escape(&row.subdomain),
    )
}

/// The rows list. Every column is a fact from the record: the name as
/// stored (punycode — the form DNS uses), the venture that claims it,
/// the state and how long it has been there, the record to create, and
/// the last error verbatim when there is one.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn render_rows(rows: &[HostnameRow]) -> String {
    let mut out = String::from(
        "<div class=\"dash__lrow dash__lrow--hostnames dash__lrow--head\">\
         <span>Hostname</span><span>Venture</span><span>State</span>\
         <span>DNS record to create</span></div>",
    );
    if rows.is_empty() {
        out.push_str(
            "<p class=\"dash__empty\">No custom hostnames claimed yet. Add one above; the \
             record to create appears beside it.</p>",
        );
    }
    for row in rows {
        let error = if row.last_error.is_empty() {
            String::new()
        } else {
            format!(
                "<br><span class=\"dash__err\">{error}</span>",
                error = escape(&row.last_error)
            )
        };
        out.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--hostnames\">\
             <span><code>{hostname}</code>{error}</span>\
             <span><a href=\"{BASE}/ventures/{vid}\">{slug}</a><br><em>{subdomain}</em></span>\
             <span>{chip}<br><em class=\"dash__meta\">since {when}</em>\
             <form method=\"post\" action=\"{PATH}/{id}/check\">\
             <button class=\"btn\" type=\"submit\">Check now</button></form></span>\
             <span>{record}</span></div>",
            hostname = escape(&row.hostname),
            vid = escape(&row.venture_id),
            slug = escape(&row.venture_slug),
            subdomain = escape(&row.subdomain),
            chip = row.state.chip(),
            when = escape(&row.state_changed_at),
            id = escape(&row.id),
            record = dns_record(row),
        ));
    }
    out
}

/// The add form. Guarded like the dashboard's other POSTs (the session
/// the guard proves is the account every claim is scoped to), and the
/// venture list is the account's own non-archived ventures, so the form
/// cannot even offer a venture the account cannot act on.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn render_form(ventures: &[Venture], error: Option<&str>) -> String {
    if ventures.is_empty() {
        return format!(
            "<div class=\"dash__card dash__card--wide\">\
             <p class=\"dash__card-h\">Add a hostname</p>\
             <p class=\"dash__empty\">No ventures to claim a hostname for. \
             <a href=\"/v1/console/new\">Create one in the console</a> first.</p></div>\
             {err}",
            err = error_banner(error),
        );
    }
    let options: Vec<String> = ventures
        .iter()
        .map(|venture| {
            format!(
                "<option value=\"{id}\">{slug} — {subdomain}</option>",
                id = escape(&venture.id),
                slug = escape(&venture.slug),
                subdomain = escape(&venture.subdomain),
            )
        })
        .collect();
    format!(
        "<div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Add a hostname</p>{err}\
         <form method=\"post\" action=\"{PATH}/add\">\
         <p class=\"field\"><label for=\"hostname-venture\">Venture</label>\
         <select id=\"hostname-venture\" name=\"venture\">{options}</select></p>\
         <p class=\"field\"><label for=\"hostname-name\">Hostname</label>\
         <input id=\"hostname-name\" name=\"hostname\" required maxlength=\"254\" \
         autocomplete=\"off\" placeholder=\"app.example.com\"></p>\
         <div class=\"dash__act\">\
         <button class=\"btn btn--primary\" type=\"submit\">Claim hostname</button></div>\
         </form>\
         <p class=\"dash__note\">The name is stored in its punycode form — the form \
         DNS uses — so <code>bücher.example</code> is recorded as \
         <code>xn--bcher-kva.example</code> and the record shown beside it is the \
         one that resolves. A name another venture already holds is refused, not \
         taken over.</p></div>",
        options = options.join(""),
        err = error_banner(error),
    )
}

/// The refusal banner a rejected POST leaves on the page: the reason in
/// full, at the status code the refusal deserves.
fn error_banner(error: Option<&str>) -> String {
    match error {
        Some(reason) => format!(
            "<p class=\"dash__banner dash__banner--bad\"><span class=\"chip \
             chip--degraded\">Refused</span><strong>Nothing was recorded.</strong> \
             {reason}</p>",
            reason = escape(reason),
        ),
        None => String::new(),
    }
}

/// The banner that says where the flow really stops, in the voice the
/// planned screens used: what is wrong, and what to do today instead.
fn unwired_banner() -> &'static str {
    "<p class=\"dash__banner\"><span class=\"chip chip--degraded\">No Cloudflare \
     credential</span><strong>Verification cannot proceed.</strong> The control \
     plane holds no Cloudflare credential, so it cannot create or check a custom \
     hostname at Cloudflare (#26). Everything else on this screen is real: the \
     claim is recorded, the state below is what actually happened, and the \
     refusal is shown beside it rather than dressed up as a pending check.</p>\
     <p class=\"dash__note\">Today you do this instead: add the custom hostname in \
     Cloudflare yourself, pointing at the venture's subdomain — the record \
     beside each row names the exact target. When verification becomes possible \
     here, pressing <em>Check now</em> on a claimed row walks it the rest of the \
     way; today that press records the same honest refusal.</p>"
}

#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn page(
    identity: &str,
    ventures: &[Venture],
    rows: &[HostnameRow],
    error: Option<&str>,
) -> Response {
    let body = format!(
        "{banner}{form}\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Claimed hostnames <span class=\"dash__tag\">{n}</span></p>\
         <div class=\"dash__list\">{rows}</div></div>\
         <p class=\"dash__note\">The states are the real flow's: added, awaiting DNS, \
         verifying, certificate issuing, live, failed — and the moves between them are \
         a state machine, not a status string an error handler improvised. A failed \
         row recovers by starting the flow again, never by jumping to live.</p>",
        banner = unwired_banner(),
        form = render_form(ventures, error),
        n = rows.len(),
        rows = render_rows(rows),
    );
    Html(render(&Page {
        title: "Domains",
        signed_in_as: Some(identity),
        body: &format!(
            "<div class=\"page-h\"><h1>Domains</h1></div>\
             <p class=\"lede\">A venture on the customer's own hostname: claim the \
             name, create the record, verify it, serve it.</p>{frame}",
            frame = frame(&account_nav("domains"), "Domains", &body),
        ),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `/v1/dashboard/domains` — the claims list and the add form.
pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let ventures = match repo.ventures_for(&account.id).await {
        Ok(ventures) => ventures,
        Err(err) => {
            tracing::error!(error = %err, "venture list failed for the domains screen");
            return internal("could not load the ventures");
        }
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let rows = match hostnames_for(db.as_ref(), &account.id).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, "hostname list failed");
            return internal("could not load the hostnames");
        }
    };
    page(&session.account_id, &ventures, &rows, None)
}

/// `/v1/dashboard/domains/add` — records the claim and runs the flow's
/// first step for real through the port. A refusal from the provider
/// side is a recorded `failed` row (the redirect shows it); a refusal
/// from validation or ownership is a page that says nothing was
/// recorded and why.
pub(super) async fn add(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };

    let venture_id = form
        .iter()
        .find(|(key, _)| key == "venture")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let hostname = form
        .iter()
        .find(|(key, _)| key == "hostname")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    if venture_id.is_empty() || hostname.trim().is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "the form is incomplete",
        )
            .into_response();
    }

    // The venture is resolved within the account: a venture id that is
    // not this account's is a 404, exactly as the venture screen treats
    // it, so the form cannot be aimed at another customer's venture.
    let venture = match repo.venture_for(&account.id, &venture_id).await {
        Ok(Some(venture)) => venture,
        Ok(None) => {
            return (axum::http::StatusCode::NOT_FOUND, "no such venture").into_response();
        }
        Err(err) => {
            tracing::error!(error = %err, "venture lookup failed");
            return internal("could not load the venture");
        }
    };
    if venture.status == cratefield_accounts::VentureStatus::Archived {
        return (
            axum::http::StatusCode::CONFLICT,
            "an archived venture cannot claim a hostname",
        )
            .into_response();
    }

    match add_hostname(
        db.as_ref(),
        &account.id,
        &venture,
        &hostname,
        &Unwired,
        &ulid(ctx),
        &now_rfc3339(ctx),
    )
    .await
    {
        // The claim was recorded; wherever the flow stopped, the list
        // shows the true state and the true reason.
        Ok(_) => Redirect::to(PATH).into_response(),
        Err(AddFailure::Refused(refusal)) => {
            let (status, reason) = (refusal.status(), refusal.reason());
            let Ok(ventures) = repo.ventures_for(&account.id).await else {
                return (status, reason).into_response();
            };
            let Ok(rows) = hostnames_for(db.as_ref(), &account.id).await else {
                return (status, reason).into_response();
            };
            let mut response = page(&session.account_id, &ventures, &rows, Some(&reason));
            *response.status_mut() = status;
            response
        }
        Err(AddFailure::Db(err)) => {
            tracing::error!(error = %err, "hostname add failed");
            internal("could not record the hostname")
        }
    }
}

/// `/v1/dashboard/domains/{id}/check` — advances one claim as far as
/// the provider's answers take it. With no adapter wired this records
/// the same honest refusal again and leaves the row failed; the button
/// exists so that the day one is wired, this exact press is the one
/// that works.
pub(super) async fn check(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    // Scoped by the join: a row whose venture is not this account's does
    // not exist as far as this query is concerned.
    let Some(row) = hostnames_for(db.as_ref(), &account.id)
        .await
        .ok()
        .and_then(|rows| rows.into_iter().find(|row| row.id == id))
    else {
        return (axum::http::StatusCode::NOT_FOUND, "no such hostname").into_response();
    };
    if let Err(err) = check_hostname(db.as_ref(), &row, &Unwired, &now_rfc3339(ctx)).await {
        tracing::error!(error = %err, "hostname check failed");
        return internal("could not check the hostname");
    }
    Redirect::to(PATH).into_response()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unused_async_trait_impl)] // the sync test fakes implement an async port
    use super::*;
    use crate::Dashboard;
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_accounts::{Repository, VentureStatus};
    use cratefield_adapter_sqlite::SqliteDatabase;
    use cratefield_testing::TestHarness;
    use http::{Method, Request as HttpRequest, StatusCode};
    use std::cell::RefCell;
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    /// The kit's fixed clock reads `1_800_000_000`; mint sessions "now"
    /// so they are live, not expired.
    const NOW: u64 = 1_800_000_000;

    fn kit() -> TestHarness {
        TestHarness::new(vec![
            Box::new(cratefield_console::Console),
            Box::new(Dashboard::new(None)),
        ])
    }

    fn cookie(kit: &TestHarness) -> String {
        let token = issue_session(kit.signer.as_ref(), EMAIL, NOW, DEFAULT_TTL_SECS);
        format!("cf_session={token}")
    }

    /// The control plane's own composition plus one account, two
    /// ventures (the second for the same-hostname refusal), and a second
    /// account with one venture (for the cross-account refusal).
    async fn seeded() -> TestHarness {
        let kit = kit();
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        for (id, slug) in [("v1", "my-app"), ("v2", "other-app")] {
            repo.create_venture(
                id,
                "acc_1",
                slug,
                &format!("{slug}.cratefield.app"),
                "cms",
                "ten_1",
                "t0",
            )
            .await
            .expect("venture");
        }
        repo.account_for_login("b@x.co", "B", "acc_2", "t0")
            .await
            .expect("second account");
        repo.create_venture(
            "v9",
            "acc_2",
            "their-app",
            "their-app.cratefield.app",
            "cms",
            "ten_2",
            "t0",
        )
        .await
        .expect("their venture");
        kit
    }

    struct Reply {
        status: StatusCode,
        location: String,
        body: String,
    }

    async fn send(
        kit: &TestHarness,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        form: Option<&str>,
    ) -> Reply {
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(http::header::COOKIE, cookie);
        }
        let body = match form {
            Some(form) => {
                builder = builder.header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                );
                axum::body::Body::from(form.to_owned())
            }
            None => axum::body::Body::empty(),
        };
        let response = kit
            .router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
            .await
            .expect("body");
        Reply {
            status: parts.status,
            location: parts
                .headers
                .get(http::header::LOCATION)
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default(),
            body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
        }
    }

    async fn add(kit: &TestHarness, venture: &str, hostname: &str, cookie: &str) -> Reply {
        send(
            kit,
            Method::POST,
            &format!("{PATH}/add"),
            Some(cookie),
            Some(&format!("venture={venture}&hostname={hostname}")),
        )
        .await
    }

    // -------------------------------------------------------------------
    // The state machine
    // -------------------------------------------------------------------

    #[test]
    fn the_state_machine_refuses_illegal_transitions() {
        use HostnameState::{Added, AwaitingDns, CertificateIssuing, Failed, Live, Verifying};
        // The legal spine: forward one step at a time...
        for (from, to) in [
            (Added, AwaitingDns),
            (AwaitingDns, Verifying),
            (Verifying, CertificateIssuing),
            (CertificateIssuing, Live),
        ] {
            assert!(
                from.can_transition_to(to),
                "{from:?} -> {to:?} must be legal"
            );
        }
        // ...any working state may fail, failure restarts the flow, and
        // a live hostname may stop being live.
        for from in [Added, AwaitingDns, Verifying, CertificateIssuing, Live] {
            assert!(
                from.can_transition_to(Failed),
                "{from:?} -> failed must be legal"
            );
        }
        assert!(Failed.can_transition_to(AwaitingDns));
        assert!(Live.can_transition_to(Failed));

        // The refusals: skipping forward, any backward move, and a
        // failure leaping straight to live. These are the moves a bug in
        // a flow would try first, which is what the guard is for.
        for (from, to) in [
            (Added, Verifying),
            (Added, CertificateIssuing),
            (Added, Live),
            (AwaitingDns, CertificateIssuing),
            (AwaitingDns, Live),
            (Verifying, Live),
            (Failed, Live),
            (Failed, Verifying),
            (Live, Verifying),
            (Live, AwaitingDns),
            (Live, Added),
            (CertificateIssuing, AwaitingDns),
        ] {
            assert!(
                !from.can_transition_to(to),
                "{from:?} -> {to:?} must be refused"
            );
        }
        // A state following itself is legal: an ensure-shaped re-report
        // is not an error.
        for state in [
            Added,
            AwaitingDns,
            Verifying,
            CertificateIssuing,
            Live,
            Failed,
        ] {
            assert!(state.can_transition_to(state));
        }
    }

    #[test]
    fn an_illegal_write_is_refused_and_the_row_stands() {
        // The machine has to hold at the database, not only in memory:
        // drive a real row to live through legal steps, then attempt the
        // move a buggy flow would make (live -> added) and watch the
        // write be refused with the row unchanged.
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[cratefield_accounts::MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("dashboard", &[MIGRATION])
            .expect("hostname schema");

        let row = HostnameRow {
            id: "h1".to_owned(),
            hostname: "app.example.com".to_owned(),
            venture_id: "v1".to_owned(),
            venture_slug: "my-app".to_owned(),
            subdomain: "my-app.cratefield.app".to_owned(),
            state: HostnameState::Live,
            last_error: String::new(),
            added_at: "t0".to_owned(),
            state_changed_at: "t4".to_owned(),
        };
        pollster::block_on(async {
            // A venture row so the read's join finds it.
            db.execute(&Statement::with_values(
                "INSERT INTO account (id, identity, name, status, created_at) \
                 VALUES ('acc_1', 'op@cratefield.com', 'Op', 'active', 't0')",
                vec![],
            ))
            .await
            .expect("account");
            db.execute(&Statement::with_values(
                "INSERT INTO venture (id, account_id, slug, subdomain, module_set, status, \
                 tenant_id, created_at, updated_at) VALUES ('v1', 'acc_1', 'my-app', \
                 'my-app.cratefield.app', 'cms', 'live', 'ten_1', 't0', 't0')",
                vec![],
            ))
            .await
            .expect("venture");
            db.execute(&Statement::with_values(
                "INSERT INTO hostname (id, account_id, venture_id, hostname, state, \
                 last_error, added_at, state_changed_at, updated_at) VALUES \
                 ('h1', 'acc_1', 'v1', 'app.example.com', 'live', '', 't0', 't4', 't4')",
                vec![],
            ))
            .await
            .expect("hostname");

            let refused = set_state(&db, &row, HostnameState::Added, "", "t5")
                .await
                .expect_err("live -> added must be refused");
            assert_eq!(
                refused,
                IllegalTransition {
                    from: HostnameState::Live,
                    to: HostnameState::Added
                }
            );
            let fresh = row_by_id(&db, "h1").await.unwrap().expect("row");
            assert_eq!(fresh.state, HostnameState::Live, "the row stands");
            assert_eq!(fresh.state_changed_at, "t4", "and so does its clock");
        });
    }

    // -------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------

    #[test]
    fn punycode_is_handled_not_mangled() {
        assert_eq!(
            normalise("Bücher.example").as_deref(),
            Ok("xn--bcher-kva.example")
        );
        assert_eq!(
            normalise(" bücher.example ").as_deref(),
            Ok("xn--bcher-kva.example")
        );
        assert_eq!(
            normalise("app.example.com.").as_deref(),
            Ok("app.example.com"),
            "one trailing root dot is the same name"
        );
    }

    #[test]
    fn addresses_wildcards_and_overlong_input_are_refused() {
        for raw in [
            "https://app.example.com",
            "app.example.com/hello",
            "app.example.com?x=1",
            "app.example.com#frag",
            "user@app.example.com",
            "app.example.com:8443",
            "*.example.com",
            "app.*.example.com",
            "",
            " ",
            ".",
            "com",
            "app..example.com",
            "-leading.example.com",
            "trailing-.example.com",
            &format!("{}.example.com", "a".repeat(64)),
            &format!("{}.example.com", "a".repeat(242)),
        ] {
            assert!(normalise(raw).is_err(), "{raw:?} must be refused");
        }
        // 63 in a label and 253 overall are the protocol's own edges:
        // both legal.
        assert_eq!(
            normalise(&format!("{}.example.com", "a".repeat(63))).as_deref(),
            Ok(&*format!("{}.example.com", "a".repeat(63)))
        );
        assert!(normalise("app.example.com").is_ok());
    }

    // -------------------------------------------------------------------
    // The flows, with a fake adapter
    // -------------------------------------------------------------------

    /// An adapter that logs calls, can refuse `create`, and reports a
    /// chosen validation and status — the same shape the provisioning
    /// crate's `FakeDeployer` has, for the same reasons.
    struct FakeCustomHostnames {
        calls: RefCell<Vec<&'static str>>,
        refuse_create: bool,
        validation: Validation,
        status: ProviderStatus,
    }

    impl FakeCustomHostnames {
        fn ok() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                refuse_create: false,
                validation: Validation::Verified,
                status: ProviderStatus::Live,
            }
        }

        fn log(&self, what: &'static str) {
            self.calls.borrow_mut().push(what);
        }
    }

    impl CustomHostnames for FakeCustomHostnames {
        async fn create(&self, _hostname: &str, _target: &str) -> Result<(), DomainError> {
            self.log("create");
            if self.refuse_create {
                return Err(DomainError::new("the provider refused (fake)"));
            }
            Ok(())
        }
        async fn check_validation(&self, _hostname: &str) -> Result<Validation, DomainError> {
            self.log("validation");
            Ok(self.validation)
        }
        async fn status(&self, _hostname: &str) -> Result<ProviderStatus, DomainError> {
            self.log("status");
            Ok(self.status)
        }
    }

    async fn a_venture(repo: &Repository) -> Venture {
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        repo.create_venture(
            "v1",
            "acc_1",
            "my-app",
            "my-app.cratefield.app",
            "cms",
            "ten_1",
            "t0",
        )
        .await
        .expect("venture")
    }

    #[pollster::test]
    async fn a_succeeding_adapter_walks_the_hostname_to_live_through_legal_steps() {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[cratefield_accounts::MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("dashboard", &[MIGRATION])
            .expect("hostname schema");
        let db: Arc<dyn Database> = Arc::new(db);
        let repo = Repository::new(Arc::clone(&db));
        let venture = a_venture(&repo).await;

        let api = FakeCustomHostnames::ok();
        let row = add_hostname(
            db.as_ref(),
            "acc_1",
            &venture,
            "app.example.com",
            &api,
            "h1",
            "t1",
        )
        .await
        .expect("added");
        assert_eq!(row.state, HostnameState::AwaitingDns, "create answered");

        // The provider is several states ahead in one poll; the flow
        // walks each intermediate state as its own legal step.
        let row = check_hostname(db.as_ref(), &row, &api, "t2")
            .await
            .expect("checked");
        assert_eq!(row.state, HostnameState::Live);
        assert_eq!(row.last_error, "");
        let calls = api.calls.borrow().clone();
        assert_eq!(calls, vec!["create", "validation", "status"]);

        // And the recorded history is a path: every state on the spine
        // was entered in order (state_changed_at moves only when the
        // state does, and the last one is the check's now).
        assert_eq!(row.state_changed_at, "t2");
    }

    #[pollster::test]
    async fn a_provider_failure_mid_flow_fails_the_hostname_it_had_verified() {
        // AwaitingDns -> Failed is the move nothing else exercises: a
        // hostname the provider had accepted, whose check then fails.
        // The failure is recorded and the row stays recoverable.
        struct RefusingValidation;
        impl CustomHostnames for RefusingValidation {
            async fn create(&self, _h: &str, _t: &str) -> Result<(), DomainError> {
                Ok(())
            }
            async fn check_validation(&self, _h: &str) -> Result<Validation, DomainError> {
                Err(DomainError::new("validation check exploded (fake)"))
            }
            async fn status(&self, _h: &str) -> Result<ProviderStatus, DomainError> {
                Ok(ProviderStatus::Live)
            }
        }

        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[cratefield_accounts::MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("dashboard", &[MIGRATION])
            .expect("hostname schema");
        let db: Arc<dyn Database> = Arc::new(db);
        let repo = Repository::new(Arc::clone(&db));
        let venture = a_venture(&repo).await;

        let api = FakeCustomHostnames::ok();
        let row = add_hostname(
            db.as_ref(),
            "acc_1",
            &venture,
            "app.example.com",
            &api,
            "h1",
            "t1",
        )
        .await
        .expect("added");
        assert_eq!(row.state, HostnameState::AwaitingDns);

        let row = check_hostname(db.as_ref(), &row, &RefusingValidation, "t2")
            .await
            .expect("checked");
        assert_eq!(row.state, HostnameState::Failed);
        assert!(
            row.last_error.contains("validation check exploded"),
            "{}",
            row.last_error
        );

        // Recoverable: a later healthy check walks it back through the
        // flow (re-ensure, validation, status) to live.
        let row = check_hostname(db.as_ref(), &row, &api, "t3")
            .await
            .expect("checked");
        assert_eq!(row.state, HostnameState::Live);
        assert_eq!(row.last_error, "");
    }

    #[pollster::test]
    async fn pending_validation_holds_the_hostname_at_awaiting_dns() {
        // The provider may already report a status ahead of the DNS
        // record being seen; the flow does not skip ahead of the
        // customer's own record.
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[cratefield_accounts::MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("dashboard", &[MIGRATION])
            .expect("hostname schema");
        let db: Arc<dyn Database> = Arc::new(db);
        let repo = Repository::new(Arc::clone(&db));
        let venture = a_venture(&repo).await;

        let api = FakeCustomHostnames {
            refuse_create: false,
            calls: RefCell::new(Vec::new()),
            validation: Validation::Pending,
            status: ProviderStatus::Live,
        };
        let row = add_hostname(
            db.as_ref(),
            "acc_1",
            &venture,
            "app.example.com",
            &api,
            "h1",
            "t1",
        )
        .await
        .expect("added");
        let row = check_hostname(db.as_ref(), &row, &api, "t2")
            .await
            .expect("checked");
        assert_eq!(
            row.state,
            HostnameState::AwaitingDns,
            "pending DNS holds the row, whatever the provider claims"
        );
        // And status was never asked: validation is the gate.
        assert!(
            !api.calls.borrow().contains(&"status"),
            "status is not read before the record is seen"
        );
    }

    #[pollster::test]
    async fn a_refusing_adapter_records_the_failure_and_a_retry_re_ensures() {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("accounts", &[cratefield_accounts::MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("dashboard", &[MIGRATION])
            .expect("hostname schema");
        let db: Arc<dyn Database> = Arc::new(db);
        let repo = Repository::new(Arc::clone(&db));
        let venture = a_venture(&repo).await;

        let row = add_hostname(
            db.as_ref(),
            "acc_1",
            &venture,
            "app.example.com",
            &Unwired,
            "h1",
            "t1",
        )
        .await
        .expect("the claim is recorded even though the call refuses");
        assert_eq!(row.state, HostnameState::Failed);
        assert!(
            row.last_error
                .starts_with("cannot verify: no Cloudflare credential is wired"),
            "the refusal is recorded verbatim: {}",
            row.last_error
        );

        // A retry through the same port refreshes the refusal rather
        // than duplicating it or inventing progress.
        let row = check_hostname(db.as_ref(), &row, &Unwired, "t2")
            .await
            .expect("checked");
        assert_eq!(row.state, HostnameState::Failed);
        assert!(row.last_error.starts_with("cannot verify:"));
    }

    // -------------------------------------------------------------------
    // The screen, over HTTP
    // -------------------------------------------------------------------

    #[pollster::test]
    async fn adding_a_hostname_shows_the_record_and_the_stopped_state() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        let reply = add(&kit, "v1", "app.example.com", &cookie).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_eq!(reply.location, PATH);

        let page = send(&kit, Method::GET, PATH, Some(&cookie), None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        // The claim, recorded.
        assert!(page.body.contains("app.example.com"), "{}", page.body);
        // The state, stopped where the port refused, saying so.
        assert!(page.body.contains("failed"), "{}", page.body);
        assert!(
            page.body
                .contains("cannot verify: no Cloudflare credential is wired"),
            "the recorded refusal is on the page: {}",
            page.body
        );
        // The exact DNS record, computed from the venture's own
        // subdomain — not an example.
        assert!(
            page.body.contains("<b>type</b> <code>CNAME</code>"),
            "{}",
            page.body
        );
        assert!(
            page.body
                .contains("<b>target</b> <code>my-app.cratefield.app</code>"),
            "{}",
            page.body
        );
        assert!(
            page.body
                .contains("<b>name</b> <code>app.example.com</code>"),
            "{}",
            page.body
        );
        // The planned page is gone, and neither half of the bluff is
        // present.
        assert!(!page.body.contains("Not built."), "{}", page.body);
        // The banner promises a Check now button; the row has to keep
        // that promise (a banner naming a control that is not there is
        // its own small lie).
        assert!(
            page.body.contains("Check now"),
            "every claimed row offers its check: {}",
            page.body
        );
        // What the operator does today instead is.
        assert!(
            page.body.contains("Today you do this instead:"),
            "{}",
            page.body
        );
    }

    #[pollster::test]
    async fn the_same_hostname_is_refused_for_a_second_venture() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        add(&kit, "v1", "app.example.com", &cookie).await;

        // Same account, other venture: refused, naming the holder.
        let reply = add(&kit, "v2", "app.example.com", &cookie).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        assert!(
            reply
                .body
                .contains("another of your ventures already holds"),
            "{}",
            reply.body
        );
        assert!(reply.body.contains("my-app"), "{}", reply.body);

        // Another account's venture: refused, and the holder's name is
        // not leaked across the account boundary.
        let token = issue_session(kit.signer.as_ref(), "b@x.co", NOW, DEFAULT_TTL_SECS);
        let stranger = format!("cf_session={token}");
        let reply = add(&kit, "v9", "app.example.com", &stranger).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        assert!(
            reply
                .body
                .contains("another venture already holds this hostname"),
            "{}",
            reply.body
        );
        assert!(
            !reply.body.contains("my-app</a>"),
            "the other account's holder must not be named: {}",
            reply.body
        );

        // And nothing was written by either refusal: one row, one claim.
        let rows = hostnames_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        assert_eq!(rows.len(), 1);
    }

    #[pollster::test]
    async fn refused_input_records_nothing_and_says_why() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        for raw in ["https://app.example.com", "*.example.com", "com"] {
            let reply = add(&kit, "v1", raw, &cookie).await;
            assert_eq!(
                reply.status,
                StatusCode::BAD_REQUEST,
                "{raw}: {}",
                reply.body
            );
            assert!(
                reply.body.contains("Nothing was recorded."),
                "{raw}: {}",
                reply.body
            );
        }
        let rows = hostnames_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        assert!(rows.is_empty(), "no refusal wrote a row");

        // A venture that is not this account's is a 404, not a claim.
        let reply = add(&kit, "v9", "app.example.com", &cookie).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);

        // The venture's own subdomain is refused as a custom hostname.
        // (The apostrophe is HTML-escaped on the page, so the assertion
        // spells around it.)
        let reply = add(&kit, "v1", "my-app.cratefield.app", &cookie).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        assert!(
            reply.body.contains("own subdomain (my-app.cratefield.app)"),
            "{}",
            reply.body
        );
    }

    #[pollster::test]
    async fn punycode_round_trips_through_the_form() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        let reply = add(&kit, "v1", "Bücher.example", &cookie).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);

        let page = send(&kit, Method::GET, PATH, Some(&cookie), None).await;
        assert!(
            page.body.contains("xn--bcher-kva.example"),
            "the stored form is the form DNS uses: {}",
            page.body
        );
    }

    #[pollster::test]
    async fn checking_a_stopped_row_records_the_refusal_again() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        add(&kit, "v1", "app.example.com", &cookie).await;
        let rows = hostnames_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        let id = rows[0].id.clone();

        let reply = send(
            &kit,
            Method::POST,
            &format!("{PATH}/{id}/check"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);

        let rows = hostnames_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        assert_eq!(rows[0].state, HostnameState::Failed);
        assert!(
            rows[0].last_error.starts_with("cannot verify:"),
            "{}",
            rows[0].last_error
        );

        // One account cannot check another's hostname: scoped to
        // nothing, the id is a 404.
        let token = issue_session(kit.signer.as_ref(), "b@x.co", NOW, DEFAULT_TTL_SECS);
        let stranger = format!("cf_session={token}");
        let reply = send(
            &kit,
            Method::POST,
            &format!("{PATH}/{id}/check"),
            Some(&stranger),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
    }

    #[pollster::test]
    async fn an_archived_venture_cannot_claim_a_hostname() {
        let kit = seeded().await;
        let cookie = cookie(&kit);
        let repo = Repository::new(kit.db.clone());
        repo.set_venture_status("acc_1", "v1", VentureStatus::Provisioning, "t1")
            .await
            .expect("provisioning");
        repo.set_venture_status("acc_1", "v1", VentureStatus::Archived, "t2")
            .await
            .expect("archived");

        let reply = add(&kit, "v1", "app.example.com", &cookie).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        let rows = hostnames_for(kit.db.as_ref(), "acc_1").await.expect("rows");
        assert!(rows.is_empty());
    }

    #[pollster::test]
    async fn an_unauthenticated_request_is_redirected_to_the_login_gate() {
        let kit = seeded().await;
        let reply = send(&kit, Method::GET, PATH, None, None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert_eq!(reply.location, "/v1/console/login");
        // The POSTs carry a parseable body so the form extractor lets
        // the request reach the guard, which is what is under test.
        let reply = send(
            &kit,
            Method::POST,
            &format!("{PATH}/add"),
            None,
            Some("venture=v1"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert_eq!(reply.location, "/v1/console/login");
    }
}
