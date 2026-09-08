//! The login gate (issue #3): who may sign in, and how a session is proved.
//!
//! Cratefield is **invite-only** in v1. Login is Google SSO through
//! `Factory-Zero/auth`; the control plane is a relying party, not a second
//! identity provider, and it holds no password and no Google token beyond
//! the exchange. This crate owns the three pieces that are ours rather than
//! the auth service's:
//!
//! - the **whitelist** ([`Allowlist`]) keyed on the Google-verified email
//!   or hosted domain, with every add and remove kept as an operator action
//!   (the [`allowlist_audit`](MIGRATION) table);
//! - the **admission** decision ([`Allowlist::admit`]) that turns a verified
//!   identity into either an admitted account identity or a plain refusal —
//!   never a half-provisioned account;
//! - the **session cookie** ([`issue_session`], [`read_session`]), a
//!   [`Signer`]-signed token carried in an `HttpOnly; Secure; SameSite=Strict`
//!   cookie, short-lived and `kid`-rotated, the same mechanism the harness
//!   admin UI uses.
//!
//! **What is deferred, and why.** The Google exchange itself — code +
//! PKCE verifier to a [`VerifiedIdentity`] — is the auth service's job, and
//! it is blocked on that service having a wasm deploy target for the control
//! plane's callback URL (`webauthn-rs` pulls OpenSSL, which does not build
//! for `wasm32`; see the auth program notes and control-plane issue #3). So
//! this crate takes a [`VerifiedIdentity`] as its input and stops at the seam
//! rather than shipping an untestable HTTP client against a service that
//! cannot yet run. The wizard (issue #8) wires the live exchange in once the
//! auth service is deployable.

#![forbid(unsafe_code)]

use std::sync::Arc;

use cratefield_core::{Database, DbError, Kid, Payload, Signer, Statement};
use sea_query::Value as SeaValue;
use serde::{Deserialize, Serialize};

/// The schema migration, applied the way a harness module's is.
pub const MIGRATION: cratefield_core::SqlMigration = cratefield_core::SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

// ---------------------------------------------------------------------------
// Session cookie
// ---------------------------------------------------------------------------

/// The token `purpose` for a control-plane session, so a session token can
/// never be replayed as some other signed link and vice versa (ADR 0006).
pub const SESSION_PURPOSE: &str = "cratefield-session";

/// The session cookie name.
pub const COOKIE_NAME: &str = "cf_session";

/// Default session lifetime: eight hours. An operator signs in for a working
/// session, not indefinitely; the wizard may pass a shorter TTL.
pub const DEFAULT_TTL_SECS: u64 = 8 * 60 * 60;

/// A proven session: the account identity it names and when it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The account identity the session belongs to (a Google-verified email).
    pub account_id: String,
    /// Unix expiry in seconds, or `None` if the token carried no expiry.
    pub expires_at: Option<u64>,
}

/// Signs a session token for `account_id`, expiring `ttl_secs` from `now`.
///
/// `now` is a Unix timestamp in seconds; keeping it a parameter makes the
/// call testable without reaching for a clock. The returned string is the
/// bare token — wrap it with [`session_cookie`] before setting it.
#[must_use]
pub fn issue_session(signer: &dyn Signer, account_id: &str, now: u64, ttl_secs: u64) -> String {
    signer.sign(&Payload {
        purpose: SESSION_PURPOSE.to_owned(),
        subject: account_id.to_owned(),
        exp: Some(now.saturating_add(ttl_secs)),
        kid: Kid::Cur,
    })
}

/// Verifies a session token, returning the [`Session`] it proves or `None`
/// for a missing, tampered, wrong-purpose or expired token. Expiry is checked
/// against the wall clock inside the signer, so a stale cookie is refused
/// without the caller passing the time.
#[must_use]
pub fn read_session(signer: &dyn Signer, token: &str) -> Option<Session> {
    let payload = signer.verify(token, SESSION_PURPOSE)?;
    Some(Session {
        account_id: payload.subject,
        expires_at: payload.exp,
    })
}

/// The `Set-Cookie` value that carries a session token: `HttpOnly` so script
/// cannot read it, `Secure` so it never rides plaintext, `SameSite=Strict` so
/// it is not sent on cross-site navigations (CSRF), and `Path=/` with a
/// `Max-Age` matching the token TTL.
#[must_use]
pub fn session_cookie(token: &str, max_age_secs: u64) -> String {
    format!(
        "{COOKIE_NAME}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age_secs}"
    )
}

/// The `Set-Cookie` value that clears the session (logout): an empty token,
/// same attributes, `Max-Age=0` so the browser drops it immediately.
#[must_use]
pub fn clear_session_cookie() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
}

/// Pulls the session token out of a `Cookie:` header value, or `None` if this
/// request carries no session cookie. Does not verify it — pass the result to
/// [`read_session`].
#[must_use]
pub fn session_token_from_cookie_header(cookie_header: &str) -> Option<&str> {
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == COOKIE_NAME).then_some(value)
    })
}

// ---------------------------------------------------------------------------
// Whitelist and admission
// ---------------------------------------------------------------------------

/// What the auth service returns after a verified Google exchange. Produced
/// outside this crate (see the crate docs on the deferred exchange); the
/// email is Google-verified and the admission gate lowercases it before
/// matching, so the caller need not normalise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The Google-verified email address.
    pub email: String,
    /// The display name, carried through to the account on first login.
    pub name: String,
    /// The Google Workspace hosted domain, if the account has one.
    pub hosted_domain: Option<String>,
}

/// The gate's verdict for a verified identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// On the whitelist: the normalised identity and display name to log in
    /// as. This is the only value that should lead to a session.
    Admitted { identity: String, name: String },
    /// Not on the whitelist. The caller shows the invite-only page; it never
    /// creates an account.
    Refused,
}

/// Whether an allowlist entry names one address or a whole domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    Email,
    Domain,
}

impl EntryKind {
    fn as_str(self) -> &'static str {
        match self {
            EntryKind::Email => "email",
            EntryKind::Domain => "domain",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "email" => Some(EntryKind::Email),
            "domain" => Some(EntryKind::Domain),
            _ => None,
        }
    }
}

/// One whitelist entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowEntry {
    /// The match value: a lowercased email, or `@domain` for a domain entry.
    pub value: String,
    pub kind: EntryKind,
    pub note: String,
    pub added_by: String,
    pub added_at: String,
}

/// Failures from the allowlist repository.
#[derive(Debug)]
pub enum AccessError {
    Db(DbError),
    /// A row was malformed (an unknown `kind`, a missing column).
    Invalid(String),
}

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessError::Db(err) => write!(f, "database: {err}"),
            AccessError::Invalid(what) => write!(f, "invalid: {what}"),
        }
    }
}

impl std::error::Error for AccessError {}

impl From<DbError> for AccessError {
    fn from(err: DbError) -> Self {
        AccessError::Db(err)
    }
}

/// The whitelist, over the harness [`Database`] port. Mutations are audited:
/// [`allow`](Allowlist::allow) and [`revoke`](Allowlist::revoke) each write an
/// `allowlist_audit` row in the same call, so there is no way to change who is
/// admitted without leaving a record.
pub struct Allowlist {
    db: Arc<dyn Database>,
}

impl Allowlist {
    #[must_use]
    pub fn new(db: Arc<dyn Database>) -> Self {
        Self { db }
    }

    /// Decides admission for a verified identity: admitted iff the email is
    /// listed, or its domain is. The returned identity is the lowercased
    /// email, the same value [`crate::VerifiedIdentity::email`] would key an
    /// account on.
    ///
    /// # Errors
    ///
    /// [`AccessError::Db`] if the whitelist cannot be read.
    pub async fn admit(&self, identity: &VerifiedIdentity) -> Result<Admission, AccessError> {
        let email = identity.email.trim().to_lowercase();
        if self.contains(&email).await? {
            return Ok(Admission::Admitted {
                identity: email,
                name: identity.name.clone(),
            });
        }
        if let Some(domain) = domain_key_for(&email, identity.hosted_domain.as_deref())
            && self.contains(&domain).await?
        {
            return Ok(Admission::Admitted {
                identity: email,
                name: identity.name.clone(),
            });
        }
        Ok(Admission::Refused)
    }

    /// Adds a whitelist entry and records the action. `now` is RFC 3339;
    /// `id` is the audit row id. Idempotent on `value`: re-adding an existing
    /// entry replaces its note/attribution and still audits the action.
    ///
    /// # Errors
    ///
    /// [`AccessError::Db`].
    pub async fn allow(
        &self,
        value: &str,
        kind: EntryKind,
        note: &str,
        actor: &str,
        audit_id: &str,
        now: &str,
    ) -> Result<AllowEntry, AccessError> {
        let value = normalise_value(value, kind);
        // The mutation and its audit row commit together (`batch` is one unit
        // of work on SQLite and D1), so the whitelist can never change without
        // a matching audit record, and vice versa.
        self.db
            .batch(&[
                Statement::with_values(
                    "INSERT INTO allowlist (value, kind, note, added_by, added_at) \
                     VALUES (?, ?, ?, ?, ?) \
                     ON CONFLICT(value) DO UPDATE SET \
                     kind = excluded.kind, note = excluded.note, \
                     added_by = excluded.added_by, added_at = excluded.added_at",
                    vec![
                        text(&value),
                        text(kind.as_str()),
                        text(note),
                        text(actor),
                        text(now),
                    ],
                ),
                audit_statement(audit_id, "allow", &value, kind, actor, now),
            ])
            .await?;
        Ok(AllowEntry {
            value,
            kind,
            note: note.to_owned(),
            added_by: actor.to_owned(),
            added_at: now.to_owned(),
        })
    }

    /// Removes a whitelist entry and records the action. Removing an entry
    /// that is not there is not an error, but is only audited when something
    /// was actually removed, so the audit never claims a revoke that did not
    /// happen. Returns whether a row was removed.
    ///
    /// # Errors
    ///
    /// [`AccessError::Db`].
    pub async fn revoke(
        &self,
        value: &str,
        actor: &str,
        audit_id: &str,
        now: &str,
    ) -> Result<bool, AccessError> {
        let Some(entry) = self.entry(value).await? else {
            return Ok(false);
        };
        self.db
            .batch(&[
                Statement::with_values(
                    "DELETE FROM allowlist WHERE value = ?",
                    vec![text(&entry.value)],
                ),
                audit_statement(audit_id, "revoke", &entry.value, entry.kind, actor, now),
            ])
            .await?;
        Ok(true)
    }

    /// One whitelist entry by exact value, or `None`.
    ///
    /// # Errors
    ///
    /// [`AccessError::Db`].
    pub async fn entry(&self, value: &str) -> Result<Option<AllowEntry>, AccessError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT value, kind, note, added_by, added_at FROM allowlist WHERE value = ?",
                vec![text(&value.trim().to_lowercase())],
            ))
            .await?;
        rows.first().map(entry_from_row).transpose()
    }

    /// Every whitelist entry, oldest first. For the operator's admin page.
    ///
    /// # Errors
    ///
    /// [`AccessError::Db`].
    pub async fn entries(&self) -> Result<Vec<AllowEntry>, AccessError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT value, kind, note, added_by, added_at FROM allowlist \
                 ORDER BY added_at ASC",
                vec![],
            ))
            .await?;
        rows.rows.iter().map(entry_from_row).collect()
    }

    async fn contains(&self, value: &str) -> Result<bool, AccessError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT value FROM allowlist WHERE value = ?",
                vec![text(value)],
            ))
            .await?;
        Ok(!rows.is_empty())
    }
}

/// The audit insert for one whitelist mutation, batched alongside it so the
/// two commit together.
fn audit_statement(
    id: &str,
    action: &str,
    value: &str,
    kind: EntryKind,
    actor: &str,
    now: &str,
) -> Statement {
    Statement::with_values(
        "INSERT INTO allowlist_audit (id, action, value, kind, actor, at) \
         VALUES (?, ?, ?, ?, ?, ?)",
        vec![
            text(id),
            text(action),
            text(value),
            text(kind.as_str()),
            text(actor),
            text(now),
        ],
    )
}

/// The domain key (`@domain`) to test for an email, preferring the
/// Google-asserted hosted domain and falling back to the address's own
/// domain. `None` if the email has no `@`.
fn domain_key_for(email: &str, hosted_domain: Option<&str>) -> Option<String> {
    if let Some(hd) = hosted_domain {
        let hd = hd.trim().to_lowercase();
        if !hd.is_empty() {
            return Some(format!("@{hd}"));
        }
    }
    email
        .rsplit_once('@')
        .map(|(_, domain)| format!("@{domain}"))
}

/// Normalises an entry value: lowercased, and a domain entry is stored with a
/// single leading `@` regardless of how the operator typed it.
fn normalise_value(value: &str, kind: EntryKind) -> String {
    let v = value.trim().to_lowercase();
    match kind {
        EntryKind::Email => v,
        EntryKind::Domain => format!("@{}", v.trim_start_matches('@')),
    }
}

fn entry_from_row(row: &cratefield_core::Row) -> Result<AllowEntry, AccessError> {
    Ok(AllowEntry {
        value: field(row, "value")?,
        kind: EntryKind::parse(&field(row, "kind")?)
            .ok_or_else(|| AccessError::Invalid("allowlist kind".to_owned()))?,
        note: field(row, "note")?,
        added_by: field(row, "added_by")?,
        added_at: field(row, "added_at")?,
    })
}

fn field(row: &cratefield_core::Row, name: &str) -> Result<String, AccessError> {
    row.get(name)
        .ok_or_else(|| AccessError::Invalid(format!("row has no `{name}`")))
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_adapter_sqlite::SqliteDatabase;
    use cratefield_core::HmacSigner;

    const SECRET: &str = "0123456789abcdef0123456789abcdef"; // 32 bytes

    fn allowlist() -> Allowlist {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("access", &[MIGRATION]).expect("schema");
        Allowlist::new(Arc::new(db))
    }

    fn signer() -> HmacSigner {
        HmacSigner::new(SECRET, None).expect("secret long enough")
    }

    // Far in the future (2100-01-01): the signer checks expiry against the
    // real wall clock, so a token issued here is not already stale.
    fn now() -> u64 {
        4_102_444_800
    }

    // -- session --------------------------------------------------------

    #[test]
    fn a_session_round_trips() {
        let s = signer();
        let token = issue_session(&s, "ada@example.com", now(), DEFAULT_TTL_SECS);
        let session = read_session(&s, &token).expect("valid");
        assert_eq!(session.account_id, "ada@example.com");
        assert_eq!(session.expires_at, Some(now() + DEFAULT_TTL_SECS));
    }

    #[test]
    fn an_expired_session_is_refused() {
        let s = signer();
        // Issued far in the past with a tiny TTL: expiry is before the wall
        // clock the signer checks against, so verify rejects it.
        let token = issue_session(&s, "ada@example.com", 1_000, 1);
        assert!(read_session(&s, &token).is_none(), "stale cookie refused");
    }

    #[test]
    fn a_tampered_or_foreign_token_is_refused() {
        let s = signer();
        let token = issue_session(&s, "ada@example.com", now(), DEFAULT_TTL_SECS);
        let mut bytes = token.into_bytes();
        *bytes.last_mut().unwrap() ^= 0x01;
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(read_session(&s, &tampered).is_none(), "tamper refused");

        let other = HmacSigner::new("ffffffffffffffffffffffffffffffff", None).unwrap();
        let foreign = issue_session(&other, "mallory@example.com", now(), DEFAULT_TTL_SECS);
        assert!(read_session(&s, &foreign).is_none(), "other key refused");
    }

    #[test]
    fn a_session_token_is_not_replayable_under_another_purpose() {
        // The session token must not verify as, say, a confirm link.
        let s = signer();
        let token = issue_session(&s, "ada@example.com", now(), DEFAULT_TTL_SECS);
        assert!(s.verify(&token, "confirm").is_none());
        assert!(s.verify(&token, SESSION_PURPOSE).is_some());
    }

    #[test]
    fn the_cookie_carries_the_hardening_attributes() {
        let cookie = session_cookie("tok", 3600);
        assert!(cookie.starts_with("cf_session=tok;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(clear_session_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn the_token_is_read_out_of_a_cookie_header() {
        let header = "theme=dark; cf_session=abc.def; other=1";
        assert_eq!(session_token_from_cookie_header(header), Some("abc.def"));
        assert_eq!(session_token_from_cookie_header("theme=dark"), None);
    }

    // -- whitelist and admission ---------------------------------------

    #[pollster::test]
    async fn an_unlisted_identity_is_refused_not_errored() {
        let list = allowlist();
        let outcome = list
            .admit(&VerifiedIdentity {
                email: "stranger@example.com".into(),
                name: "Stranger".into(),
                hosted_domain: None,
            })
            .await
            .expect("a decision, not an error");
        assert_eq!(outcome, Admission::Refused);
    }

    #[pollster::test]
    async fn a_listed_email_is_admitted_case_insensitively() {
        let list = allowlist();
        list.allow(
            "Ada@Example.com",
            EntryKind::Email,
            "founder",
            "op",
            "aud_1",
            "t0",
        )
        .await
        .expect("allow");
        let outcome = list
            .admit(&VerifiedIdentity {
                email: "ADA@example.COM".into(),
                name: "Ada".into(),
                hosted_domain: None,
            })
            .await
            .expect("decision");
        assert_eq!(
            outcome,
            Admission::Admitted {
                identity: "ada@example.com".into(),
                name: "Ada".into(),
            }
        );
    }

    #[pollster::test]
    async fn a_domain_entry_admits_anyone_on_that_hosted_domain() {
        let list = allowlist();
        list.allow(
            "cratefield.com",
            EntryKind::Domain,
            "the team",
            "op",
            "aud_1",
            "t0",
        )
        .await
        .expect("allow");
        // Stored with a single leading @, however it was typed.
        assert!(list.entry("@cratefield.com").await.unwrap().is_some());
        let outcome = list
            .admit(&VerifiedIdentity {
                email: "new.hire@cratefield.com".into(),
                name: "New Hire".into(),
                hosted_domain: Some("cratefield.com".into()),
            })
            .await
            .expect("decision");
        assert!(matches!(outcome, Admission::Admitted { .. }));
    }

    #[pollster::test]
    async fn a_lookalike_domain_is_not_admitted_by_the_address_domain() {
        // Without a Google-asserted hosted domain, an attacker whose address
        // merely ends in the listed domain must still be admitted only if
        // that exact domain is listed — and here it is a different domain.
        let list = allowlist();
        list.allow("cratefield.com", EntryKind::Domain, "", "op", "aud_1", "t0")
            .await
            .unwrap();
        let outcome = list
            .admit(&VerifiedIdentity {
                email: "evil@cratefield.com.attacker.test".into(),
                name: "Evil".into(),
                hosted_domain: None,
            })
            .await
            .unwrap();
        assert_eq!(outcome, Admission::Refused);
    }

    #[pollster::test]
    async fn allow_and_revoke_are_audited() {
        let list = allowlist();
        list.allow(
            "ada@example.com",
            EntryKind::Email,
            "founder",
            "op",
            "aud_1",
            "t0",
        )
        .await
        .unwrap();
        let removed = list
            .revoke("ada@example.com", "op", "aud_2", "t1")
            .await
            .unwrap();
        assert!(removed);
        assert!(list.entry("ada@example.com").await.unwrap().is_none());

        // Both actions are on the audit record, in order.
        let rows = list
            .db
            .query(&Statement::with_values(
                "SELECT action, value, actor FROM allowlist_audit ORDER BY at ASC",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "allow then revoke both recorded");
        assert_eq!(
            rows.rows[0].get::<String>("action").as_deref(),
            Some("allow")
        );
        assert_eq!(
            rows.rows[1].get::<String>("action").as_deref(),
            Some("revoke")
        );
    }

    #[pollster::test]
    async fn revoking_a_missing_entry_is_a_no_op_and_not_audited() {
        let list = allowlist();
        let removed = list
            .revoke("ghost@example.com", "op", "aud_1", "t0")
            .await
            .unwrap();
        assert!(!removed, "nothing to remove");
        let rows = list
            .db
            .query(&Statement::with_values(
                "SELECT id FROM allowlist_audit",
                vec![],
            ))
            .await
            .unwrap();
        assert!(rows.is_empty(), "no audit for a revoke that did not happen");
    }

    #[pollster::test]
    async fn re_adding_updates_the_note_and_re_audits() {
        let list = allowlist();
        list.allow(
            "ada@example.com",
            EntryKind::Email,
            "first",
            "op",
            "aud_1",
            "t0",
        )
        .await
        .unwrap();
        list.allow(
            "ada@example.com",
            EntryKind::Email,
            "second",
            "op2",
            "aud_2",
            "t1",
        )
        .await
        .unwrap();
        let entry = list
            .entry("ada@example.com")
            .await
            .unwrap()
            .expect("present");
        assert_eq!(entry.note, "second");
        assert_eq!(entry.added_by, "op2");
        assert_eq!(list.entries().await.unwrap().len(), 1, "not duplicated");
    }
}
