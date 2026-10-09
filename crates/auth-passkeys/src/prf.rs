//! The PRF extension (issue #756).
//!
//! A passkey that can evaluate PRF lets an app unseal, at sign-in, what it
//! sealed with the same extension. This module's job is small and strict:
//! hand each credential a random salt at `login/options`, record what each
//! ceremony showed about whether the passkey can answer the extension at
//! all, and never accept the extension's *output*. The output is the hash
//! of the server's salt with the authenticator's own secret — this service
//! handed out the salt and has no use for the bytes it produced, so a body
//! that carries one is refused before anything is read or written.
//!
//! One row per credential in the module's own table: the salt and one of
//! three words. Rows are created lazily the first time a salt is needed,
//! so a credential registered before the extension existed gets one on its
//! next login, and they go away with their credential.

use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use cratefield_auth_core::{CREDENTIAL_PASSKEY, credentials_by_user};
use cratefield_core::{Database, DbError, Problem, Scope, Statement};
use http::HeaderMap;
use sea_query::{Alias, Expr, OnConflict, Query};
use serde_json::json;
use std::sync::Arc;

use crate::ModuleState;
use crate::challenge::credential_id_bytes;
use crate::request::{b64u, internal, ok, ports, require_session};

/// The PRF table, created by this module's migration. Must match the
/// `CREATE TABLE` in `migrations/sqlite/0002_passkey_prf.sql`.
pub(crate) const PRF_TABLE: &str = "auth_passkeys_prf";

/// 32 bytes, the size the PRF spec's examples use and what a `YubiKey`
/// expects, from the same CSPRNG the challenges draw on.
const SALT_BYTES: usize = 32;

/// Whether the passkey can answer the `prf` extension, as far as the
/// ceremonies so far have shown. `unknown` is the honest default: some
/// authenticators answer neither at creation nor at the next sign-in, and
/// `unsupported` is only ever earned by a client explicitly reporting no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfCapability {
    Supported,
    Unsupported,
    Unknown,
}

impl PrfCapability {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PrfCapability::Supported => "supported",
            PrfCapability::Unsupported => "unsupported",
            PrfCapability::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "supported" => Some(PrfCapability::Supported),
            "unsupported" => Some(PrfCapability::Unsupported),
            "unknown" => Some(PrfCapability::Unknown),
            _ => None,
        }
    }

    /// What a registration ceremony showed. The signed answer —
    /// `hmac-secret: true` inside the authenticator data — is the
    /// authenticator's own; `enabled` is the browser's, unsigned. Some
    /// authenticators answer neither at creation and only report on the
    /// next sign-in, so no signal stays `unknown` rather than being read
    /// as a no. Never `unsupported` here: absence of evidence at creation
    /// is not evidence of absence.
    #[must_use]
    pub fn at_registration(hmac_secret: bool, client_enabled: Option<bool>) -> Self {
        if hmac_secret || client_enabled == Some(true) {
            PrfCapability::Supported
        } else {
            PrfCapability::Unknown
        }
    }

    /// What a login's redacted client report showed: the unsigned report is
    /// all an assertion carries that this service can act on — the
    /// authenticator's own answer stays inside the device.
    #[must_use]
    pub fn from_login_report(client_enabled: Option<bool>) -> Self {
        match client_enabled {
            Some(true) => PrfCapability::Supported,
            Some(false) => PrfCapability::Unsupported,
            None => PrfCapability::Unknown,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PrfError {
    #[error("no entropy available: {0}")]
    Entropy(String),
    #[error("the prf row vanished after it was written")]
    Missing,
    #[error(transparent)]
    Db(#[from] DbError),
}

/// The salt a credential evaluates with, and the capability recorded for
/// it so far.
pub(crate) struct Entry {
    pub salt: Vec<u8>,
    pub capability: PrfCapability,
}

/// What the raw JSON body's `clientExtensionResults.prf` said. Read from
/// the raw value rather than the typed wire structs, which have no `prf`
/// field — serde would drop it.
pub(crate) struct ClientPrf {
    /// The client sent a PRF result. Never accepted: the result is the
    /// hash of this service's salt with the authenticator's secret, and
    /// the whole redaction rule exists so those bytes stay on the device.
    pub results: bool,
    /// The client's (unsigned) report of whether the passkey supports PRF.
    pub enabled: Option<bool>,
}

/// Reads `credential.clientExtensionResults.prf` out of a verify body. The
/// `extensions` spelling is accepted too, which is what the wire structs
/// alias.
pub(crate) fn client_prf(body: &serde_json::Value) -> ClientPrf {
    let prf = body
        .get("credential")
        .and_then(|credential| {
            credential
                .get("clientExtensionResults")
                .or_else(|| credential.get("extensions"))
        })
        .and_then(|results| results.get("prf"));
    ClientPrf {
        results: prf.is_some_and(|prf| prf.get("results").is_some()),
        enabled: prf
            .and_then(|prf| prf.get("enabled"))
            .and_then(serde_json::Value::as_bool),
    }
}

/// Parses a verify body the way both ceremonies must: as a value first, to
/// read the client extension results the typed wire structs have no field
/// for, then into those structs. A body carrying a PRF result is refused
/// here, before anything else — the refusal spends no challenge, stores
/// nothing and issues no session (issue #756). This service hands salts
/// out; the extension's output stays on the device. The client is expected
/// to send a redacted `prf: { enabled }`.
pub(crate) fn parse_body<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    scope: &Scope,
) -> Result<(ClientPrf, T), Problem> {
    let value: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|err| Problem::validation_failed(format!("body is not a credential: {err}")))?;
    let client_prf = client_prf(&value);
    if client_prf.results {
        return Err(Problem::new(&crate::PRF_OUTPUT_REJECTED).instance(&scope.request_id));
    }
    let body: T = serde_json::from_value(value)
        .map_err(|err| Problem::validation_failed(format!("body is not a credential: {err}")))?;
    Ok((client_prf, body))
}

/// The `prf` extension for a login options call (issue #756): one salt per
/// credential the browser may answer with, created lazily so a credential
/// registered before the extension existed gets its row at its next login.
/// `eval` with the salt when exactly one credential may answer,
/// `evalByCredential` — keyed by the base64url credential id, the WebAuthn
/// JSON form — when several. For a discoverable login this service cannot
/// know which credential will answer, so there is no extension at all.
pub(crate) async fn eval_extension(
    db: &dyn Database,
    allowed: &[webauthn_rs_proto::AllowCredentials],
    now: &str,
) -> Result<Option<serde_json::Value>, PrfError> {
    let mut salts = Vec::with_capacity(allowed.len());
    for credential in allowed {
        salts.push(ensure(db, &credential.id, now).await?.salt);
    }
    Ok(match allowed.len() {
        0 => None,
        1 => Some(json!({
            "prf": { "eval": { "first": b64u(&salts[0]) } }
        })),
        _ => Some(json!({
            "prf": {
                "evalByCredential": allowed
                    .iter()
                    .zip(salts.iter())
                    .map(|(credential, salt)| {
                        (
                            b64u(credential.id.as_slice()),
                            json!({ "first": b64u(salt) }),
                        )
                    })
                    .collect::<serde_json::Map<String, serde_json::Value>>(),
            }
        })),
    })
}

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

async fn entry_of(db: &dyn Database, credential_id: &[u8]) -> Result<Option<Entry>, DbError> {
    let mut select = Query::select();
    select
        .columns(["salt", "prf"])
        .from(iden(PRF_TABLE))
        .and_where(Expr::col(iden("credential_id")).eq(credential_id.to_vec()));
    let rows = db.query(&Statement::render(&select)).await?;
    Ok(rows.first().and_then(|row| {
        Some(Entry {
            salt: row.get::<Vec<u8>>("salt")?,
            capability: row
                .get::<String>("prf")
                .as_deref()
                .and_then(PrfCapability::parse)
                .unwrap_or(PrfCapability::Unknown),
        })
    }))
}

/// The salt for `credential_id`, creating the row if this credential
/// predates the extension, with the capability recorded so far.
///
/// # Errors
///
/// [`PrfError`] when entropy or the database fails.
pub(crate) async fn ensure(
    db: &dyn Database,
    credential_id: &[u8],
    now: &str,
) -> Result<Entry, PrfError> {
    if let Some(entry) = entry_of(db, credential_id).await? {
        return Ok(entry);
    }
    let mut salt = [0u8; SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|err| PrfError::Entropy(err.to_string()))?;
    let mut insert = Query::insert();
    insert
        .into_table(iden(PRF_TABLE))
        .columns(["credential_id", "salt", "prf", "updated_at"])
        .values_panic([
            credential_id.to_vec().into(),
            salt.to_vec().into(),
            PrfCapability::Unknown.as_str().into(),
            now.to_owned().into(),
        ])
        .on_conflict(
            OnConflict::column(iden("credential_id"))
                .do_nothing()
                .to_owned(),
        );
    db.execute(&Statement::render(&insert)).await?;
    // The insert may have lost to a concurrent ceremony for the same
    // credential; either way exactly one salt exists now, and it is the
    // one the earlier caller handed out.
    entry_of(db, credential_id).await?.ok_or(PrfError::Missing)
}

/// Applies what a ceremony showed about `credential_id`, creating the row
/// if this credential predates the extension, and returns the entry — the
/// registration path sends the salt back with the stored credential.
///
/// `supported` is sticky: one ceremony that evaluated the extension proves
/// the passkey can, and a later one reporting otherwise never downgrades
/// it. Nothing here stores an extension output; there is no column for one.
///
/// # Errors
///
/// [`PrfError`] when entropy or the database fails.
pub(crate) async fn record(
    db: &dyn Database,
    credential_id: &[u8],
    capability: PrfCapability,
    now: &str,
) -> Result<Entry, PrfError> {
    let entry = ensure(db, credential_id, now).await?;
    match capability {
        // The row exists and already says `unknown`; a ceremony with no
        // opinion leaves it alone.
        PrfCapability::Unknown => {}
        PrfCapability::Supported => {
            let mut update = Query::update();
            update
                .table(iden(PRF_TABLE))
                .values([
                    (iden("prf"), PrfCapability::Supported.as_str().into()),
                    (iden("updated_at"), now.to_owned().into()),
                ])
                .and_where(Expr::col(iden("credential_id")).eq(credential_id.to_vec()));
            db.execute(&Statement::render(&update)).await?;
        }
        // Sticky: never overwrite `supported`.
        PrfCapability::Unsupported => {
            let mut update = Query::update();
            update
                .table(iden(PRF_TABLE))
                .values([
                    (iden("prf"), PrfCapability::Unsupported.as_str().into()),
                    (iden("updated_at"), now.to_owned().into()),
                ])
                .and_where(Expr::col(iden("credential_id")).eq(credential_id.to_vec()))
                .and_where(Expr::col(iden("prf")).ne(PrfCapability::Supported.as_str()));
            db.execute(&Statement::render(&update)).await?;
        }
    }
    Ok(entry)
}

/// Deletes the row when the credential goes. Reads filter against live
/// credentials anyway, so a row that outlives its credential is inert;
/// this keeps the table from growing orphans.
///
/// # Errors
///
/// [`DbError`] when the delete fails.
pub(crate) async fn forget(db: &dyn Database, credential_id: &[u8]) -> Result<(), DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(PRF_TABLE))
        .and_where(Expr::col(iden("credential_id")).eq(credential_id.to_vec()));
    db.execute(&Statement::render(&delete)).await?;
    Ok(())
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new().route("/passkeys/prf", get(list))
}

/// The signed-in account's passkeys with what this service knows about
/// each one's PRF capability and the salt it evaluates with. The salt is
/// not a secret — the app needs it, and the authenticator hashes it with
/// a secret that never leaves the device.
async fn list(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let session = require_session(&state, &headers, &scope).await?;
    let (db, clock, _) = ports(&state)?;
    let rows = credentials_by_user(db, &session.user_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not list credentials");
            internal(&scope)
        })?;

    let now = crate::iso(clock.now());
    let mut passkeys = Vec::new();
    // Filtered against live credentials, so a row whose credential went
    // away is invisible here.
    for row in rows.iter().filter(|row| row.kind == CREDENTIAL_PASSKEY) {
        let Some(id) = row.passkey_credential_id.as_ref() else {
            continue;
        };
        let entry = ensure(db, credential_id_bytes(id), &now)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "could not read the passkey's PRF entry");
                internal(&scope)
            })?;
        passkeys.push(json!({
            "credentialId": b64u(credential_id_bytes(id)),
            "prf": entry.capability.as_str(),
            "prfSalt": b64u(&entry.salt),
        }));
    }
    Ok(ok(json!({ "passkeys": passkeys })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capability_round_trips_through_its_stored_word() {
        for capability in [
            PrfCapability::Supported,
            PrfCapability::Unsupported,
            PrfCapability::Unknown,
        ] {
            assert_eq!(PrfCapability::parse(capability.as_str()), Some(capability));
        }
        assert_eq!(PrfCapability::parse("maybe"), None);
    }

    #[test]
    fn the_client_report_is_read_from_the_raw_body() {
        let body = serde_json::json!({
            "credential": {
                "clientExtensionResults": {
                    "prf": { "enabled": true }
                }
            }
        });
        let prf = client_prf(&body);
        assert!(!prf.results);
        assert_eq!(prf.enabled, Some(true));

        // The spelling the wire structs alias.
        let aliased = serde_json::json!({
            "credential": { "extensions": { "prf": { "enabled": false } } }
        });
        assert_eq!(client_prf(&aliased).enabled, Some(false));
    }

    #[test]
    fn a_result_is_detected_and_an_absent_report_is_no_opinion() {
        let with_results = serde_json::json!({
            "credential": {
                "clientExtensionResults": {
                    "prf": { "enabled": true, "results": { "first": "AA" } }
                }
            }
        });
        assert!(client_prf(&with_results).results);

        let no_prf = serde_json::json!({
            "credential": { "clientExtensionResults": {} }
        });
        let prf = client_prf(&no_prf);
        assert!(!prf.results);
        assert_eq!(prf.enabled, None);

        assert_eq!(client_prf(&serde_json::json!({})).enabled, None);
    }
}
