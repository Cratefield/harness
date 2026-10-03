//! The server half of `fz auth import` (issue #650, part B): the admin
//! routes that move a system of record's users into a venture without
//! losing the password verifier or the verified address.
//!
//! Two routes, both under the admin router and so behind the same
//! `Authorization: Bearer <ADMIN_TOKEN>` guard as the client API
//! ([`crate::clients`]):
//!
//! - `POST /admin/users/import` — validate and (unless `dry_run`) apply
//!   up to [`MAX_IMPORT_USERS`] users, answering one verdict per user in
//!   request order;
//! - `GET /admin/users/by-external-id` — the `sub` an import wrote, so a
//!   caller can check what landed without holding the ids.
//!
//! An imported person is an ordinary account plus an `identities` row with
//! provider `import` whose subject is `<external_provider>:<external_id>`.
//! That row is the idempotency key: a second run of the same import finds
//! it and reports `unchanged`, writing nothing.
//!
//! The password verifier is stored verbatim, so a person signs in with the
//! password they already had and is upgraded to argon2id on that first
//! login (the login path in `auth-password` does the rehash). A hash this
//! crate cannot verify is refused rather than written: a row nobody can
//! sign in to is worse than a row that never existed.
//!
//! Nothing in the response carries an email or a hash — only the
//! `(external_provider, external_id)` the caller sent, the verdict, the
//! `sub`, and a short machine reason. The request is the only place those
//! values appear.
//!
//! # Partial failures
//!
//! Every user is written on its own; the loop holds no transaction, because
//! a request may carry a thousand and each user's outcome stands alone. A
//! store error ends the request with a 500 after the users before it were
//! written, and the import identity makes a re-run report each of those
//! `unchanged`, so a retry continues the batch rather than duplicating it.
//!
//! # Rate limiting
//!
//! No limiter of its own: the harness already limits every `/admin/*`
//! path by client IP at the edge (issue #437, `crates/core/src/harness.rs`),
//! which is the budget an import should draw from. A second limiter here
//! would be a second key to tune for no new protection.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use cratefield_core::{Database, IdGen, Json, Problem, Scope, is_valid, normalize_email};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

use crate::LegacyHashes;
use crate::ModuleState;
use crate::secrets::{BCRYPT_MAX_COST, bcrypt_cost, is_argon2id_phc};
use crate::store::{
    self, CREDENTIAL_PASSWORD, CredentialRow, IdentityRow, PROVIDER_IMPORT, PROVIDER_PASSWORD,
    Redacted, STATUS_ACTIVE, UserRow,
};

/// Users one request may carry. Above this the import is refused whole, so
/// a caller can batch without ever half-applying an oversized run. The CLI
/// defaults to fewer per request ([`cratefield-cli`]'s `--batch-size`).
pub(crate) const MAX_IMPORT_USERS: usize = 1000;

/// The largest import body this module accepts, raising core's 64 KiB
/// `/v1/*` cap (issue #440): a thousand users, each with an address and a
/// PHC hash, do not fit in 64 KiB. The import route carries its own
/// `DefaultBodyLimit` at exactly this value, and [`crate::AuthCore`]
/// reports it from `max_body_bytes` so a runtime refuses above it before
/// buffering.
pub(crate) const MAX_IMPORT_BYTES: usize = 2 * 1024 * 1024;

/// An `external_id` may be this many bytes; the column is TEXT and the id
/// comes from somebody else's system, so the bound is generous but finite.
const MAX_EXTERNAL_ID_BYTES: usize = 255;

/// The longest `external_provider`: `^[a-z0-9][a-z0-9_-]{0,31}$`.
const MAX_PROVIDER_BYTES: usize = 32;

/// More users than one request may carry (413). A stable slug so a caller
/// can batch: the whole request is refused, nothing is written, and the
/// caller retries in smaller pieces.
pub(crate) const IMPORT_TOO_LARGE: cratefield_core::ProblemDef = cratefield_core::ProblemDef {
    slug: "auth/import-too-large",
    status: StatusCode::PAYLOAD_TOO_LARGE,
    title: "Too many users to import",
    description: "An import may carry at most 1000 users in one request; \
                  nothing was written.",
};

pub(crate) fn router(state: Arc<ModuleState>) -> axum::Router {
    // The import route raises core's 64 KiB /v1/* cap for itself; axum
    // resolves the innermost DefaultBodyLimit, so this wins for this route
    // and this route only.
    let import = post(import_users).layer(DefaultBodyLimit::max(MAX_IMPORT_BYTES));
    axum::Router::new()
        .route("/admin/users/import", import)
        .route("/admin/users/by-external-id", get(by_external_id))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::clients::admin_guard,
        ))
        .with_state(state)
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

#[derive(Deserialize)]
struct ImportBody {
    dry_run: bool,
    merge_by_email: bool,
    users: Vec<ImportUser>,
}

/// One user to import. `locale` and any other field a caller sends are
/// ignored: an imported account starts with no stored locale (issue #649
/// stores one only when it is a tag the deployment lists in
/// `AUTH_LOCALES`, which the import does not check), and the store's shape
/// is the contract — an unknown field is not an error.
#[derive(Deserialize)]
struct ImportUser {
    external_provider: String,
    external_id: String,
    email: String,
    email_verified: bool,
    password_hash: Option<String>,
    created_at: Option<String>,
}

/// One user's verdict.
struct Verdict {
    status: &'static str,
    sub: Option<String>,
    reason: Option<&'static str>,
}

impl Verdict {
    fn invalid(reason: &'static str) -> Self {
        Self {
            status: "invalid",
            sub: None,
            reason: Some(reason),
        }
    }
}

/// `POST /admin/users/import`.
async fn import_users(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    raw: Bytes,
) -> Result<Response, Problem> {
    // Parsed by hand so a malformed body is a `400 validation-failed`
    // problem rather than axum's own rejection, which is not problem+json.
    // The message names no field value, so a malformed body cannot echo an
    // address or a hash back.
    let body: ImportBody = serde_json::from_slice(&raw).map_err(|_| {
        Problem::validation_failed("the request body is not a valid import document")
            .instance(&scope.request_id)
    })?;
    if body.users.len() > MAX_IMPORT_USERS {
        return Err(Problem::new(&IMPORT_TOO_LARGE).instance(&scope.request_id));
    }

    let (Some(db), Some(clock), Some(id_gen)) = (
        state.ctx.ports.db.clone(),
        state.ctx.ports.clock.clone(),
        state.ctx.ports.id_gen.clone(),
    ) else {
        return Err(internal(&scope));
    };
    // A typo in the legacy list is a misconfiguration the login path
    // already warns about; here it reads as "bcrypt is off", which is the
    // safe direction — a bcrypt row is refused, not written and orphaned.
    let legacy = match LegacyHashes::from_config(&*state.ctx.config) {
        Ok(legacy) => legacy,
        Err(err) => {
            tracing::warn!(error = %err, "auth-core: legacy-hash configuration is invalid");
            LegacyHashes::default()
        }
    };
    let now = crate::clients::now_iso(&*clock);

    let mut owned: HashMap<String, Option<String>> = HashMap::new();
    let mut results = Vec::with_capacity(body.users.len());
    for user in &body.users {
        let verdict = import_one(&*db, &*id_gen, legacy, &body, user, &now, &mut owned).await?;
        results.push(json!({
            "external_provider": user.external_provider,
            "external_id": user.external_id,
            "status": verdict.status,
            "sub": verdict.sub,
            "reason": verdict.reason,
        }));
    }

    tracing::info!(
        audit = true,
        action = "user.import",
        users = body.users.len(),
        dry_run = body.dry_run,
        "auth-core admin"
    );
    Ok(Json(json!({
        "dry_run": body.dry_run,
        "results": results,
    }))
    .into_response())
}

/// Validates one user and, unless this is a dry run, applies it. `owned`
/// records the normalised address of every user this request has already
/// accounted for, so an earlier row in the same request owns its email
/// even in a dry run, when nothing has been written to find.
async fn import_one(
    db: &dyn Database,
    id_gen: &dyn IdGen,
    legacy: LegacyHashes,
    body: &ImportBody,
    user: &ImportUser,
    now: &str,
    owned: &mut HashMap<String, Option<String>>,
) -> Result<Verdict, Problem> {
    if !valid_provider(&user.external_provider) {
        return Ok(Verdict::invalid("invalid-provider"));
    }
    if !valid_external_id(&user.external_id) {
        return Ok(Verdict::invalid("invalid-external-id"));
    }
    let email = normalize_email(&user.email);
    if !is_valid(&email) {
        return Ok(Verdict::invalid("invalid-email"));
    }
    let created_at = match &user.created_at {
        Some(raw) => match canonical_instant(raw) {
            Some(instant) => instant,
            None => return Ok(Verdict::invalid("invalid-created-at")),
        },
        None => now.to_owned(),
    };
    if let Some(hash) = &user.password_hash
        && let Some(reason) = unacceptable_hash(hash, legacy)
    {
        return Ok(Verdict::invalid(reason));
    }

    let subject = format!("{}:{}", user.external_provider, user.external_id);
    // The import identity is the idempotency key: seen before, this user is
    // already here, whatever else changed, and nothing is written.
    if let Some(identity) =
        store::identity_by_provider_subject(db, PROVIDER_IMPORT, &subject).await?
    {
        return Ok(Verdict {
            status: "unchanged",
            sub: Some(identity.user_id),
            reason: None,
        });
    }

    // Who owns this address: an earlier row in this request, or an account
    // the store already holds. `Some(sub)` is the owner's id, or `None`
    // when this request would have created it and is only dry-running.
    let claim: Option<Option<String>> = match owned.get(&email) {
        Some(sub) => Some(sub.clone()),
        None => store::user_by_primary_email(db, &email)
            .await?
            .map(|row| Some(row.id)),
    };

    if let Some(sub) = claim {
        if !body.merge_by_email {
            return Ok(Verdict {
                status: "conflict",
                sub: None,
                reason: Some("email-exists"),
            });
        }
        // Merged into the account that owns the address. The account's
        // own row is left alone — no email, no timestamp, and above all
        // no existing password credential is overwritten.
        if !body.dry_run
            && let Some(user_id) = sub.as_deref()
        {
            attach_import_identity(db, id_gen, user_id, &subject, user, &email, now).await?;
            attach_password_if_absent(db, id_gen, user_id, user, &email, now).await?;
        }
        owned.insert(email, sub.clone());
        Ok(Verdict {
            status: "merged",
            sub,
            reason: None,
        })
    } else {
        let sub = if body.dry_run {
            None
        } else {
            let user_id = id_gen.ulid();
            create_imported_user(db, id_gen, &user_id, user, &email, &created_at, now).await?;
            Some(user_id)
        };
        owned.insert(email, sub.clone());
        Ok(Verdict {
            status: "created",
            sub,
            reason: None,
        })
    }
}

/// Writes the user, the `import` identity, and — when a hash was given —
/// the password identity and credential, mirroring what `auth-password`'s
/// `create_account` writes so password login finds the account.
async fn create_imported_user(
    db: &dyn Database,
    id_gen: &dyn IdGen,
    user_id: &str,
    user: &ImportUser,
    email: &str,
    created_at: &str,
    now: &str,
) -> Result<(), Problem> {
    store::insert_user(
        db,
        &UserRow {
            id: user_id.to_owned(),
            display_name: None,
            primary_email: Some(email.to_owned()),
            // The row's own claim. The linking rules only auto-link a
            // verified address, so an import that says "verified" says so
            // about an address the source system already proved.
            primary_email_verified: user.email_verified,
            // Not carried over (see `ImportUser`): the request resolves
            // one per mail until the person picks one.
            locale: None,
            status: STATUS_ACTIVE.to_owned(),
            created_at: created_at.to_owned(),
            updated_at: now.to_owned(),
        },
    )
    .await?;
    store::insert_identity(
        db,
        &IdentityRow {
            id: id_gen.ulid(),
            user_id: user_id.to_owned(),
            provider: PROVIDER_IMPORT.to_owned(),
            provider_subject: format!("{}:{}", user.external_provider, user.external_id),
            email: Some(email.to_owned()),
            email_verified: user.email_verified,
            name_at_link: None,
            created_at: now.to_owned(),
            last_login_at: None,
        },
    )
    .await?;
    if let Some(hash) = &user.password_hash {
        insert_password_identity(db, id_gen, user_id, email, user.email_verified, now).await?;
        insert_password_credential(db, id_gen, user_id, hash, now).await?;
    }
    Ok(())
}

/// Attaches the `import` identity to an existing account, leaving the
/// account's own row untouched.
async fn attach_import_identity(
    db: &dyn Database,
    id_gen: &dyn IdGen,
    user_id: &str,
    subject: &str,
    user: &ImportUser,
    email: &str,
    now: &str,
) -> Result<(), Problem> {
    store::insert_identity(
        db,
        &IdentityRow {
            id: id_gen.ulid(),
            user_id: user_id.to_owned(),
            provider: PROVIDER_IMPORT.to_owned(),
            provider_subject: subject.to_owned(),
            email: Some(email.to_owned()),
            email_verified: user.email_verified,
            name_at_link: None,
            created_at: now.to_owned(),
            last_login_at: None,
        },
    )
    .await?;
    Ok(())
}

/// On a merge, adds a password only when there is none: an account that can
/// already sign in with a password keeps the one it has.
async fn attach_password_if_absent(
    db: &dyn Database,
    id_gen: &dyn IdGen,
    user_id: &str,
    user: &ImportUser,
    email: &str,
    now: &str,
) -> Result<(), Problem> {
    let Some(hash) = &user.password_hash else {
        return Ok(());
    };
    if store::password_credential(db, user_id).await?.is_some() {
        return Ok(());
    }
    // The password provider's subject is the address. If that identity is
    // somehow already taken — by this account or another — the credential
    // is still worth adding; only the identity insert is skipped.
    if store::identity_by_provider_subject(db, PROVIDER_PASSWORD, email)
        .await?
        .is_none()
    {
        insert_password_identity(db, id_gen, user_id, email, user.email_verified, now).await?;
    }
    insert_password_credential(db, id_gen, user_id, hash, now).await?;
    Ok(())
}

async fn insert_password_identity(
    db: &dyn Database,
    id_gen: &dyn IdGen,
    user_id: &str,
    email: &str,
    email_verified: bool,
    now: &str,
) -> Result<(), Problem> {
    store::insert_identity(
        db,
        &IdentityRow {
            id: id_gen.ulid(),
            user_id: user_id.to_owned(),
            provider: PROVIDER_PASSWORD.to_owned(),
            provider_subject: email.to_owned(),
            email: Some(email.to_owned()),
            email_verified,
            name_at_link: None,
            created_at: now.to_owned(),
            last_login_at: None,
        },
    )
    .await?;
    Ok(())
}

/// Stores the hash verbatim: it is verified, and upgraded on first login,
/// exactly as the login path already does for a legacy value.
async fn insert_password_credential(
    db: &dyn Database,
    id_gen: &dyn IdGen,
    user_id: &str,
    hash: &str,
    now: &str,
) -> Result<(), Problem> {
    store::insert_credential(
        db,
        &CredentialRow {
            id: id_gen.ulid(),
            user_id: user_id.to_owned(),
            kind: CREDENTIAL_PASSWORD.to_owned(),
            passkey_credential_id: None,
            passkey_public_key_cose: None,
            passkey_sign_count: None,
            passkey_aaguid: None,
            passkey_transports: None,
            password_hash: Some(Redacted(hash.to_owned())),
            label: None,
            created_at: now.to_owned(),
            last_used_at: None,
            passkey_suspect_at: None,
            failed_attempts: 0,
            failed_window_started_at: None,
            locked_until: None,
        },
    )
    .await?;
    Ok(())
}

/// `^[a-z0-9][a-z0-9_-]{0,31}$`, so the first `:` in the composed
/// `provider_subject` splits the provider from the id unambiguously.
fn valid_provider(provider: &str) -> bool {
    if provider.len() > MAX_PROVIDER_BYTES {
        return false;
    }
    let mut bytes = provider.bytes();
    match bytes.next() {
        Some(byte) if byte.is_ascii_lowercase() || byte.is_ascii_digit() => {}
        _ => return false,
    }
    bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
    })
}

/// Non-empty, at most [`MAX_EXTERNAL_ID_BYTES`] bytes, no control
/// characters. A `:` is fine: only the provider's own characters are
/// restricted, so the split on the first `:` stays unambiguous.
fn valid_external_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_EXTERNAL_ID_BYTES && !id.chars().any(char::is_control)
}

/// The reason a hash may not be stored, or `None` when it may. The order
/// is deliberate: a bcrypt-shaped value is judged as bcrypt (cost, then the
/// deployment's opt-in) and never handed to the argon2 parser.
fn unacceptable_hash(hash: &str, legacy: LegacyHashes) -> Option<&'static str> {
    if let Some(cost) = bcrypt_cost(hash) {
        if cost > BCRYPT_MAX_COST {
            return Some("bcrypt-cost-too-high");
        }
        if !legacy.allows_bcrypt() {
            return Some("legacy-hashes-disabled");
        }
        return None;
    }
    if is_argon2id_phc(hash) {
        return None;
    }
    Some("unsupported-hash")
}

/// Parses an RFC 3339 instant and re-formats it to the store's fixed-width
/// seconds-precision UTC shape, so lexicographic order stays chronological
/// (`crate::store`'s invariant) whatever offset the row carried.
fn canonical_instant(raw: &str) -> Option<String> {
    let parsed = time::OffsetDateTime::parse(raw, &Rfc3339).ok()?;
    // To UTC, not merely reformatted: an offset the source carried would
    // otherwise be written verbatim and sort before or after a `now` that
    // is UTC, breaking the invariant the doc above relies on.
    parsed
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

#[derive(Deserialize)]
struct ByExternalId {
    provider: String,
    external_id: String,
}

/// `GET /admin/users/by-external-id?provider=<p>&external_id=<id>` — the
/// `sub` an import wrote for that pair, or `404`.
async fn by_external_id(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Query(query): Query<ByExternalId>,
) -> Result<Response, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let subject = format!("{}:{}", query.provider, query.external_id);
    match store::identity_by_provider_subject(&*db, PROVIDER_IMPORT, &subject).await? {
        Some(identity) => Ok(Json(json!({ "sub": identity.user_id })).into_response()),
        None => Err(Problem::not_found().instance(&scope.request_id)),
    }
}
