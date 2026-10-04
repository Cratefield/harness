//! Per-organization enterprise SSO connections (issue #627), OIDC first.
//!
//! A connection is one organization's own identity provider: the issuer to
//! send its people to, the client credentials to present there, and the
//! email domains that route a sign-in to it. `auth-oidc` runs the flow;
//! this module owns the rows, and the admin API that writes them.
//!
//! Three rules hold here rather than in the flow:
//!
//! 1. **The admin API authenticates with the venture's own client
//!    credentials**, `Authorization: Basic base64(client_id:client_secret)`
//!    checked through the same argon2 path `/token` uses. There is no
//!    separate admin token: the party who may register an app is the party
//!    who may point it at an `IdP`.
//! 2. **Every query is scoped by the authenticated client id.** Another
//!    client's connection is a 404, and another client's id in a body is
//!    never read, so one venture cannot address another's rows by guessing.
//! 3. **The client secret is stored sealed, never in the clear.** The
//!    column is `oidc_client_secret_sealed`, the AAD binds it to this row
//!    and column, and the key is `AUTH_CORE_SSO_TOKEN_KEY` — not in the
//!    database. The key is needed to seal when a connection is created or
//!    its secret rotated — and, in `auth-oidc`, to open the secret to run
//!    a sign-in; listing or reading a connection never needs it. `Debug`
//!    on the row prints the ciphertext as `[redacted]`.
//!
//! A domain belongs to at most one *active* connection of a client. The
//! rule is enforced where the writes happen (both writes read the other
//! active connections first), not by a database constraint, because the
//! column is a JSON array and the rule is about a subset of rows.

use axum::extract::{Extension, Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{patch, post};
use base64ct::{Base64, Base64Unpadded, Encoding as _};
use cratefield_core::{Clock, Config, Database, Json, ModuleConfig, Problem, ProblemDef, Scope};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::ModuleState;
use crate::secrets;
use crate::store::{self, Redacted, STATUS_ACTIVE, STATUS_DISABLED, SsoConnectionRow};

/// The `identities.provider` value an SSO sign-in writes, and the flow
/// segment `auth-oidc` serves it under.
pub const SSO_PROVIDER: &str = "sso";

/// The table these rows live in. Named because the sealing AAD and the
/// schema guard both pin the exact string.
pub(crate) const TABLE: &str = "sso_connections";

/// The sealing namespace. Domain separation is the whole reason each
/// module has its own: an auth-core blob must not open as a connections
/// blob even if the two ever shared a key.
const NAMESPACE: &str = "auth-core";

/// The sealed secret's column name, spelled once. It is the last element
/// of the AAD, so a ciphertext cannot be moved into another column.
const SECRET_COLUMN: &str = "oidc_client_secret_sealed";

/// The three ports every admin handler needs: the rows, the clock and an
/// id generator. Named because a three-element tuple of trait objects
/// written out at each signature is a mouthful.
type Ports = (
    Arc<dyn Database>,
    Arc<dyn Clock>,
    Arc<dyn cratefield_core::IdGen>,
);

/// The admin API was called without usable client credentials.
pub const SSO_UNAUTHORIZED: ProblemDef = ProblemDef {
    slug: "auth/sso-unauthorized",
    status: StatusCode::UNAUTHORIZED,
    title: "That SSO request is not authorized",
    description: "The admin API takes HTTP Basic with a confidential client's id and secret",
};

/// A requested domain is already routed to another active connection of
/// the same client.
pub const SSO_DOMAIN_CLAIMED: ProblemDef = ProblemDef {
    slug: "auth/sso-domain-claimed",
    status: StatusCode::CONFLICT,
    title: "That email domain is already in use",
    description: "An email domain routes to at most one active SSO connection per client",
};

/// The sealing key is not configured, so a client secret cannot be sealed
/// when a connection is created or its secret rotated, nor opened to run a
/// sign-in (`auth-oidc` opens it at `/start` and the callback). Listing and
/// reading a connection never needs it. A deployment mistake, not a
/// caller's problem.
pub const SSO_UNCONFIGURED: ProblemDef = ProblemDef {
    slug: "auth/sso-unconfigured",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "SSO connections are not configured on this deployment",
    description: "AUTH_CORE_SSO_TOKEN_KEY is missing or unusable",
};

/// Why a secret could not be sealed or opened. The message names the
/// setting, never a value.
#[derive(Debug, thiserror::Error)]
pub enum SsoSecretError {
    #[error("{0}")]
    Unconfigured(String),
    #[error("the sealed client secret could not be read")]
    Seal,
}

// ---------------------------------------------------------------------------
// sealing

fn seal_key(cfg: &dyn Config) -> Result<cratefield_oauth_client::XChaChaSealer, SsoSecretError> {
    let module = ModuleConfig::new("auth-core", cfg);
    let key_name = module.key("SSO_TOKEN_KEY");
    let encoded = module
        .get_opt("SSO_TOKEN_KEY")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| SsoSecretError::Unconfigured(format!("{key_name} is not configured")))?;
    let id = module
        .get_opt("SSO_TOKEN_KEY_ID")
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(1);
    cratefield_oauth_client::XChaChaSealer::from_base64_key(&encoded, id)
        .map_err(|_| SsoSecretError::Unconfigured(format!("{key_name} is not 32 bytes of base64")))
}

fn context<'a>(row_id: &'a str, column: &'a str) -> cratefield_oauth_client::SealContext<'a> {
    cratefield_oauth_client::SealContext {
        namespace: NAMESPACE,
        table: TABLE,
        row_id,
        column,
    }
}

/// Seals a connection's client secret for the row that is about to hold
/// it. `row_id` must be the id the row is written with, or the ciphertext
/// opens nowhere.
pub(crate) fn seal_client_secret(
    cfg: &dyn Config,
    row_id: &str,
    plaintext: &str,
) -> Result<String, SsoSecretError> {
    use cratefield_oauth_client::TokenSealer as _;
    let sealer = seal_key(cfg)?;
    sealer
        .seal(plaintext, &context(row_id, SECRET_COLUMN))
        .map_err(|_| SsoSecretError::Seal)
}

/// Opens the client secret of a stored connection, for the length of the
/// token exchange. The plaintext is zeroized when the returned guard
/// drops.
///
/// # Errors
///
/// [`SsoSecretError::Unconfigured`] when the key is missing or wrong;
/// [`SsoSecretError::Seal`] when the blob does not authenticate, which
/// means the key, the row or the column is not the one it was sealed
/// under.
pub fn open_client_secret(
    cfg: &dyn Config,
    connection: &SsoConnectionRow,
) -> Result<Zeroizing<String>, SsoSecretError> {
    use cratefield_oauth_client::TokenSealer as _;
    let sealer = seal_key(cfg)?;
    sealer
        .open(
            &connection.oidc_client_secret_sealed.0,
            &context(&connection.id, SECRET_COLUMN),
        )
        .map_err(|_| SsoSecretError::Seal)
}

// ---------------------------------------------------------------------------
// domains

/// Lowercases and trims a domain, stripping the trailing dot of a fully
/// qualified name. Comparison is exact on the result.
#[must_use]
pub fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether a normalized domain is syntactically plausible: dot-separated
/// labels of letters, digits and hyphens, no empty label, no label
/// starting or ending with a hyphen, at least one dot.
///
/// Deliberately not a full IDN check: the value is only ever compared
/// for equality against the domain half of an address. The dot rule keeps
/// a single-label value such as `com` — which would route every address
/// at that suffix — out.
#[must_use]
pub fn valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// The domain half of an email address, normalized, or `None` when there
/// is no `@` or nothing follows it.
#[must_use]
pub fn domain_of_email(email: &str) -> Option<String> {
    let (_, domain) = email.rsplit_once('@')?;
    let domain = normalize_domain(domain);
    (!domain.is_empty()).then_some(domain)
}

/// The domains of `candidate` that another connection of the same client
/// already routes. `exclude` is the connection being written, so a patch
/// does not collide with itself. The returned slices borrow `candidate`.
fn claimed_domains<'a>(
    existing: &[SsoConnectionRow],
    candidate: &'a [String],
    exclude: Option<&str>,
) -> Vec<&'a str> {
    let claimed: Vec<&str> = existing
        .iter()
        .filter(|row| row.status == STATUS_ACTIVE && Some(row.id.as_str()) != exclude)
        .flat_map(|row| row.domains.iter())
        .map(String::as_str)
        .collect();
    candidate
        .iter()
        .filter(|domain| claimed.contains(&domain.as_str()))
        .map(String::as_str)
        .collect()
}

// ---------------------------------------------------------------------------
// admin authentication

/// The authenticated client, put in the request extensions by
/// [`client_guard`]. A handler that does not take it is a handler that
/// never authenticated — so it is taken everywhere.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedClient(pub String);

/// HTTP Basic with the venture's own client credentials, checked before
/// any body is parsed. A missing header, a malformed one, an unknown
/// client, a wrong secret and a disabled client are all the same 401.
pub(crate) async fn client_guard(
    State(state): State<Arc<ModuleState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let scope = request.extensions().get::<Scope>().cloned();
    let unauthorized = || {
        let problem = Problem::new(&SSO_UNAUTHORIZED);
        let problem = match scope.as_ref() {
            Some(scope) => problem.instance(&scope.request_id),
            None => problem,
        };
        let mut response = problem.into_response();
        // RFC 7617: a 401 on a Basic-protected resource carries the
        // challenge, or the client has nothing to answer with.
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Basic realm=\"sso\", charset=\"UTF-8\""),
        );
        response
    };

    let Some(db) = state.ctx.ports.db.clone() else {
        return Problem::internal().into_response();
    };
    let Some(clock) = state.ctx.ports.clock.clone() else {
        return Problem::internal().into_response();
    };
    let Some((client_id, presented)) = basic_credentials(request.headers()) else {
        return unauthorized();
    };
    let Some(client) = store::client_by_id(&*db, &client_id).await.ok().flatten() else {
        return unauthorized();
    };
    if !secrets::kind_allows_secret(&client.kind) {
        // A public client has no secret to present, so it can never
        // authenticate here. Same answer as a wrong one.
        return unauthorized();
    }
    let now = crate::clients::now_iso(&*clock);
    if !secrets::verify_client_secret(&client, &presented, &now) {
        return unauthorized();
    }
    if secrets::ensure_client_usable(&client).is_err() {
        return unauthorized();
    }

    request
        .extensions_mut()
        .insert(AuthenticatedClient(client.id));
    next.run(request).await
}

/// The client id and secret of an `Authorization: Basic` header, decoded.
/// The value is `base64(client_id:client_secret)`; the split is on the
/// first `:`, which is safe because neither a generated client id nor a
/// generated secret contains one.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    // The scheme is case-insensitive (RFC 9110 §11.1): `Basic`, `basic`
    // and `BASIC` all name the same one.
    let (scheme, encoded) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let encoded = encoded.trim();
    let decoded = Base64::decode_vec(encoded)
        .or_else(|_| Base64Unpadded::decode_vec(encoded))
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, secret) = decoded.split_once(':')?;
    (!client_id.is_empty()).then(|| (client_id.to_owned(), secret.to_owned()))
}

// ---------------------------------------------------------------------------
// routes

pub(crate) fn router(state: Arc<ModuleState>) -> axum::Router {
    axum::Router::new()
        .route("/sso/connections", post(create).get(list))
        .route(
            "/sso/connections/{id}",
            patch(patch_connection).get(get_one),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            client_guard,
        ))
        .with_state(state)
}

const MAX_ORG_REF_BYTES: usize = 128;
const MAX_ISSUER_BYTES: usize = 512;
const MAX_OIDC_CLIENT_ID_BYTES: usize = 512;
const MAX_SECRET_BYTES: usize = 1024;
const MAX_DOMAINS: usize = 64;

fn internal() -> Problem {
    Problem::internal()
}

fn audit(action: &str, id: &str) {
    tracing::info!(
        audit = true,
        action,
        sso_connection = id,
        "auth-core sso connection"
    );
}

/// The admin-visible shape of a connection. Never the secret, and never
/// the sealed form of it either: the sealed blob is a capability to be
/// opened, and the admin who wrote it does not need to read it back.
fn view(connection: &SsoConnectionRow) -> Value {
    json!({
        "id": connection.id,
        "org_ref": connection.org_ref,
        "issuer": connection.issuer,
        "oidc_client_id": connection.oidc_client_id,
        "domains": connection.domains,
        "status": connection.status,
        "created_at": connection.created_at,
        "updated_at": connection.updated_at,
    })
}

/// The issuer, normalized: trimmed, no trailing slash, `https` — or
/// `http` on localhost, which is how a developer runs an `IdP` against
/// `wrangler dev` (the same allowance `AUTH_OIDC_REDIRECT_BASE` makes).
fn validate_issuer(raw: &str) -> Result<String, Problem> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed.len() > MAX_ISSUER_BYTES {
        return Err(Problem::validation_failed("issuer must be 1..=512 bytes"));
    }
    let Ok(url) = url::Url::parse(trimmed) else {
        return Err(Problem::validation_failed("issuer must be a URL"));
    };
    let host = url.host_str().unwrap_or_default();
    let localhost = host == "localhost" || host == "127.0.0.1" || host == "[::1]";
    let ok = url.scheme() == "https" || (url.scheme() == "http" && localhost);
    if !ok {
        return Err(Problem::validation_failed(
            "issuer must be https (localhost may be http)",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Problem::validation_failed(
            "issuer must not carry a query or fragment",
        ));
    }
    Ok(trimmed.to_owned())
}

fn validate_domains(
    raw: &[String],
    exclude: Option<&str>,
    existing: &[SsoConnectionRow],
) -> Result<Vec<String>, Problem> {
    if raw.is_empty() {
        return Err(Problem::validation_failed("domains must not be empty"));
    }
    if raw.len() > MAX_DOMAINS {
        return Err(Problem::validation_failed(format!(
            "at most {MAX_DOMAINS} domains per connection"
        )));
    }
    let mut domains: Vec<String> = Vec::with_capacity(raw.len());
    for candidate in raw {
        let domain = normalize_domain(candidate);
        if !valid_domain(&domain) {
            return Err(Problem::validation_failed(format!(
                "`{domain}` is not a plausible email domain"
            )));
        }
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    let claimed = claimed_domains(existing, &domains, exclude);
    if !claimed.is_empty() {
        return Err(Problem::new(&SSO_DOMAIN_CLAIMED).with_detail(format!(
            "already routed to another active connection: {}",
            claimed.join(", ")
        )));
    }
    Ok(domains)
}

fn ports(state: &ModuleState) -> Option<Ports> {
    Some((
        state.ctx.ports.db.clone()?,
        state.ctx.ports.clock.clone()?,
        state.ctx.ports.id_gen.clone()?,
    ))
}

#[derive(Deserialize)]
struct CreateBody {
    org_ref: String,
    issuer: String,
    oidc_client_id: String,
    oidc_client_secret: String,
    domains: Vec<String>,
}

async fn create(
    scope: Scope,
    Extension(client): Extension<AuthenticatedClient>,
    State(state): State<Arc<ModuleState>>,
    Json(body): Json<CreateBody>,
) -> Result<Response, Problem> {
    let org_ref = body.org_ref.trim();
    if org_ref.is_empty() || org_ref.len() > MAX_ORG_REF_BYTES {
        return Err(internal_validation(
            &scope,
            format!("org_ref must be 1..={MAX_ORG_REF_BYTES} bytes"),
        ));
    }
    let issuer = validate_issuer(&body.issuer).map_err(|p| p.instance(&scope.request_id))?;
    let oidc_client_id = body.oidc_client_id.trim();
    if oidc_client_id.is_empty() || oidc_client_id.len() > MAX_OIDC_CLIENT_ID_BYTES {
        return Err(internal_validation(
            &scope,
            "oidc_client_id must be 1..=512 bytes",
        ));
    }
    if body.oidc_client_secret.is_empty() || body.oidc_client_secret.len() > MAX_SECRET_BYTES {
        return Err(internal_validation(
            &scope,
            "oidc_client_secret must be 1..=1024 bytes",
        ));
    }
    let Some((db, clock, id_gen)) = ports(&state) else {
        return Err(internal().instance(&scope.request_id));
    };
    let existing = store::sso_connections_for_client(&*db, &client.0, None).await?;
    let domains = validate_domains(&body.domains, None, &existing)
        .map_err(|p| p.instance(&scope.request_id))?;

    let id = format!("ssoc_{}", id_gen.ulid());
    let sealed = seal_client_secret(&*state.ctx.config, &id, &body.oidc_client_secret)
        .map_err(|err| match err {
            SsoSecretError::Unconfigured(message) => {
                tracing::error!(error = %message, "the seal key is unusable");
                Problem::new(&SSO_UNCONFIGURED)
            }
            SsoSecretError::Seal => internal(),
        })
        .map_err(|p| p.instance(&scope.request_id))?;
    let now = crate::clients::now_iso(&*clock);

    store::insert_sso_connection(
        &*db,
        &SsoConnectionRow {
            id: id.clone(),
            client_id: client.0.clone(),
            org_ref: org_ref.to_owned(),
            issuer,
            oidc_client_id: oidc_client_id.to_owned(),
            oidc_client_secret_sealed: Redacted(sealed),
            domains: domains.clone(),
            status: STATUS_ACTIVE.to_owned(),
            created_at: now.clone(),
            updated_at: now,
        },
    )
    .await?;

    audit("sso.connection.create", &id);
    let row = store::sso_connection_by_id(&*db, &id)
        .await?
        .ok_or_else(internal)?;
    Ok((StatusCode::CREATED, Json(view(&row))).into_response())
}

fn internal_validation(scope: &Scope, detail: impl Into<String>) -> Problem {
    Problem::validation_failed(detail).instance(&scope.request_id)
}

#[derive(Deserialize)]
struct ListQuery {
    org_ref: Option<String>,
}

async fn list(
    scope: Scope,
    Extension(client): Extension<AuthenticatedClient>,
    State(state): State<Arc<ModuleState>>,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
) -> Result<Response, Problem> {
    let Some((db, _clock, _id_gen)) = ports(&state) else {
        return Err(internal().instance(&scope.request_id));
    };
    // Trim like create does, and treat a blank filter as absent so
    // `?org_ref=` lists everything rather than matching nothing.
    let org_ref = query
        .org_ref
        .as_deref()
        .map(str::trim)
        .filter(|org_ref| !org_ref.is_empty());
    let rows = store::sso_connections_for_client(&*db, &client.0, org_ref).await?;
    audit("sso.connection.list", &client.0);
    Ok(Json(Value::Array(rows.iter().map(view).collect())).into_response())
}

/// One connection of *this* client. A connection of another client, and
/// one that does not exist, are both a plain 404.
async fn owned(
    db: &dyn Database,
    client_id: &str,
    id: &str,
) -> Result<Option<SsoConnectionRow>, Problem> {
    Ok(store::sso_connection_by_id(db, id)
        .await?
        .filter(|row| row.client_id == client_id))
}

async fn get_one(
    scope: Scope,
    Extension(client): Extension<AuthenticatedClient>,
    State(state): State<Arc<ModuleState>>,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let Some((db, _clock, _id_gen)) = ports(&state) else {
        return Err(internal().instance(&scope.request_id));
    };
    let Some(row) = owned(&*db, &client.0, &id).await? else {
        return Err(Problem::not_found().instance(&scope.request_id));
    };
    audit("sso.connection.get", &id);
    Ok(Json(view(&row)).into_response())
}

#[derive(Deserialize)]
struct PatchBody {
    status: Option<String>,
    oidc_client_secret: Option<String>,
    domains: Option<Vec<String>>,
}

async fn patch_connection(
    scope: Scope,
    Extension(client): Extension<AuthenticatedClient>,
    State(state): State<Arc<ModuleState>>,
    Path(id): Path<String>,
    Json(body): Json<PatchBody>,
) -> Result<Response, Problem> {
    if body.status.is_none() && body.oidc_client_secret.is_none() && body.domains.is_none() {
        return Err(internal_validation(
            &scope,
            "nothing to change: status, oidc_client_secret or domains",
        ));
    }
    if let Some(status) = &body.status
        && !matches!(status.as_str(), STATUS_ACTIVE | STATUS_DISABLED)
    {
        return Err(internal_validation(
            &scope,
            format!("status must be `{STATUS_ACTIVE}` or `{STATUS_DISABLED}`"),
        ));
    }
    if let Some(secret) = &body.oidc_client_secret
        && (secret.is_empty() || secret.len() > MAX_SECRET_BYTES)
    {
        return Err(internal_validation(
            &scope,
            "oidc_client_secret must be 1..=1024 bytes",
        ));
    }
    let Some((db, clock, _id_gen)) = ports(&state) else {
        return Err(internal().instance(&scope.request_id));
    };
    // Another client's connection, and one that does not exist, are the
    // same 404 — before any domain or secret is looked at.
    if owned(&*db, &client.0, &id).await?.is_none() {
        return Err(Problem::not_found().instance(&scope.request_id));
    }

    let domains = match &body.domains {
        Some(raw) => {
            let existing = store::sso_connections_for_client(&*db, &client.0, None).await?;
            Some(
                validate_domains(raw, Some(&id), &existing)
                    .map_err(|p| p.instance(&scope.request_id))?,
            )
        }
        None => None,
    };
    let sealed = match &body.oidc_client_secret {
        Some(secret) => Some(
            seal_client_secret(&*state.ctx.config, &id, secret)
                .map_err(|err| match err {
                    SsoSecretError::Unconfigured(message) => {
                        tracing::error!(error = %message, "the seal key is unusable");
                        Problem::new(&SSO_UNCONFIGURED)
                    }
                    SsoSecretError::Seal => internal(),
                })
                .map_err(|p| p.instance(&scope.request_id))?,
        ),
        None => None,
    };
    let domains_json = domains
        .as_ref()
        .map(|domains| serde_json::to_string(domains).unwrap_or_else(|_| "[]".to_owned()));

    let landed = store::update_sso_connection(
        &*db,
        &id,
        body.status.as_deref(),
        sealed.as_deref(),
        domains_json.as_deref(),
        &crate::clients::now_iso(&*clock),
    )
    .await?;
    if landed == 0 {
        return Err(Problem::not_found().instance(&scope.request_id));
    }

    audit("sso.connection.patch", &id);
    match store::sso_connection_by_id(&*db, &id).await? {
        Some(row) => Ok(Json(view(&row)).into_response()),
        None => Err(internal().instance(&scope.request_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_normalized_and_validated() {
        assert_eq!(normalize_domain("  Acme.Example.  "), "acme.example");
        for good in ["acme.example", "a-b.example.co.uk", "x1.y2.example"] {
            assert!(valid_domain(good), "{good} should be accepted");
        }
        // A single label would route every address at that suffix, and the
        // rest are malformed.
        for bad in [
            "",
            "com",
            ".example",
            "example.",
            "exa mple.com",
            "-x.example",
            "x-.example",
            "ex_ample.com",
        ] {
            assert!(!valid_domain(bad), "{bad} should be refused");
        }
        assert_eq!(
            domain_of_email("nick@ACME.example").as_deref(),
            Some("acme.example")
        );
        assert_eq!(domain_of_email("nick").as_deref(), None);
        assert_eq!(domain_of_email("nick@").as_deref(), None);
    }

    #[test]
    fn an_issuer_must_be_https_outside_localhost() {
        assert_eq!(
            validate_issuer("https://idp.acme.example/").expect("valid"),
            "https://idp.acme.example"
        );
        assert!(validate_issuer("http://localhost:8080").is_ok());
        assert!(validate_issuer("http://idp.acme.example").is_err());
        assert!(validate_issuer("not a url").is_err());
        assert!(validate_issuer("").is_err());
        assert!(validate_issuer("https://idp.example/?x=1").is_err());
    }

    #[test]
    fn basic_credentials_split_on_the_first_colon() {
        let mut headers = HeaderMap::new();
        let encoded = Base64::encode_string(b"client-1:s3cret:with:colons");
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Basic {encoded}")).expect("header"),
        );
        let (id, secret) = basic_credentials(&headers).expect("decodes");
        assert_eq!(id, "client-1");
        assert_eq!(secret, "s3cret:with:colons");

        assert!(basic_credentials(&HeaderMap::new()).is_none());
        let mut bearer = HeaderMap::new();
        bearer.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer abc"),
        );
        assert!(basic_credentials(&bearer).is_none());
    }

    #[test]
    fn a_domain_already_routed_by_another_active_connection_is_claimed() {
        let row = |id: &str, status: &str, domains: &[&str]| SsoConnectionRow {
            id: id.to_owned(),
            client_id: "c1".to_owned(),
            org_ref: "acme".to_owned(),
            issuer: "https://idp.example".to_owned(),
            oidc_client_id: "id".to_owned(),
            oidc_client_secret_sealed: Redacted("sealed".to_owned()),
            domains: domains.iter().map(|d| (*d).to_owned()).collect(),
            status: status.to_owned(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        let existing = vec![
            row("a", STATUS_ACTIVE, &["acme.example"]),
            row("b", STATUS_DISABLED, &["old.example"]),
        ];
        let candidate = vec!["acme.example".to_owned(), "new.example".to_owned()];
        assert_eq!(
            claimed_domains(&existing, &candidate, None),
            ["acme.example"]
        );
        // The connection being written does not claim against itself.
        assert!(claimed_domains(&existing, &candidate, Some("a")).is_empty());
        // A disabled connection's domains are free.
        assert!(claimed_domains(&existing, &["old.example".to_owned()], None).is_empty());
    }

    #[test]
    fn the_row_debug_never_prints_the_sealed_secret() {
        let row = SsoConnectionRow {
            id: "ssoc_1".to_owned(),
            client_id: "c1".to_owned(),
            org_ref: "acme".to_owned(),
            issuer: "https://idp.example".to_owned(),
            oidc_client_id: "id".to_owned(),
            oidc_client_secret_sealed: Redacted("super-secret-blob".to_owned()),
            domains: vec!["acme.example".to_owned()],
            status: STATUS_ACTIVE.to_owned(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        let printed = format!("{row:?}");
        assert!(!printed.contains("super-secret-blob"), "{printed}");
        assert!(printed.contains("Redacted"), "{printed}");
    }
}
