//! The module's routes, mounted at `/v1/orgs` (issue #652).
//!
//! Every route but the admin listing takes an authenticated caller, through the
//! [`Auth`](cratefield_core::Auth) port: a module has no ambient request, and a
//! subject id read from anywhere else would be a claim the caller made about
//! themselves. The routes do the two things a route should — read the caller,
//! then hand the domain rules their arguments — and `problem_for` turns a
//! failure into the RFC 9457 body, with one deliberate silence: a caller who is
//! not a member of an organization gets the same 404 as a caller asking about
//! one that does not exist, so the ids cannot be enumerated.

use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use cratefield_core::{
    Action, Audience, Auth, AuthError, Caller, Config, ConfigError, ModuleConfig, ModuleContext,
    Outcome, Problem, ProblemDef, RoutePolicy, SLUGS, Scope, Surface,
};

use crate::OrgsError;
use crate::service;

/// No organization carries that id, or the caller is not a member of the one it
/// does name. The two are one answer on purpose.
pub(crate) const NOT_FOUND: ProblemDef = ProblemDef {
    slug: "orgs-not-found",
    status: StatusCode::NOT_FOUND,
    title: "No such organization",
    description: "No organization the caller is a member of carries that id. An organization \
                  the caller is not in answers the same way, so its existence is not disclosed.",
};

/// The caller is a member, but their role may not do this.
pub(crate) const FORBIDDEN: ProblemDef = ProblemDef {
    slug: "orgs-forbidden",
    status: StatusCode::FORBIDDEN,
    title: "Your role does not allow this",
    description: "The caller's role in this organization does not permit the change they \
                  asked for — only owners, and the manager roles the venture named, may \
                  manage members and invitations, and only an owner may grant or change the \
                  owner role.",
};

/// The role is not one this venture configured.
pub(crate) const UNKNOWN_ROLE: ProblemDef = ProblemDef {
    slug: "orgs-unknown-role",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    title: "Unknown role",
    description: "The role is not one of the roles this venture configured for its \
                  organizations. The configured set is fixed at build.",
};

/// The organization's name was missing or blank.
pub(crate) const INVALID_NAME: ProblemDef = ProblemDef {
    slug: "orgs-invalid-name",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    title: "An organization needs a name",
    description: "The name was empty or whitespace only.",
};

/// The address to invite was not an address.
pub(crate) const INVALID_EMAIL: ProblemDef = ProblemDef {
    slug: "orgs-invalid-email",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    title: "That is not an email address",
    description: "The address to invite could not be normalized and validated as one.",
};

/// The change would leave the organization with no owner.
pub(crate) const LAST_OWNER: ProblemDef = ProblemDef {
    slug: "orgs-last-owner",
    status: StatusCode::CONFLICT,
    title: "An organization keeps an owner",
    description: "This is the organization's only owner, so it cannot be removed or demoted. \
                  Grant the owner role to somebody else first.",
};

/// The person is already a member.
pub(crate) const ALREADY_MEMBER: ProblemDef = ProblemDef {
    slug: "orgs-already-member",
    status: StatusCode::CONFLICT,
    title: "Already a member",
    description: "That account already belongs to this organization.",
};

/// The invitation is unknown, expired or already accepted.
pub(crate) const INVITATION_GONE: ProblemDef = ProblemDef {
    slug: "orgs-invitation-gone",
    status: StatusCode::GONE,
    title: "That invitation is no longer valid",
    description: "The invitation token is unknown, has lapsed, or has already been accepted. \
                  An invitation is single-use, so a second acceptance is refused.",
};

/// The invitation was issued to a different address.
pub(crate) const INVITATION_FOR_SOMEONE_ELSE: ProblemDef = ProblemDef {
    slug: "orgs-invitation-for-someone-else",
    status: StatusCode::FORBIDDEN,
    title: "That invitation is for another address",
    description: "The signed-in account's verified address is not the one the invitation was \
                  sent to. The invitation has not been spent.",
};

/// Nothing proved the caller's address, so an invitation cannot be matched to it.
pub(crate) const EMAIL_UNVERIFIED: ProblemDef = ProblemDef {
    slug: "orgs-email-unverified",
    status: StatusCode::FORBIDDEN,
    title: "Your email address is not verified",
    description: "Accepting an invitation matches the caller's verified address against the \
                  one invited, and the credential this request carried proved none.",
};

/// The mail provider refused the invitation.
pub(crate) const MAIL_FAILED: ProblemDef = ProblemDef {
    slug: "orgs-mail-failed",
    status: StatusCode::BAD_GATEWAY,
    title: "The invitation could not be sent",
    description: "The mailing provider refused the invitation message, so no invitation was \
                  created. Nothing is left behind to accept; try again.",
};

/// The builder's settings, cloned into the router state and every API handle.
/// Nothing here reads the environment; `validate` reads the two keys that can
/// override a default.
#[derive(Clone)]
pub(crate) struct Settings {
    /// Every role an organization may use. `owner` is always in it.
    pub roles: Vec<String>,
    /// The non-owner roles that may manage members and invitations.
    pub managers: Vec<String>,
    /// The venture's staff organization, when the builder named one.
    pub staff_org: String,
    /// The roles in the staff organization that may see the admin listing.
    pub staff_roles: Vec<String>,
    /// How long an invitation stays acceptable.
    pub invitation_ttl_secs: i64,
}

impl Settings {
    /// The staff organization as this deployment resolves it: `ORGS_STAFF_ORG`
    /// when set, so a venture can point at a different organization without a
    /// rebuild, else the builder's.
    pub(crate) fn staff_org(&self, cfg: &dyn Config) -> String {
        ModuleConfig::new(crate::MODULE_NAME, cfg)
            .get_opt("STAFF_ORG")
            .unwrap_or_else(|| self.staff_org.clone())
    }
}

/// Maps a domain failure to the problem a route answers with.
pub(crate) fn problem_for(error: &OrgsError) -> Problem {
    match error {
        OrgsError::Db(_) | OrgsError::Config(_) => {
            tracing::error!(error = %error, "an orgs entry point failed");
            Problem::internal()
        }
        OrgsError::Mail(_) => {
            tracing::error!(error = %error, "an invitation message was refused");
            Problem::new(&MAIL_FAILED)
        }
        OrgsError::MailNotConfigured => Problem::new(&SLUGS.mail_not_configured),
        OrgsError::NotFound(_) => Problem::new(&NOT_FOUND),
        OrgsError::Forbidden(detail) => Problem::new(&FORBIDDEN).with_detail(detail.clone()),
        OrgsError::UnknownRole(role) => {
            Problem::new(&UNKNOWN_ROLE).with_detail(format!("`{role}` is not a configured role"))
        }
        OrgsError::InvalidName => Problem::new(&INVALID_NAME),
        OrgsError::InvalidEmail(_) => Problem::new(&INVALID_EMAIL),
        OrgsError::TooLong { field, max } => {
            Problem::validation_failed(format!("`{field}` must be at most {max} characters"))
        }
        OrgsError::LastOwner => Problem::new(&LAST_OWNER),
        OrgsError::AlreadyMember(_) => Problem::new(&ALREADY_MEMBER),
        OrgsError::InvitationGone => Problem::new(&INVITATION_GONE),
        OrgsError::InvitationForSomeoneElse => Problem::new(&INVITATION_FOR_SOMEONE_ELSE),
        OrgsError::EmailUnverified => Problem::new(&EMAIL_UNVERIFIED),
    }
}

/// A failure as the response body, carrying the request's id.
fn fail(scope: &Scope, error: &OrgsError) -> Problem {
    problem_for(error).instance(&scope.request_id)
}

// ---------------------------------------------------------------------------
// State and the caller

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
    /// The verifier, cloned out of the context so the extractor can reach it
    /// without holding the whole `ModuleContext`. Required by `requires()`, so
    /// a deployment that cannot identify a caller refuses to boot rather than
    /// serving these routes to everybody.
    pub auth: Option<Arc<dyn Auth>>,
}

/// The calling account.
///
/// It exists so no handler can read a subject id from anywhere else: the only
/// way to obtain one is to present a credential the venture's verifier accepts.
/// `email` is present only when the credential carried a **verified** address,
/// which is exactly the guarantee the invitation accept path needs — an
/// unverified address is a string the caller typed.
pub(crate) struct Account {
    pub sub: String,
    pub email: Option<String>,
}

impl FromRequestParts<Arc<ModuleState>> for Account {
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ModuleState>,
    ) -> Result<Self, Self::Rejection> {
        let Some(auth) = state.auth.clone() else {
            tracing::error!(
                "orgs: no Auth port is mounted; every route answers 401 until a deployment \
                 provides a token verifier"
            );
            return Err(Problem::new(&SLUGS.unauthenticated));
        };
        match auth.identify(&parts.headers).await {
            Ok(Caller::Subject(subject)) => Ok(Account {
                sub: subject.id,
                email: subject.email,
            }),
            // No credential at all, or one that did not verify: both are a
            // caller this route has not identified.
            Ok(Caller::Anonymous) | Err(AuthError::NotVerified) => {
                Err(Problem::new(&SLUGS.unauthenticated))
            }
            // The verifier could not answer. That is the deployment's problem,
            // not the caller's, and it is not a 401 — a 401 would tell a
            // signed-in person to sign in again.
            Err(AuthError::Unavailable(_)) => Err(Problem::internal()),
            // `Caller` and `AuthError` are `non_exhaustive`: a variant core
            // adds after this module was built is, until this module says what
            // it means, a caller that was not identified.
            Ok(_) | Err(_) => Err(Problem::new(&SLUGS.unauthenticated)),
        }
    }
}

// ---------------------------------------------------------------------------
// Routes

/// The module's routes, mounted at `/v1/orgs`.
pub(crate) fn router(ctx: Arc<ModuleContext>, settings: Settings) -> Router {
    let auth = ctx.ports.auth.clone();
    let state = Arc::new(ModuleState {
        ctx,
        settings,
        auth,
    });
    Router::new()
        .route("/", post(create_org).get(list_orgs))
        .route("/invitations/accept", post(accept_invitation))
        .route("/admin/orgs", get(admin_orgs))
        .route("/{org_id}", get(get_org))
        .route("/{org_id}/members", get(list_members).post(add_member))
        .route("/{org_id}/members/me", get(my_membership))
        .route(
            "/{org_id}/members/{sub}",
            patch(set_role).delete(remove_member),
        )
        .route("/{org_id}/leave", post(leave))
        .route("/{org_id}/invitations", post(invite))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Paging

/// The rows a listing hands back unless the caller asks for fewer, and the
/// ceiling a caller cannot raise. The same default and cap the notifications
/// inbox uses, so a client's paging code is the same shape everywhere.
const PAGE_DEFAULT: u64 = 20;
const PAGE_MAX: u64 = 100;

/// Splits the two halves of a keyset cursor — `created_at~tie-break`. `~` is
/// unreserved in a query string, so the cursor survives a round trip bare.
const CURSOR_SEPARATOR: char = '~';

/// The `cursor` and `limit` a listing route takes. `limit` is clamped rather
/// than rejected: a caller asking for more than the ceiling gets the ceiling.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u64>,
}

impl ListQuery {
    /// This page's size, clamped to the ceiling.
    fn page_size(&self) -> u64 {
        self.limit.unwrap_or(PAGE_DEFAULT).clamp(1, PAGE_MAX)
    }

    /// The `(created_at, tie-break)` a page starts after, from
    /// `<created_at>~<tie-break>`. A malformed cursor names nothing, so the
    /// page starts at the beginning rather than failing: paging is best
    /// effort, and the first page is always right.
    fn after(&self) -> Option<(&str, &str)> {
        self.cursor
            .as_deref()
            .and_then(|raw| raw.split_once(CURSOR_SEPARATOR))
            .filter(|(at, tie)| !at.is_empty() && !tie.is_empty())
    }
}

/// The next page's cursor when this page was full, else `None`. The row that
/// ends the page is the one a following page starts after; `created_at` alone
/// is not unique (two organizations made in one second), so `ends_at` also
/// names the tie-break column — `id` for organizations, `user_sub` for
/// members — and the pair never skips or repeats a row.
fn page_cursor<T>(items: &[T], limit: u64, ends_at: impl Fn(&T) -> (&str, &str)) -> Option<String> {
    if items.len() as u64 != limit {
        return None;
    }
    items.last().map(|item| {
        let (at, tie) = ends_at(item);
        format!("{at}{CURSOR_SEPARATOR}{tie}")
    })
}

// ---------------------------------------------------------------------------
// Bodies

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateOrgBody {
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddMemberBody {
    /// The subject id of the account to add.
    pub sub: String,
    /// The role to give them, from the venture's configured set.
    pub role: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoleBody {
    pub role: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InviteBody {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptBody {
    /// The token from the invitation mail. It is single-use.
    pub token: String,
}

// ---------------------------------------------------------------------------
// Handlers

/// `POST /v1/orgs` — create an organization; the caller becomes its owner.
async fn create_org(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    account: Account,
    Json(body): Json<CreateOrgBody>,
) -> Result<Response, Problem> {
    let org = service::create(&state.ctx, &account.sub, &body.name)
        .await
        .map_err(|error| fail(&scope, &error))?;
    Ok((StatusCode::CREATED, Json(org)).into_response())
}

/// `GET /v1/orgs` — the organizations the caller belongs to, newest page of a
/// keyset walk: the `cursor` in the body is where the next page starts, and is
/// `null` on the last one.
async fn list_orgs(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    account: Account,
    Query(query): Query<ListQuery>,
) -> Result<Response, Problem> {
    let limit = query.page_size();
    let orgs = service::list(&state.ctx, &account.sub, query.after(), limit)
        .await
        .map_err(|error| fail(&scope, &error))?;
    let cursor = page_cursor(&orgs, limit, |entry| (&entry.org.created_at, &entry.org.id));
    Ok(Json(json!({ "orgs": orgs, "cursor": cursor })).into_response())
}

/// `GET /v1/orgs/{org_id}` — one organization, for a member.
async fn get_org(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(org_id): Path<String>,
    account: Account,
) -> Result<Response, Problem> {
    let (org, member) = service::get(&state.ctx, &org_id, &account.sub)
        .await
        .map_err(|error| fail(&scope, &error))?;
    Ok(Json(json!({ "org": org, "role": member.role })).into_response())
}

/// `GET /v1/orgs/{org_id}/members` — the roster, for a member, paged the same
/// way the listing is.
async fn list_members(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(org_id): Path<String>,
    account: Account,
    Query(query): Query<ListQuery>,
) -> Result<Response, Problem> {
    let limit = query.page_size();
    let members = service::members(&state.ctx, &org_id, &account.sub, query.after(), limit)
        .await
        .map_err(|error| fail(&scope, &error))?;
    let cursor = page_cursor(&members, limit, |member| (&member.joined_at, &member.sub));
    Ok(Json(json!({ "members": members, "cursor": cursor })).into_response())
}

/// `GET /v1/orgs/{org_id}/members/me` — the caller's own role, or 404.
async fn my_membership(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(org_id): Path<String>,
    account: Account,
) -> Result<Response, Problem> {
    let role = service::my_role(&state.ctx, &org_id, &account.sub)
        .await
        .map_err(|error| fail(&scope, &error))?;
    Ok(Json(json!({ "role": role })).into_response())
}

/// `POST /v1/orgs/{org_id}/members` — add a member, as a manager.
async fn add_member(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(org_id): Path<String>,
    account: Account,
    Json(body): Json<AddMemberBody>,
) -> Result<Response, Problem> {
    let member = service::add_member(
        &state.ctx,
        &state.settings,
        &org_id,
        &account.sub,
        &body.sub,
        &body.role,
    )
    .await
    .map_err(|error| fail(&scope, &error))?;
    Ok((StatusCode::CREATED, Json(member)).into_response())
}

/// `PATCH /v1/orgs/{org_id}/members/{sub}` — change a member's role.
async fn set_role(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path((org_id, sub)): Path<(String, String)>,
    account: Account,
    Json(body): Json<RoleBody>,
) -> Result<Response, Problem> {
    let member = service::set_role(
        &state.ctx,
        &state.settings,
        &org_id,
        &account.sub,
        &sub,
        &body.role,
    )
    .await
    .map_err(|error| fail(&scope, &error))?;
    Ok(Json(member).into_response())
}

/// `DELETE /v1/orgs/{org_id}/members/{sub}` — remove a member, or leave.
async fn remove_member(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path((org_id, sub)): Path<(String, String)>,
    account: Account,
) -> Result<Response, Problem> {
    service::remove_member(&state.ctx, &state.settings, &org_id, &account.sub, &sub)
        .await
        .map_err(|error| fail(&scope, &error))?;
    Ok(Json(json!({ "ok": true })).into_response())
}

/// `POST /v1/orgs/{org_id}/leave` — leave the organization.
async fn leave(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(org_id): Path<String>,
    account: Account,
) -> Result<Response, Problem> {
    service::remove_member(
        &state.ctx,
        &state.settings,
        &org_id,
        &account.sub,
        &account.sub,
    )
    .await
    .map_err(|error| fail(&scope, &error))?;
    Ok(Json(json!({ "ok": true })).into_response())
}

/// `POST /v1/orgs/{org_id}/invitations` — invite an address to join.
async fn invite(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Path(org_id): Path<String>,
    account: Account,
    Json(body): Json<InviteBody>,
) -> Result<Response, Problem> {
    service::invite(
        &state.ctx,
        &state.settings,
        &org_id,
        &account.sub,
        &body.email,
        &body.role,
    )
    .await
    .map_err(|error| fail(&scope, &error))?;
    // 202: the invitation exists and the mail is on its way. The raw token is
    // deliberately not in this body — it reached the invitee, not the caller.
    Ok((StatusCode::ACCEPTED, Json(json!({ "ok": true }))).into_response())
}

/// `POST /v1/orgs/invitations/accept` — accept an invitation sent to the
/// caller's verified address.
async fn accept_invitation(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    account: Account,
    Json(body): Json<AcceptBody>,
) -> Result<Response, Problem> {
    let org = service::accept(
        &state.ctx,
        &state.settings,
        &body.token,
        &account.sub,
        account.email.as_deref(),
    )
    .await
    .map_err(|error| fail(&scope, &error))?;
    Ok(Json(org).into_response())
}

/// `GET /v1/orgs/admin/orgs` — every organization, for a machine holding
/// `ADMIN_TOKEN` or a person in the venture's staff organization.
async fn admin_orgs(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response, Problem> {
    let staff_org = state.settings.staff_org(&*state.ctx.config);
    let staff_roles: Vec<&str> = state
        .settings
        .staff_roles
        .iter()
        .map(String::as_str)
        .collect();
    crate::require_staff(&state.ctx, &headers, &staff_org, &staff_roles)
        .await
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let limit = query.page_size();
    let orgs = service::all_orgs(&state.ctx, query.after(), limit)
        .await
        .map_err(|error| fail(&scope, &error))?;
    let cursor = page_cursor(&orgs, limit, |org| (&org.created_at, &org.id));
    Ok(Json(json!({ "orgs": orgs, "cursor": cursor })).into_response())
}

// ---------------------------------------------------------------------------
// Surface, config and composition checks

/// Every route, as an action. All but the admin listing are `Subject`: they
/// act for whichever account the credential names, and there is nothing for a
/// CAPTCHA to gate and no signature the request could carry.
pub(crate) fn surface() -> Surface {
    Surface::new()
        .action(
            Action::post("create", "/")
                .audience(Audience::Subject)
                .input::<CreateOrgBody>()
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::get("list", "/")
                .audience(Audience::Subject)
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::get("get", "/{org_id}")
                .audience(Audience::Subject)
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::get("members", "/{org_id}/members")
                .audience(Audience::Subject)
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::post("add-member", "/{org_id}/members")
                .audience(Audience::Subject)
                .input::<AddMemberBody>()
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::get("my-membership", "/{org_id}/members/me")
                .audience(Audience::Subject)
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::new(
                "set-role",
                axum::http::Method::PATCH,
                "/{org_id}/members/{sub}",
            )
            .audience(Audience::Subject)
            .input::<RoleBody>()
            .outcome(Outcome::Json)
            .policy(RoutePolicy::Open),
        )
        .action(
            Action::new(
                "remove-member",
                axum::http::Method::DELETE,
                "/{org_id}/members/{sub}",
            )
            .audience(Audience::Subject)
            .outcome(Outcome::Json)
            .policy(RoutePolicy::Open),
        )
        .action(
            Action::post("leave", "/{org_id}/leave")
                .audience(Audience::Subject)
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::post("invite", "/{org_id}/invitations")
                .audience(Audience::Subject)
                .input::<InviteBody>()
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::post("accept-invitation", "/invitations/accept")
                .audience(Audience::Subject)
                .input::<AcceptBody>()
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
        .action(
            Action::get("admin-orgs", "/admin/orgs")
                .audience(Audience::Admin)
                .outcome(Outcome::Json)
                .policy(RoutePolicy::Open),
        )
}

/// The two config keys that can point this module at another origin. Both are
/// optional; when present they must not be a plaintext origin a browser would
/// refuse to send a token to (a localhost URL is allowed for `wrangler dev`).
#[must_use]
pub(crate) fn validate(_settings: &Settings, cfg: &dyn Config) -> ConfigError {
    let module = ModuleConfig::new(crate::MODULE_NAME, cfg);
    let mut errors = ConfigError::new();
    for key in ["API_BASE", "ACCEPT_URL"] {
        let Some(value) = cfg.get(&module.key(key)) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty()
            || value.starts_with("https://")
            || value.starts_with("http://localhost")
            || value.starts_with("http://127.0.0.1")
        {
            continue;
        }
        errors.push(format!(
            "orgs: {} must be https (or a localhost URL for wrangler dev), got {value:?}",
            module.key(key)
        ));
    }
    errors
}

/// The compositions a build must refuse, reported by
/// [`Module::self_check`](cratefield_core::Module::self_check).
#[must_use]
pub(crate) fn self_check(settings: &Settings) -> Vec<String> {
    let mut problems = Vec::new();
    for manager in &settings.managers {
        if !settings.roles.contains(manager) {
            problems.push(format!(
                "orgs: manager role `{manager}` is not one of the configured roles — add it to \
                 `.roles(..)` or drop it from `.managers(..)`"
            ));
        }
    }
    if !settings.staff_roles.is_empty() && settings.staff_org.is_empty() {
        problems.push(
            "orgs: staff roles are configured without a staff organization, so nobody could \
             ever hold one — add `.staff_org(..)`"
                .to_owned(),
        );
    }
    for role in &settings.roles {
        if role.trim().is_empty() {
            problems.push("orgs: a configured role is empty".to_owned());
        }
    }
    problems
}
