#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod clock;
mod handlers;
mod mail;
mod service;
mod store;

use std::sync::OnceLock;

use async_trait::async_trait;
use http::HeaderMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::Duration;

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DataKind, Database, Disposition, Migrations, Module,
    ModuleContext, PersonalDataSet, Port, Problem, SLUGS, SqlMigration, Surface,
};

use handlers::Settings;

pub use mail::{InvitationMail, TEMPLATE_INVITATION, default_templates, themed_templates};

/// The module's name: it is mounted at `/v1/orgs`, and its config keys are
/// prefixed `ORGS_`.
pub const MODULE_NAME: &str = "orgs";

/// The module's one migration: the three tables in the portable SQL subset
/// (ADR 0004). Portable means it is also the set the Postgres runner applies,
/// so a `postgres` override is only needed if the SQL ever truly diverges.
const MIGRATION_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The invitation lifetime when a venture sets none.
const DEFAULT_INVITATION_TTL_SECS: i64 = 7 * 86_400;

/// The lowercase-hex SHA-256 of a value. Both the invitation token and the
/// invitee's normalized address reach the database only through this, so a
/// dump, a backup or a query log holds nothing that can be redeemed or read
/// back as an address.
#[must_use]
pub(crate) fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

// ---------------------------------------------------------------------------
// The public types

/// An organization, as a venture reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Org {
    /// The organization's id — stable, and what every other call takes.
    pub id: String,
    /// The name a person gave it.
    pub name: String,
    /// The subject that created it.
    pub created_by: String,
    /// When it was created, RFC 3339 UTC.
    pub created_at: String,
}

/// An organization and the role the caller holds in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Membership {
    pub org: Org,
    pub role: String,
}

/// One membership, as a member of the organization reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Member {
    /// The account's subject id.
    pub sub: String,
    /// The role they hold here.
    pub role: String,
    /// Whoever added them, when it was not themselves.
    pub invited_by: Option<String>,
    /// When they joined, RFC 3339 UTC.
    pub joined_at: String,
}

/// An authorized staff caller, as [`require_staff`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staff {
    /// The staff member's subject, when a person proved it. `None` for a
    /// machine holding `ADMIN_TOKEN`.
    pub subject: Option<String>,
    /// The role they hold in the staff organization, when a person.
    pub role: Option<String>,
}

impl Staff {
    /// Whether this caller was a machine token rather than a person.
    #[must_use]
    pub fn is_machine(&self) -> bool {
        self.subject.is_none()
    }
}

// ---------------------------------------------------------------------------
// Errors

/// What an orgs entry point can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrgsError {
    /// No such organization, no such member, or the caller is not a member.
    /// One variant on purpose: a caller who is not in an organization must not
    /// be able to tell it from one that does not exist.
    #[error("no organization or member matching `{0}` is visible to the caller")]
    NotFound(String),
    /// The caller is a member, but their role does not permit this.
    #[error("{0}")]
    Forbidden(String),
    /// The role is not one the venture configured.
    #[error("`{0}` is not a configured role")]
    UnknownRole(String),
    /// The organization's name was empty.
    #[error("an organization needs a name")]
    InvalidName,
    /// The address to invite is not an address.
    #[error("`{0}` is not a valid email address")]
    InvalidEmail(String),
    /// A field was longer than the module accepts.
    #[error("`{field}` must be at most {max} characters")]
    TooLong { field: &'static str, max: usize },
    /// The change would leave the organization with no owner.
    #[error("this is the organization's last owner")]
    LastOwner,
    /// The account is already a member.
    #[error("`{0}` is already a member")]
    AlreadyMember(String),
    /// The invitation is unknown, lapsed or already spent.
    #[error("the invitation is unknown, expired or already accepted")]
    InvitationGone,
    /// The invitation was issued to a different address.
    #[error("the invitation was issued to a different address")]
    InvitationForSomeoneElse,
    /// The credential proved no address, so no invitation can be matched.
    #[error("the caller's email address is not verified")]
    EmailUnverified,
    /// The deployment has no mailer, or the mailer has no verified domain.
    #[error("mail is not configured")]
    MailNotConfigured,
    /// The provider refused the invitation message.
    #[error("the invitation message was refused: {0}")]
    Mail(String),
    /// The module is misconfigured.
    #[error("orgs is misconfigured: {0}")]
    Config(String),
    /// A database failure.
    #[error(transparent)]
    Db(#[from] cratefield_core::DbError),
}

impl OrgsError {
    /// The RFC 9457 `type` slug this failure maps to.
    #[must_use]
    pub fn slug(&self) -> &'static str {
        handlers::problem_for(self).slug
    }

    /// The problem body a caller should answer with.
    #[must_use]
    pub fn problem(&self) -> Problem {
        handlers::problem_for(self)
    }
}

// ---------------------------------------------------------------------------
// The typed in-process API

/// The role `sub` holds in `org_id`, or `None` when they are not a member —
/// the one call an external app needs to answer "may this person see this
/// organization's page", without going through HTTP.
///
/// # Errors
///
/// [`OrgsError::Db`] when the query fails; a caller with no role and a caller
/// whose organization does not exist both answer `Ok(None)`, which is the same
/// deliberate silence the routes keep.
pub async fn member_role(
    db: &dyn Database,
    org_id: &str,
    sub: &str,
) -> Result<Option<String>, OrgsError> {
    Ok(store::find_member(db, org_id, sub)
        .await?
        .map(|member| member.role))
}

/// Authorizes a staff caller for an admin action: a machine holding
/// `ADMIN_TOKEN`, or a person whose verified subject is a member of `staff_org`
/// holding one of `roles`.
///
/// `ADMIN_TOKEN` stays for machines — a cron, a CLI, a back-office script that
/// has no account. People move to the staff organization, where membership is
/// revocable the same way any other membership is: no shared secret to rotate,
/// and the person's departure is a `DELETE` away.
///
/// # Errors
///
/// `401 admin-unauthorized` when `ADMIN_TOKEN` is the only configured path and
/// nothing acceptable was presented, `403 admin-forbidden` when a verified
/// caller is not staff, and `500` when the database cannot be read.
pub async fn require_staff(
    ctx: &ModuleContext,
    headers: &HeaderMap,
    staff_org: &str,
    roles: &[&str],
) -> Result<Staff, Problem> {
    // The machine path first and unchanged: a deployment that has an
    // `ADMIN_TOKEN` keeps the machine it was written for.
    if cratefield_core::require_admin(&*ctx.config, headers).is_ok() {
        return Ok(Staff {
            subject: None,
            role: None,
        });
    }
    if staff_org.is_empty() || roles.is_empty() {
        // No staff organization to move to: report the admin-token outcome,
        // so the answer is the 401 or 403 the token path would have given.
        return cratefield_core::require_admin(&*ctx.config, headers).map(|()| Staff {
            subject: None,
            role: None,
        });
    }

    let Some(auth) = ctx.ports.auth.clone() else {
        return Err(Problem::new(&SLUGS.admin_unauthorized));
    };
    let subject = match auth.identify(headers).await {
        Ok(caller) => caller.subject().map(|subject| subject.id.clone()),
        Err(_) => None,
    };
    let Some(subject) = subject else {
        // Anonymous, or a credential that did not verify. Both are a caller
        // who has not been established as anybody.
        return Err(Problem::new(&SLUGS.admin_unauthorized));
    };

    let db = ctx.ports.db.as_deref().ok_or_else(Problem::internal)?;
    let role = member_role(db, staff_org, &subject)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "reading a staff membership failed");
            Problem::internal()
        })?;
    match role {
        Some(role) if roles.iter().any(|allowed| *allowed == role) => Ok(Staff {
            subject: Some(subject),
            role: Some(role),
        }),
        // A signed-in person who is not staff: a 403, never a 401, so the
        // answer does not tell them to sign in again.
        _ => Err(Problem::new(&SLUGS.admin_forbidden)),
    }
}

// ---------------------------------------------------------------------------
// The module and its builder

/// The organizations module (issue #652): organizations, memberships, roles
/// and email invitations. Compose it with [`Orgs::builder`].
pub struct Orgs {
    settings: Settings,
}

impl Default for Orgs {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Orgs {
    /// The module with its defaults: the `owner` role alone, no manager roles,
    /// no staff organization. The same as `builder().build()`, and what a
    /// generated manifest mounts when it has nothing to configure.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A builder with the default role set: `owner` alone. Named `builder`
    /// rather than `new`, like every other module in this workspace, because
    /// it returns an [`OrgsBuilder`] rather than the module itself.
    #[must_use]
    pub fn builder() -> OrgsBuilder {
        OrgsBuilder::new()
    }

    /// The role set, for a caller that wants to publish it.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.settings.roles
    }
}

/// Builds an [`Orgs`].
pub struct OrgsBuilder {
    settings: Settings,
}

impl OrgsBuilder {
    fn new() -> Self {
        Self {
            settings: Settings {
                roles: vec![store::OWNER.to_owned()],
                managers: Vec::new(),
                staff_org: String::new(),
                staff_roles: Vec::new(),
                invitation_ttl_secs: DEFAULT_INVITATION_TTL_SECS,
            },
        }
    }

    /// The roles an organization may use, e.g.
    /// `Orgs::builder().roles(["owner", "manager", "staff"])`.
    ///
    /// `owner` is always in the set — it is added here if it was omitted — and
    /// is the role the creator gets. A role a venture did not name is refused
    /// with `422 orgs-unknown-role` rather than stored, so a typo cannot leave
    /// an organization holding a role nothing can interpret.
    #[must_use]
    pub fn roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut out: Vec<String> = Vec::new();
        for role in roles {
            let role = role.into();
            if !role.trim().is_empty() && !out.contains(&role) {
                out.push(role);
            }
        }
        if !out.iter().any(|role| role == store::OWNER) {
            out.insert(0, store::OWNER.to_owned());
        }
        self.settings.roles = out;
        self
    }

    /// The non-owner roles that may manage members and invitations: add,
    /// remove, change roles, and invite. Owners may always manage; only an
    /// owner may grant, change or remove the `owner` role, and only an owner
    /// may touch an owner's membership. The default is that only owners manage.
    #[must_use]
    pub fn managers<I, S>(mut self, managers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.settings.managers = managers.into_iter().map(Into::into).collect();
        self
    }

    /// The venture's staff organization — the one whose members may see the
    /// admin listing. `ORGS_STAFF_ORG` overrides it per deployment.
    #[must_use]
    pub fn staff_org(mut self, org_id: impl Into<String>) -> Self {
        self.settings.staff_org = org_id.into();
        self
    }

    /// The roles in the staff organization that may see the admin listing.
    /// Empty (the default) means the staff organization grants nothing.
    #[must_use]
    pub fn staff_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.settings.staff_roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// How long an invitation stays acceptable. Seven days by default; a
    /// negative value is clamped to zero, which makes every invitation lapse
    /// at once — a shape only a test wants.
    #[must_use]
    pub fn invitation_ttl(mut self, ttl: Duration) -> Self {
        self.settings.invitation_ttl_secs = ttl.whole_seconds().max(0);
        self
    }

    /// Finishes the module.
    #[must_use]
    pub fn build(self) -> Orgs {
        Orgs {
            settings: self.settings,
        }
    }
}

// ---------------------------------------------------------------------------
// The module

#[async_trait]
impl Module for Orgs {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Memberships are rows, so the module needs a database; every route but
    /// the admin listing acts for the account a credential proves, so it needs
    /// a verifier. A deployment without one refuses to boot rather than
    /// serving an organization's roster to whoever asks.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Auth]
    }

    /// `Clock` decides "now" for expiry and single-use, `IdGen` mints ids and
    /// the invitation token, and `Mailer` delivers the invitation. Each has a
    /// working default or a documented absence, so none is required.
    fn optional(&self) -> &'static [Port] {
        &[Port::Clock, Port::IdGen, Port::Mailer]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["orgs", "org_members", "org_invitations"]
    }

    /// Three tables, one declaration each — `HarnessBuilder::build` refuses a
    /// table declared twice, so a column that names a *second* person cannot
    /// get a declaration of its own and the choice has to be made once per
    /// table:
    ///
    /// - `org_members` is the member's. `Erase` is the only disposition that
    ///   leaves no membership pointing at an account that no longer exists.
    ///   Its `invited_by` names whoever added them — a *second* person on the
    ///   member's row — so it is named in `redacted`: an export of the row
    ///   shows the column and not the id. Nothing erases it, and the reason is
    ///   in the declaration rather than left to be discovered: the framework
    ///   blanks columns only on the rows a subject's own value matches.
    /// - `orgs` is retained: the row is not one person's — deleting it would
    ///   delete every other member's organization — and `created_by` is kept
    ///   as provenance. Erasure of the creator's account does not remove the
    ///   organization, which is what `Retain` says.
    /// - `org_invitations` is the inviter's. The row is keyed by `invited_by`,
    ///   so erasing the inviter takes the invitations they sent; the invitee
    ///   is held only as the SHA-256 of their address, which is not a value an
    ///   erasure request can carry, so there is nothing to erase *for* them
    ///   and nothing of theirs left to read.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        static SETS: OnceLock<Vec<PersonalDataSet>> = OnceLock::new();
        SETS.get_or_init(|| {
            vec![
                PersonalDataSet {
                    table: "orgs",
                    subject: "created_by",
                    kind: DataKind::Identifier,
                    disposition: Disposition::Retain(
                        "An organization is not one person's: removing the row would remove \
                         every other member's organization with it. The creator is kept as \
                         provenance, and the name belongs to the organization.",
                    ),
                    description: "An organization you created: its name, when it was made, \
                                  and the fact that you made it. It is kept because its other \
                                  members' data is inside it.",
                    redacted: &[],
                    subject_via: None,
                },
                PersonalDataSet {
                    table: "org_members",
                    subject: "user_sub",
                    kind: DataKind::Identifier,
                    disposition: Disposition::Erase,
                    description: "Your membership in an organization: the role you hold, when \
                                  you joined, and who added you if it was not you. Erasing \
                                  your account removes the membership.",
                    // The `invited_by` on somebody *else's* row names you: an
                    // export of their membership shows the column and not your
                    // id. Nothing erases it — see the note above the sets.
                    redacted: &["invited_by"],
                    subject_via: None,
                },
                PersonalDataSet {
                    table: "org_invitations",
                    subject: "invited_by",
                    kind: DataKind::Contact,
                    disposition: Disposition::Erase,
                    description: "An invitation you sent: the organization, the role offered, \
                                  an address held only as a hash, and when the link lapses. \
                                  Erasing your account removes the invitations you sent.",
                    redacted: &[],
                    subject_via: None,
                },
            ]
        })
        .as_slice()
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        handlers::validate(&self.settings, cfg).into_result()
    }

    fn self_check(&self) -> Vec<String> {
        handlers::self_check(&self.settings)
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(std::sync::Arc::new(ctx), self.settings.clone())
    }

    fn surface(&self) -> Surface {
        handlers::surface()
    }

    /// The scheduled pass: delete invitations that have lapsed, so an
    /// organization is not left holding addresses it can no longer invite
    /// with. An accepted invitation is kept until it lapses — it is what the
    /// accept path reads back to tell who spent the token, and it holds only
    /// hashes.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            if let Err(error) = service::maintain(ctx).await {
                tracing::warn!(cron, error = %error, "the scheduled orgs pass did not complete");
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `owner` is in the set whether or not the venture named it, and one
    /// blank or repeated role does not become a role an organization can hold.
    #[test]
    fn the_role_set_always_holds_owner_and_never_a_blank() {
        let builder = Orgs::builder().roles(["manager", "manager", " ", "staff"]);
        assert_eq!(builder.settings.roles, vec!["owner", "manager", "staff"]);

        let builder = Orgs::builder().roles(Vec::<String>::new());
        assert_eq!(builder.settings.roles, vec!["owner"]);
    }

    /// A manager role the venture named but did not declare a role for is a
    /// composition mistake, not a role nothing can hold.
    #[test]
    fn a_manager_role_that_is_not_a_role_is_reported() {
        let module = Orgs::builder()
            .roles(["staff"])
            .managers(["manager"])
            .build();
        let problems = module.self_check();
        assert_eq!(problems.len(), 1, "one problem: {problems:?}");
        assert!(problems[0].contains("manager"));
    }

    /// Staff roles without a staff organization grant nothing, so the builder
    /// says so rather than letting the admin listing quietly never open.
    #[test]
    fn staff_roles_need_a_staff_organization() {
        let module = Orgs::builder().staff_roles(["admin"]).build();
        assert_eq!(module.self_check().len(), 1);
        let module = Orgs::builder()
            .staff_org("org-staff")
            .staff_roles(["admin"])
            .build();
        assert!(module.self_check().is_empty());
    }

    /// A three-day invitation is three days, and a negative one lapses at once
    /// rather than underflowing into a lifetime.
    #[test]
    fn the_invitation_lifetime_is_what_the_builder_set() {
        let module = Orgs::builder().invitation_ttl(Duration::days(3)).build();
        assert_eq!(module.settings.invitation_ttl_secs, 3 * 86_400);
        let module = Orgs::builder()
            .invitation_ttl(Duration::seconds(-5))
            .build();
        assert_eq!(module.settings.invitation_ttl_secs, 0);
    }
}
