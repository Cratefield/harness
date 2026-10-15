//! Access grants (issue #878): who may do what to which part of an
//! organization's data.
//!
//! A [`Grant`] says that a **principal** (a member, a service account, a role
//! group — opaque strings the venture chooses) holds a [`Permission`] on a
//! [`Selector`], or — with [`Effect::Deny`] — that it must not. A selector is
//! a resource **kind** (`pages`, `files`, or `*` for every kind), a **space**
//! (an opaque partition the venture names: `shared`, `personal:<id>`, …) and a
//! **path** of segments; it covers a [`Resource`] of the same kind and space
//! whose path *starts with* the selector's path, segment by segment. So
//! `docs/team` covers `docs/team` and `docs/team/plan`, and never
//! `docs/teamwork`.
//!
//! ## The rule
//!
//! [`decide`] is deny-by-default, and **an applicable deny wins**:
//!
//! 1. Only grants whose principal is one of the asker's, and which have not
//!    expired, apply.
//! 2. If an applicable deny covers the resource, the answer is
//!    [`Decision::Denied`] — whatever any allow says.
//! 3. Otherwise the answer is [`Decision::Allowed`] iff an applicable allow
//!    covers it with a permission at least the one asked for.
//!
//! A deny forbids every permission on what it covers: it is a wall, not a
//! downgrade. The rule is monotonic — adding an allow never revokes, adding a
//! deny never grants, and no answer depends on the order rows were written —
//! which is what lets a person review "who can see this" one grant at a time.
//! "Allow a folder, deny one sub-folder" is expressible; "deny a folder,
//! re-allow inside it" deliberately is not.
//!
//! ## Credentials narrow, never widen
//!
//! A credential (an API key, a personal token) may carry a scope list —
//! [`CredentialScope`]s. [`decide_with_credential`] answers the grant
//! decision first and then requires that some entry of a present list also
//! covers the resource at the permission asked; an absent list is "no
//! narrowing". The result is the intersection, so a credential can never
//! reach what its principal could not.
//!
//! ## Implicit grants
//!
//! A venture usually has access nobody wrote down — a member's own space,
//! everyone's read on a shared one. Those are [`Grant`] values too
//! ([`Grant::implicit`]), passed to [`decide`] beside the stored rows, so the
//! one rule above governs both and an empty table reproduces the venture's
//! default.

use cratefield_core::{Database, DbError, Row, Statement};
use time::OffsetDateTime;

use crate::clock::{iso, parse};

/// The grants table.
pub const TABLE: &str = "org_grants";

/// The kind a selector names to cover every resource kind.
pub const ANY_KIND: &str = "*";

/// The longest a kind, space, principal or path segment may be, in bytes.
const MAX_PART: usize = 256;
/// The most segments a path may have.
const MAX_SEGMENTS: usize = 32;

// ---------------------------------------------------------------------------
// The vocabulary

/// What a grant lets its principal do. Ordered: `Read < Write < Admin`, and a
/// grant of one implies every permission below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// See the resource.
    Read,
    /// Change it.
    Write,
    /// Grant and revoke access to it.
    Admin,
}

impl Permission {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    /// The permission a stored spelling names, or `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// Whether a grant opens or closes what it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Opens the selector at the grant's permission.
    Allow,
    /// Closes the selector for every permission, and wins over any allow.
    Deny,
}

impl Effect {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// The effect a stored spelling names, or `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// Why a selector, resource or principal was refused at construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidSelector {
    /// The kind is empty, too long, or not plain text.
    #[error("the kind must be 1–256 printable characters without `/`")]
    Kind,
    /// The space is empty, too long, or not plain text.
    #[error("the space must be 1–256 printable characters without `/`")]
    Space,
    /// A path segment is empty, too long, `.`/`..`, or carries `/` or a
    /// control character — or there are too many of them.
    #[error("a path is at most 32 segments of 1–256 printable characters, none `.` or `..`")]
    Path,
    /// A resource named the wildcard kind, which only a selector may.
    #[error("a resource has a concrete kind; `*` is for selectors")]
    WildcardResource,
    /// The principal is empty, too long, or not plain text.
    #[error("the principal must be 1–256 printable characters")]
    Principal,
}

fn plain(value: &str, allow_slash: bool) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PART
        && value
            .chars()
            .all(|ch| !ch.is_control() && (allow_slash || ch != '/'))
}

fn check_path(path: &[String]) -> Result<(), InvalidSelector> {
    if path.len() > MAX_SEGMENTS
        || path
            .iter()
            .any(|segment| !plain(segment, false) || segment == "." || segment == "..")
    {
        return Err(InvalidSelector::Path);
    }
    Ok(())
}

/// Splits a stored `a/b/c` path into segments; the empty string is the empty
/// path. Leading, trailing and doubled slashes are ignored, so `a/b/` and
/// `a/b` are one path.
#[must_use]
pub fn split_path(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect()
}

/// What a grant covers: one kind (or [`ANY_KIND`]), one space, and a path
/// prefix of whole segments. Built through [`Selector::new`], which refuses
/// anything that could make a prefix match ambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selector {
    kind: String,
    space: String,
    path: Vec<String>,
}

impl Selector {
    /// A selector over `kind` (or `*`), `space` and `path` (segments; empty
    /// is the whole space).
    ///
    /// # Errors
    ///
    /// [`InvalidSelector`] for an empty or oversized part, a `/` inside a
    /// kind, space or segment, a control character, or a `.`/`..` segment.
    pub fn new(
        kind: impl Into<String>,
        space: impl Into<String>,
        path: Vec<String>,
    ) -> Result<Self, InvalidSelector> {
        let (kind, space) = (kind.into(), space.into());
        if !plain(&kind, false) {
            return Err(InvalidSelector::Kind);
        }
        if !plain(&space, false) {
            return Err(InvalidSelector::Space);
        }
        check_path(&path)?;
        Ok(Self { kind, space, path })
    }

    /// The kind, or `*`.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The space.
    #[must_use]
    pub fn space(&self) -> &str {
        &self.space
    }

    /// The path prefix, segment by segment.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// The path as stored: segments joined by `/`, no leading or trailing one.
    #[must_use]
    pub fn path_string(&self) -> String {
        self.path.join("/")
    }

    /// Whether this selector covers `resource`: same space, the same kind or
    /// `*`, and a path that is a whole-segment prefix of the resource's.
    #[must_use]
    pub fn covers(&self, resource: &Resource) -> bool {
        (self.kind == ANY_KIND || self.kind == resource.kind)
            && self.space == resource.space
            && resource.path.starts_with(&self.path)
    }

    /// Whether this selector covers everything `other` does — the check that
    /// decides whether a holder of `self` may grant `other`. A `*` kind
    /// contains every kind; a concrete one contains only itself.
    #[must_use]
    pub fn contains(&self, other: &Selector) -> bool {
        (self.kind == ANY_KIND || self.kind == other.kind)
            && self.space == other.space
            && other.path.starts_with(&self.path)
    }
}

/// One thing access is asked about: a concrete kind, a space, and a full path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Resource {
    kind: String,
    space: String,
    path: Vec<String>,
}

impl Resource {
    /// A resource of `kind` in `space` at `path`.
    ///
    /// # Errors
    ///
    /// The [`Selector::new`] refusals, and [`InvalidSelector::WildcardResource`]
    /// for the kind `*`.
    pub fn new(
        kind: impl Into<String>,
        space: impl Into<String>,
        path: Vec<String>,
    ) -> Result<Self, InvalidSelector> {
        let selector = Selector::new(kind, space, path)?;
        if selector.kind == ANY_KIND {
            return Err(InvalidSelector::WildcardResource);
        }
        Ok(Self {
            kind: selector.kind,
            space: selector.space,
            path: selector.path,
        })
    }

    /// The kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The space.
    #[must_use]
    pub fn space(&self) -> &str {
        &self.space
    }

    /// The path.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }
}

/// One grant: a principal, a selector, a permission, an effect and an
/// optional expiry. `id` is empty for an [implicit](Grant::implicit) grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The row id, or empty for a grant nobody stored.
    pub id: String,
    /// Who it is for — an opaque principal string.
    pub principal: String,
    /// What it covers.
    pub selector: Selector,
    /// What it allows (ignored by a deny, which forbids everything).
    pub permission: Permission,
    /// Allow or deny.
    pub effect: Effect,
    /// When it stops applying (RFC 3339), or `None` for never.
    pub expires_at: Option<String>,
    /// Who created it; empty for an implicit grant.
    pub created_by: String,
    /// When (RFC 3339); empty for an implicit grant.
    pub created_at: String,
}

impl Grant {
    /// An allow the venture derives rather than stores — a member's own
    /// space, a role's default reach. It goes through [`decide`] like a row,
    /// so a stored deny still wins over it.
    #[must_use]
    pub fn implicit(
        principal: impl Into<String>,
        selector: Selector,
        permission: Permission,
    ) -> Self {
        Self {
            id: String::new(),
            principal: principal.into(),
            selector,
            permission,
            effect: Effect::Allow,
            expires_at: None,
            created_by: String::new(),
            created_at: String::new(),
        }
    }

    /// Whether the grant still applies at `now`. A stored expiry that does
    /// not parse reads as already past, so a corrupt row fails closed.
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        match &self.expires_at {
            None => true,
            Some(at) => parse(at) > now,
        }
    }
}

/// One entry of a credential's scope list: the selector it may reach, up to
/// a permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScope {
    /// What the credential may reach.
    pub selector: Selector,
    /// The most it may do there.
    pub permission: Permission,
}

/// The answer to one question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// An applicable allow covers it at the permission asked, and no deny does.
    Allowed,
    /// Refused. Which of the [`DenyReason`]s it was is for logs and the audit
    /// trail, never for the caller: telling them would say what exists.
    Denied(DenyReason),
}

impl Decision {
    /// Whether the answer is [`Decision::Allowed`].
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Why [`decide`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// No applicable allow covered the resource at that permission.
    NoGrant,
    /// An applicable deny covered it.
    ExplicitDeny,
    /// The grants allowed it and the credential's scope list did not.
    CredentialScope,
}

/// The grant decision: deny-by-default, an applicable deny wins. See the
/// [module docs](self) for the rule.
#[must_use]
pub fn decide(
    grants: &[Grant],
    principals: &[&str],
    resource: &Resource,
    wanted: Permission,
    now: OffsetDateTime,
) -> Decision {
    let mut allowed = false;
    for grant in grants {
        if !principals.contains(&grant.principal.as_str())
            || !grant.is_live(now)
            || !grant.selector.covers(resource)
        {
            continue;
        }
        match grant.effect {
            Effect::Deny => return Decision::Denied(DenyReason::ExplicitDeny),
            Effect::Allow => allowed |= grant.permission >= wanted,
        }
    }
    if allowed {
        Decision::Allowed
    } else {
        Decision::Denied(DenyReason::NoGrant)
    }
}

/// [`decide`], then the credential's scope list: `None` narrows nothing, and
/// `Some(list)` requires an entry that covers the resource at `wanted`. An
/// empty list reaches nothing.
#[must_use]
pub fn decide_with_credential(
    grants: &[Grant],
    principals: &[&str],
    credential: Option<&[CredentialScope]>,
    resource: &Resource,
    wanted: Permission,
    now: OffsetDateTime,
) -> Decision {
    let decision = decide(grants, principals, resource, wanted, now);
    if !decision.is_allowed() {
        return decision;
    }
    match credential {
        None => decision,
        Some(scopes)
            if scopes
                .iter()
                .any(|scope| scope.permission >= wanted && scope.selector.covers(resource)) =>
        {
            decision
        }
        Some(_) => Decision::Denied(DenyReason::CredentialScope),
    }
}

/// What one principal set may reach inside one kind and space, as prefixes —
/// for a listing or a search that must filter **before** it ranks or limits,
/// rather than ask [`decide`] once per row it has already read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    /// Paths an applicable allow opens at the permission asked.
    pub allow: Vec<Vec<String>>,
    /// Paths an applicable deny closes.
    pub deny: Vec<Vec<String>>,
}

impl Coverage {
    /// Whether `path` is open: under some allow and under no deny — the same
    /// answer [`decide`] gives for a resource at that path.
    #[must_use]
    pub fn covers(&self, path: &[String]) -> bool {
        !self.deny.iter().any(|prefix| path.starts_with(prefix))
            && self.allow.iter().any(|prefix| path.starts_with(prefix))
    }

    /// Whether nothing at all is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }

    /// Whether the whole space is open with no deny inside it.
    #[must_use]
    pub fn is_whole(&self) -> bool {
        self.deny.is_empty() && self.allow.iter().any(Vec::is_empty)
    }
}

/// The [`Coverage`] of `kind` in `space` for `principals` at `wanted`,
/// intersected with the credential's scope list when one is present.
///
/// The intersection of two prefix sets is the longer of each overlapping
/// pair, so every allow that survives is one both the grants and the
/// credential open; denies are carried over unchanged.
#[must_use]
pub fn coverage(
    grants: &[Grant],
    principals: &[&str],
    credential: Option<&[CredentialScope]>,
    kind: &str,
    space: &str,
    wanted: Permission,
    now: OffsetDateTime,
) -> Coverage {
    let applies = |selector: &Selector| {
        (selector.kind == ANY_KIND || selector.kind == kind) && selector.space == space
    };
    let mut out = Coverage::default();
    for grant in grants {
        if !principals.contains(&grant.principal.as_str())
            || !grant.is_live(now)
            || !applies(&grant.selector)
        {
            continue;
        }
        match grant.effect {
            Effect::Deny => out.deny.push(grant.selector.path.clone()),
            Effect::Allow if grant.permission >= wanted => {
                out.allow.push(grant.selector.path.clone());
            }
            Effect::Allow => {}
        }
    }
    if let Some(scopes) = credential {
        let limits: Vec<&Vec<String>> = scopes
            .iter()
            .filter(|scope| scope.permission >= wanted && applies(&scope.selector))
            .map(|scope| &scope.selector.path)
            .collect();
        let mut narrowed = Vec::new();
        for allow in &out.allow {
            for limit in &limits {
                if allow.starts_with(limit) {
                    narrowed.push(allow.clone());
                } else if limit.starts_with(allow) {
                    narrowed.push((*limit).clone());
                }
            }
        }
        out.allow = narrowed;
    }
    out.allow.sort();
    out.allow.dedup();
    out.deny.sort();
    out.deny.dedup();
    out
}

/// Whether a granter holding `grants` may create (or delete) `proposed`:
/// they must hold [`Permission::Admin`] on a selector that
/// [contains](Selector::contains) the proposed one, with no applicable deny
/// anywhere inside it. Nobody can hand out more than they hold, and a deny is
/// created under the same rule as an allow.
#[must_use]
pub fn may_grant(
    grants: &[Grant],
    principals: &[&str],
    proposed: &Selector,
    now: OffsetDateTime,
) -> bool {
    let mut holds = false;
    for grant in grants {
        if !principals.contains(&grant.principal.as_str()) || !grant.is_live(now) {
            continue;
        }
        let selector = &grant.selector;
        match grant.effect {
            // A deny that touches any part of the proposed selector — above
            // it, or inside it — means the granter cannot see all of what they
            // would be handing out.
            Effect::Deny => {
                if selector.contains(proposed) || proposed.contains(selector) {
                    return false;
                }
            }
            Effect::Allow => {
                holds |= grant.permission == Permission::Admin && selector.contains(proposed);
            }
        }
    }
    holds
}

// ---------------------------------------------------------------------------
// The table

/// A grant to store: everything but the id and the creation stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant {
    /// Who it is for.
    pub principal: String,
    /// What it covers.
    pub selector: Selector,
    /// What it allows.
    pub permission: Permission,
    /// Allow or deny.
    pub effect: Effect,
    /// When it stops applying, or `None`.
    pub expires_at: Option<OffsetDateTime>,
    /// Who created it.
    pub created_by: String,
}

fn check_principal(principal: &str) -> Result<(), InvalidSelector> {
    if plain(principal, true) {
        Ok(())
    } else {
        Err(InvalidSelector::Principal)
    }
}

/// Why a grant could not be stored.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// The principal was not plain text.
    #[error(transparent)]
    Invalid(#[from] InvalidSelector),
    /// The database refused.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Stores a grant in `org_id` under `id`, or — when the same principal
/// already has a grant of the same effect on the same selector — replaces its
/// permission and expiry, so a selector holds one row per principal and
/// effect. Answers the id of the row now holding the grant.
///
/// # Errors
///
/// [`GrantError`] for an invalid principal or a database failure.
pub async fn put_grant(
    db: &dyn Database,
    org_id: &str,
    id: &str,
    grant: &NewGrant,
    now: OffsetDateTime,
) -> Result<String, GrantError> {
    check_principal(&grant.principal)?;
    let path = grant.selector.path_string();
    let statement = Statement::with_values(
        "INSERT INTO org_grants \
           (id, org_id, principal, kind, space, path, permission, effect, expires_at, \
            created_by, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (org_id, principal, kind, space, path, effect) DO UPDATE \
           SET permission = excluded.permission, expires_at = excluded.expires_at",
        vec![
            id.into(),
            org_id.into(),
            grant.principal.as_str().into(),
            grant.selector.kind.as_str().into(),
            grant.selector.space.as_str().into(),
            path.as_str().into(),
            grant.permission.as_str().into(),
            grant.effect.as_str().into(),
            grant.expires_at.map(iso).into(),
            grant.created_by.as_str().into(),
            iso(now).into(),
        ],
    );
    db.execute(&statement).await?;
    let read = Statement::with_values(
        "SELECT id FROM org_grants WHERE org_id = ? AND principal = ? AND kind = ? \
           AND space = ? AND path = ? AND effect = ?",
        vec![
            org_id.into(),
            grant.principal.as_str().into(),
            grant.selector.kind.as_str().into(),
            grant.selector.space.as_str().into(),
            path.into(),
            grant.effect.as_str().into(),
        ],
    );
    Ok(db
        .query(&read)
        .await?
        .first()
        .and_then(|row| row.get::<String>("id"))
        .unwrap_or_else(|| id.to_owned()))
}

const COLUMNS: &str = "id, principal, kind, space, path, permission, effect, expires_at, \
                       created_by, created_at";

/// A stored row back into a [`Grant`]. A row that no longer parses — an
/// unknown permission, a selector the rules now refuse — is dropped, so a
/// corrupt allow grants nothing. A corrupt **deny** is the exception: it is
/// read back as a deny over its whole space, so it fails closed rather than
/// silently opening what it closed.
fn grant_from(row: &Row) -> Option<Grant> {
    let text = |name: &str| row.get::<String>(name).unwrap_or_default();
    let effect = Effect::parse(&text("effect"))?;
    let selector = Selector::new(text("kind"), text("space"), split_path(&text("path")));
    let permission = Permission::parse(&text("permission"));
    let (selector, permission) = match (effect, selector, permission) {
        (_, Ok(selector), Some(permission)) => (selector, permission),
        (Effect::Deny, _, _) => (
            Selector::new(ANY_KIND, text("space"), Vec::new()).ok()?,
            Permission::Admin,
        ),
        (Effect::Allow, _, _) => return None,
    };
    Some(Grant {
        id: text("id"),
        principal: text("principal"),
        selector,
        permission,
        effect,
        expires_at: row.get::<String>("expires_at").filter(|at| !at.is_empty()),
        created_by: text("created_by"),
        created_at: text("created_at"),
    })
}

/// Every stored grant in `org_id` for any of `principals`, oldest first.
/// Expired rows are returned too — [`decide`] ignores them — so a settings
/// page can show what lapsed.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub async fn grants_for(
    db: &dyn Database,
    org_id: &str,
    principals: &[&str],
) -> Result<Vec<Grant>, DbError> {
    if principals.is_empty() {
        return Ok(Vec::new());
    }
    let marks = vec!["?"; principals.len()].join(", ");
    let mut values: Vec<sea_query::Value> = vec![org_id.into()];
    values.extend(principals.iter().map(|principal| (*principal).into()));
    let statement = Statement::with_values(
        format!(
            "SELECT {COLUMNS} FROM org_grants WHERE org_id = ? AND principal IN ({marks}) \
             ORDER BY created_at, id"
        ),
        values,
    );
    Ok(db
        .query(&statement)
        .await?
        .rows
        .iter()
        .filter_map(grant_from)
        .collect())
}

/// Every stored grant in `org_id` on `space`, for any principal — the
/// "who can see this" read.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub async fn grants_on_space(
    db: &dyn Database,
    org_id: &str,
    space: &str,
) -> Result<Vec<Grant>, DbError> {
    let statement = Statement::with_values(
        format!(
            "SELECT {COLUMNS} FROM org_grants WHERE org_id = ? AND space = ? \
             ORDER BY created_at, id"
        ),
        vec![org_id.into(), space.into()],
    );
    Ok(db
        .query(&statement)
        .await?
        .rows
        .iter()
        .filter_map(grant_from)
        .collect())
}

/// Every stored grant in `org_id`.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub async fn grants_in_org(db: &dyn Database, org_id: &str) -> Result<Vec<Grant>, DbError> {
    let statement = Statement::with_values(
        format!("SELECT {COLUMNS} FROM org_grants WHERE org_id = ? ORDER BY created_at, id"),
        vec![org_id.into()],
    );
    Ok(db
        .query(&statement)
        .await?
        .rows
        .iter()
        .filter_map(grant_from)
        .collect())
}

/// One grant by id, inside `org_id` only.
///
/// # Errors
///
/// [`DbError`] when the read fails.
pub async fn grant(db: &dyn Database, org_id: &str, id: &str) -> Result<Option<Grant>, DbError> {
    let statement = Statement::with_values(
        format!("SELECT {COLUMNS} FROM org_grants WHERE org_id = ? AND id = ?"),
        vec![org_id.into(), id.into()],
    );
    Ok(db.query(&statement).await?.first().and_then(grant_from))
}

/// Deletes one grant, inside `org_id` only. Answers whether a row went.
///
/// # Errors
///
/// [`DbError`] when the delete fails.
pub async fn delete_grant(db: &dyn Database, org_id: &str, id: &str) -> Result<bool, DbError> {
    let statement = Statement::with_values(
        "DELETE FROM org_grants WHERE org_id = ? AND id = ?",
        vec![org_id.into(), id.into()],
    );
    Ok(db.execute(&statement).await? > 0)
}

/// Deletes every grant naming `principal` in `org_id` — what removing a
/// member or deleting a service account does. Answers how many went.
///
/// # Errors
///
/// [`DbError`] when the delete fails.
pub async fn delete_grants_for(
    db: &dyn Database,
    org_id: &str,
    principal: &str,
) -> Result<u64, DbError> {
    let statement = Statement::with_values(
        "DELETE FROM org_grants WHERE org_id = ? AND principal = ?",
        vec![org_id.into(), principal.into()],
    );
    db.execute(&statement).await
}

/// Deletes every grant on `space` in `org_id` — what removing the member who
/// owns a personal space does, so nobody keeps a share of it.
///
/// # Errors
///
/// [`DbError`] when the delete fails.
pub async fn delete_grants_on_space(
    db: &dyn Database,
    org_id: &str,
    space: &str,
) -> Result<u64, DbError> {
    let statement = Statement::with_values(
        "DELETE FROM org_grants WHERE org_id = ? AND space = ?",
        vec![org_id.into(), space.into()],
    );
    db.execute(&statement).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("in range")
    }

    fn sel(kind: &str, space: &str, path: &str) -> Selector {
        Selector::new(kind, space, split_path(path)).expect("a valid selector")
    }

    fn res(kind: &str, space: &str, path: &str) -> Resource {
        Resource::new(kind, space, split_path(path)).expect("a valid resource")
    }

    fn allow(principal: &str, selector: Selector, permission: Permission) -> Grant {
        Grant::implicit(principal, selector, permission)
    }

    fn deny(principal: &str, selector: Selector) -> Grant {
        Grant {
            effect: Effect::Deny,
            ..Grant::implicit(principal, selector, Permission::Read)
        }
    }

    #[test]
    fn nothing_is_open_by_default() {
        let decision = decide(
            &[],
            &["u1"],
            &res("pages", "shared", "a"),
            Permission::Read,
            now(),
        );
        assert_eq!(decision, Decision::Denied(DenyReason::NoGrant));
    }

    #[test]
    fn a_prefix_matches_whole_segments_only() {
        let grants = [allow(
            "u1",
            sel("pages", "s", "coding/claude"),
            Permission::Read,
        )];
        let ok = |path: &str| {
            decide(
                &grants,
                &["u1"],
                &res("pages", "s", path),
                Permission::Read,
                now(),
            )
            .is_allowed()
        };
        assert!(ok("coding/claude"));
        assert!(ok("coding/claude/x/y"));
        assert!(!ok("coding/claudette"));
        assert!(!ok("coding/codex/x"));
        assert!(!ok("coding"));
    }

    #[test]
    fn permissions_are_ordered_and_a_deny_wins() {
        let grants = [
            allow("u1", sel("*", "s", ""), Permission::Write),
            deny("u1", sel("pages", "s", "secret")),
        ];
        let ask = |path: &str, permission| {
            decide(
                &grants,
                &["u1"],
                &res("pages", "s", path),
                permission,
                now(),
            )
        };
        assert!(ask("a", Permission::Read).is_allowed());
        assert!(ask("a", Permission::Write).is_allowed());
        assert!(!ask("a", Permission::Admin).is_allowed());
        assert_eq!(
            ask("secret/x", Permission::Read),
            Decision::Denied(DenyReason::ExplicitDeny)
        );
    }

    #[test]
    fn grants_of_other_principals_spaces_and_kinds_do_not_apply() {
        let grants = [
            allow("u2", sel("pages", "s", ""), Permission::Admin),
            allow("u1", sel("pages", "other", ""), Permission::Admin),
            allow("u1", sel("files", "s", ""), Permission::Admin),
        ];
        assert!(
            !decide(
                &grants,
                &["u1"],
                &res("pages", "s", "a"),
                Permission::Read,
                now()
            )
            .is_allowed()
        );
    }

    #[test]
    fn an_expired_grant_or_deny_stops_applying() {
        let past = Some(iso(now() - time::Duration::seconds(1)));
        let grants = [Grant {
            expires_at: past.clone(),
            ..allow("u1", sel("pages", "s", ""), Permission::Read)
        }];
        assert!(
            !decide(
                &grants,
                &["u1"],
                &res("pages", "s", "a"),
                Permission::Read,
                now()
            )
            .is_allowed()
        );
        let grants = [
            allow("u1", sel("pages", "s", ""), Permission::Read),
            Grant {
                expires_at: past,
                ..deny("u1", sel("pages", "s", ""))
            },
        ];
        assert!(
            decide(
                &grants,
                &["u1"],
                &res("pages", "s", "a"),
                Permission::Read,
                now()
            )
            .is_allowed()
        );
        let corrupt = Grant {
            expires_at: Some("not a time".to_owned()),
            ..allow("u1", sel("pages", "s", ""), Permission::Read)
        };
        assert!(!corrupt.is_live(now()), "an unreadable expiry fails closed");
    }

    #[test]
    fn a_credential_only_narrows() {
        let grants = [allow("u1", sel("pages", "s", ""), Permission::Write)];
        let scopes = [CredentialScope {
            selector: sel("pages", "s", "public"),
            permission: Permission::Read,
        }];
        let ask = |path: &str, permission, credential: Option<&[CredentialScope]>| {
            decide_with_credential(
                &grants,
                &["u1"],
                credential,
                &res("pages", "s", path),
                permission,
                now(),
            )
        };
        assert!(ask("public/a", Permission::Read, Some(&scopes)).is_allowed());
        assert_eq!(
            ask("public/a", Permission::Write, Some(&scopes)),
            Decision::Denied(DenyReason::CredentialScope)
        );
        assert!(!ask("private", Permission::Read, Some(&scopes)).is_allowed());
        assert!(!ask("public/a", Permission::Read, Some(&[])).is_allowed());
        assert!(ask("private", Permission::Write, None).is_allowed());
        // A credential wider than the grants reaches nothing more.
        let wide = [CredentialScope {
            selector: sel("*", "elsewhere", ""),
            permission: Permission::Admin,
        }];
        let elsewhere = decide_with_credential(
            &grants,
            &["u1"],
            Some(&wide),
            &res("pages", "elsewhere", "a"),
            Permission::Read,
            now(),
        );
        assert!(!elsewhere.is_allowed());
    }

    #[test]
    fn coverage_agrees_with_decide() {
        let grants = [
            allow("u1", sel("pages", "s", "a"), Permission::Read),
            allow("u1", sel("*", "s", "b/c"), Permission::Write),
            deny("u1", sel("pages", "s", "a/x")),
        ];
        let scopes = [CredentialScope {
            selector: sel("pages", "s", "a/y"),
            permission: Permission::Read,
        }];
        for credential in [None, Some(&scopes[..])] {
            let cover = coverage(
                &grants,
                &["u1"],
                credential,
                "pages",
                "s",
                Permission::Read,
                now(),
            );
            for path in [
                "a", "a/x", "a/x/1", "a/y", "a/y/z", "b", "b/c", "b/c/d", "z",
            ] {
                let decided = decide_with_credential(
                    &grants,
                    &["u1"],
                    credential,
                    &res("pages", "s", path),
                    Permission::Read,
                    now(),
                );
                assert_eq!(
                    cover.covers(&split_path(path)),
                    decided.is_allowed(),
                    "{path} with {credential:?}"
                );
            }
        }
    }

    #[test]
    fn only_an_admin_holder_may_grant_and_only_inside_what_they_hold() {
        let grants = [allow("u1", sel("pages", "s", "team"), Permission::Admin)];
        assert!(may_grant(
            &grants,
            &["u1"],
            &sel("pages", "s", "team/a"),
            now()
        ));
        assert!(may_grant(
            &grants,
            &["u1"],
            &sel("pages", "s", "team"),
            now()
        ));
        assert!(!may_grant(&grants, &["u1"], &sel("pages", "s", ""), now()));
        assert!(!may_grant(&grants, &["u1"], &sel("*", "s", "team"), now()));
        assert!(!may_grant(
            &grants,
            &["u2"],
            &sel("pages", "s", "team/a"),
            now()
        ));
        let writer = [allow("u1", sel("pages", "s", ""), Permission::Write)];
        assert!(!may_grant(&writer, &["u1"], &sel("pages", "s", "a"), now()));
        let fenced = [
            allow("u1", sel("pages", "s", ""), Permission::Admin),
            deny("u1", sel("pages", "s", "team/secret")),
        ];
        assert!(!may_grant(
            &fenced,
            &["u1"],
            &sel("pages", "s", "team"),
            now()
        ));
        assert!(may_grant(
            &fenced,
            &["u1"],
            &sel("pages", "s", "other"),
            now()
        ));
    }

    #[test]
    fn selectors_refuse_ambiguous_parts() {
        assert!(Selector::new("pages", "s", vec!["a/b".to_owned()]).is_err());
        assert!(Selector::new("pages", "s", vec![String::new()]).is_err());
        assert!(Selector::new("pages", "s", vec!["..".to_owned()]).is_err());
        assert!(Selector::new("pages", "a/b", Vec::new()).is_err());
        assert!(Selector::new("", "s", Vec::new()).is_err());
        assert!(Selector::new("pages", "s", vec!["a\nb".to_owned()]).is_err());
        assert_eq!(
            Resource::new("*", "s", Vec::new()),
            Err(InvalidSelector::WildcardResource)
        );
        assert_eq!(split_path("/a//b/"), vec!["a".to_owned(), "b".to_owned()]);
    }
}
