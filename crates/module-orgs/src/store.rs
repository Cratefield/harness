//! Sea-query access for the three orgs tables (issue #652).
//!
//! Every value is bound, never interpolated. Two concurrency rules live here.
//!
//! The first is per-organization serialization. A guarded write that counts
//! owners ("is another owner left?") would otherwise be write-skew under
//! Postgres `READ COMMITTED`: two owners leaving at once each count two and
//! both commit, leaving none. So every such write rides a [`batch_atomic`]
//! whose first statement takes the organization's row lock; each later
//! statement then begins on a snapshot taken *after* the lock, where the other
//! transaction's change is visible. The actor's own authority is read as a
//! correlated `EXISTS` inside the same statement, so "a manager may not touch
//! an owner" cannot be decided against a stale role either.
//!
//! The second is that an invitation is spent exactly once and its companion
//! membership rides the same transaction, keyed to that one spend.
//!
//! [`batch_atomic`] returns no affected-row count, so a caller tells "applied"
//! from "refused" by reading the row back — see `service`.

use cratefield_core::{Database, DbError, Row, Statement};
use sea_query::{
    Alias, Condition, Expr, JoinType, OnConflict, Order, Query, SelectStatement, SimpleExpr,
};

pub(crate) const ORGS: &str = "orgs";
pub(crate) const MEMBERS: &str = "org_members";
pub(crate) const INVITATIONS: &str = "org_invitations";

/// The one role that is always in the role set and is never allowed to be
/// removed, demoted or left behind as the last of its kind.
pub(crate) const OWNER: &str = "owner";

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// The last-owner guard, as a `WHERE` fragment: an owner row may be changed
/// only while another owner remains. Non-owner rows are never held by it.
///
/// The correlated `COUNT(*)` names `org_members` unqualified on purpose —
/// it is the table the enclosing `UPDATE`/`DELETE` already names, so the
/// reference is the row being changed.
fn another_owner_remains() -> SimpleExpr {
    Expr::cust(format!(
        "(SELECT COUNT(*) FROM {MEMBERS} m WHERE m.org_id = {MEMBERS}.org_id \
             AND m.role = '{OWNER}') > 1"
    ))
}

/// Correlates an `EXISTS` subquery to the row the enclosing write is against,
/// so the actor's role is read from *this* organization and in the same
/// snapshot as the write it authorizes.
fn actor_member_select(actor: &str) -> SelectStatement {
    let actor_member = Alias::new("actor_member");
    let mut select = Query::select();
    select
        .expr(Expr::val(1))
        .from_as(iden(MEMBERS), actor_member.clone())
        .and_where(
            Expr::col((actor_member.clone(), iden("org_id")))
                .eq(Expr::col((MEMBERS, iden("org_id")))),
        )
        .and_where(Expr::col((actor_member, iden("user_sub"))).eq(actor));
    select
}

/// `EXISTS (…)` — the actor holds, in this organization, a role that may
/// manage members. Owners always may; a venture's manager roles also do.
fn actor_may_manage(actor: &str, managers: &[String]) -> SimpleExpr {
    let mut roles: Vec<&str> = managers.iter().map(String::as_str).collect();
    if !managers.iter().any(|role| role == OWNER) {
        roles.push(OWNER);
    }
    let mut select = actor_member_select(actor);
    select.and_where(Expr::col((Alias::new("actor_member"), iden("role"))).is_in(roles));
    Expr::exists(select)
}

/// `EXISTS (…)` — the actor is this organization's owner.
fn actor_is_owner(actor: &str) -> SimpleExpr {
    let mut select = actor_member_select(actor);
    select.and_where(Expr::col((Alias::new("actor_member"), iden("role"))).eq(OWNER));
    Expr::exists(select)
}

/// Takes the organization's row lock for the rest of a `batch_atomic`. The
/// write is a deliberate no-op: the row already holds these values, and the
/// only thing asked of it is the lock, so every later statement in the batch
/// runs on a snapshot taken after any concurrent writer on this organization
/// has committed or rolled back.
pub(crate) fn lock_org_statement(org_id: &str) -> Statement {
    Statement::with_values("UPDATE orgs SET id = id WHERE id = ?", vec![org_id.into()])
}

// ---------------------------------------------------------------------------
// Organizations

/// One organization row.
pub(crate) struct OrgRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) created_by: String,
    pub(crate) created_at: String,
}

const ORG_COLUMNS: [&str; 4] = ["id", "name", "created_by", "created_at"];

fn org_from(row: &Row) -> OrgRow {
    OrgRow {
        id: row.get("id").unwrap_or_default(),
        name: row.get("name").unwrap_or_default(),
        created_by: row.get("created_by").unwrap_or_default(),
        created_at: row.get("created_at").unwrap_or_default(),
    }
}

/// The insert for a freshly created organization, as a `Statement` so it can
/// ride the same `batch_atomic` as the creator's owner membership: the two
/// always appear together, or neither does.
pub(crate) fn insert_org_statement(id: &str, name: &str, created_by: &str, now: &str) -> Statement {
    let mut insert = Query::insert();
    insert
        .into_table(iden(ORGS))
        .columns(["id", "name", "created_by", "created_at"])
        .values_panic([id.into(), name.into(), created_by.into(), now.into()]);
    Statement::render(&insert)
}

/// One organization by id.
pub(crate) async fn find_org(db: &dyn Database, id: &str) -> Result<Option<OrgRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(ORG_COLUMNS)
        .from(iden(ORGS))
        .and_where(Expr::col(iden("id")).eq(id));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(org_from))
}

/// How many owners an organization has. Read after a guarded write was
/// refused, to tell the last owner apart from a refusal the actor's role
/// caused.
pub(crate) async fn count_owners(db: &dyn Database, org_id: &str) -> Result<i64, DbError> {
    let mut select = Query::select();
    select
        .expr_as(Expr::col(iden("user_sub")).count(), iden("n"))
        .from(iden(MEMBERS))
        .and_where(Expr::col(iden("org_id")).eq(org_id))
        .and_where(Expr::col(iden("role")).eq(OWNER));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .and_then(|row| row.get("n"))
        .unwrap_or(0))
}

/// A keyset page for organizations, oldest first, tie-broken on id so the
/// `(created_at, id)` pair the cursor carries is unique.
fn org_page_cursor(select: &mut sea_query::SelectStatement, after: Option<(&str, &str)>) {
    if let Some((at, id)) = after {
        select.cond_where(
            Condition::any()
                .add(Expr::col((iden(ORGS), iden("created_at"))).gt(at))
                .add(
                    Condition::all()
                        .add(Expr::col((iden(ORGS), iden("created_at"))).eq(at))
                        .add(Expr::col((iden(ORGS), iden("id"))).gt(id)),
                ),
        );
    }
}

/// A page of every organization, oldest first — the admin listing.
pub(crate) async fn list_all_orgs(
    db: &dyn Database,
    after: Option<(&str, &str)>,
    fetch: u64,
) -> Result<Vec<OrgRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(ORG_COLUMNS)
        .from(iden(ORGS))
        .order_by(iden("created_at"), Order::Asc)
        .order_by(iden("id"), Order::Asc)
        .limit(fetch);
    org_page_cursor(&mut select, after);
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(org_from)
        .collect())
}

/// A page of the organizations `sub` belongs to, each with the role they hold
/// there, oldest first.
pub(crate) async fn list_orgs_for(
    db: &dyn Database,
    sub: &str,
    after: Option<(&str, &str)>,
    fetch: u64,
) -> Result<Vec<(OrgRow, String)>, DbError> {
    let mut select = Query::select();
    select
        .expr_as(Expr::col((iden(ORGS), iden("id"))), iden("id"))
        .expr_as(Expr::col((iden(ORGS), iden("name"))), iden("name"))
        .expr_as(
            Expr::col((iden(ORGS), iden("created_by"))),
            iden("created_by"),
        )
        .expr_as(
            Expr::col((iden(ORGS), iden("created_at"))),
            iden("created_at"),
        )
        .expr_as(Expr::col((iden(MEMBERS), iden("role"))), iden("role"))
        .from(iden(ORGS))
        .join(
            JoinType::InnerJoin,
            iden(MEMBERS),
            Expr::col((iden(MEMBERS), iden("org_id"))).equals((iden(ORGS), iden("id"))),
        )
        .and_where(Expr::col((iden(MEMBERS), iden("user_sub"))).eq(sub))
        .order_by((iden(ORGS), iden("created_at")), Order::Asc)
        .order_by((iden(ORGS), iden("id")), Order::Asc)
        .limit(fetch);
    if let Some((at, id)) = after {
        select.cond_where(
            Condition::any()
                .add(Expr::col((iden(ORGS), iden("created_at"))).gt(at))
                .add(
                    Condition::all()
                        .add(Expr::col((iden(ORGS), iden("created_at"))).eq(at))
                        .add(Expr::col((iden(ORGS), iden("id"))).gt(id)),
                ),
        );
    }
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(|row| (org_from(row), row.get("role").unwrap_or_default()))
        .collect())
}

// ---------------------------------------------------------------------------
// Memberships

/// One membership row.
pub(crate) struct MemberRow {
    pub(crate) sub: String,
    pub(crate) role: String,
    pub(crate) invited_by: Option<String>,
    pub(crate) created_at: String,
}

fn member_from(row: &Row) -> MemberRow {
    MemberRow {
        sub: row.get("user_sub").unwrap_or_default(),
        role: row.get("role").unwrap_or_default(),
        invited_by: row.get("invited_by"),
        created_at: row.get("created_at").unwrap_or_default(),
    }
}

/// The insert for a member, unconditional, for the create batch — where the
/// creator cannot already be a member of an organization that did not exist a
/// statement ago.
pub(crate) fn insert_member_statement(
    org_id: &str,
    sub: &str,
    role: &str,
    invited_by: Option<&str>,
    now: &str,
) -> Statement {
    let mut insert = Query::insert();
    insert
        .into_table(iden(MEMBERS))
        .columns(["org_id", "user_sub", "role", "invited_by", "created_at"])
        .values_panic([
            org_id.into(),
            sub.into(),
            role.into(),
            invited_by.into(),
            now.into(),
        ]);
    Statement::render(&insert)
}

/// Adds a member only when they are not one already: one row means inserted,
/// zero means they were already there. `ON CONFLICT DO NOTHING` on the
/// `(org_id, user_sub)` primary key is the race-safe "insert if absent" and
/// renders identically on both dialects (ADR 0004).
pub(crate) async fn insert_member_once(
    db: &dyn Database,
    org_id: &str,
    sub: &str,
    role: &str,
    invited_by: Option<&str>,
    now: &str,
) -> Result<u64, DbError> {
    db.execute(&insert_member_once_statement(
        org_id, sub, role, invited_by, now,
    ))
    .await
}

/// The "insert if absent" as a `Statement`, so the accept path can ride it on
/// the same `batch_atomic` as the spend it depends on.
pub(crate) fn insert_member_once_statement(
    org_id: &str,
    sub: &str,
    role: &str,
    invited_by: Option<&str>,
    now: &str,
) -> Statement {
    let mut insert = Query::insert();
    insert
        .into_table(iden(MEMBERS))
        .columns(["org_id", "user_sub", "role", "invited_by", "created_at"])
        .values_panic([
            org_id.into(),
            sub.into(),
            role.into(),
            invited_by.into(),
            now.into(),
        ])
        .on_conflict(
            OnConflict::columns([iden("org_id"), iden("user_sub")])
                .do_nothing()
                .to_owned(),
        );
    Statement::render(&insert)
}

/// One membership by org and subject.
pub(crate) async fn find_member(
    db: &dyn Database,
    org_id: &str,
    sub: &str,
) -> Result<Option<MemberRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(["user_sub", "role", "invited_by", "created_at"])
        .from(iden(MEMBERS))
        .and_where(Expr::col(iden("org_id")).eq(org_id))
        .and_where(Expr::col(iden("user_sub")).eq(sub));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(member_from))
}

/// One page of an organization's members, oldest first, tie-broken on the
/// subject so the cursor's `(created_at, user_sub)` pair is unique.
pub(crate) async fn list_members(
    db: &dyn Database,
    org_id: &str,
    after: Option<(&str, &str)>,
    fetch: u64,
) -> Result<Vec<MemberRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(["user_sub", "role", "invited_by", "created_at"])
        .from(iden(MEMBERS))
        .and_where(Expr::col(iden("org_id")).eq(org_id))
        .order_by(iden("created_at"), sea_query::Order::Asc)
        .order_by(iden("user_sub"), sea_query::Order::Asc)
        .limit(fetch);
    if let Some((at, sub)) = after {
        select.cond_where(
            Condition::any()
                .add(Expr::col(iden("created_at")).gt(at))
                .add(
                    Condition::all()
                        .add(Expr::col(iden("created_at")).eq(at))
                        .add(Expr::col(iden("user_sub")).gt(sub)),
                ),
        );
    }
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .rows
        .iter()
        .map(member_from)
        .collect())
}

/// The batch that changes a member's role: the organization's row lock, then
/// the update.
///
/// The update carries three conditions, all evaluated in the locked snapshot.
/// The actor must be a manager of this organization; an owner's row may be
/// touched only by an owner; and demoting the last owner is refused. Granting
/// the owner role is the owner's alone.
pub(crate) fn update_role_statements(
    org_id: &str,
    sub: &str,
    role: &str,
    actor: &str,
    managers: &[String],
) -> [Statement; 2] {
    let mut update = Query::update();
    update
        .table(iden(MEMBERS))
        .value(iden("role"), role)
        .and_where(Expr::col(iden("org_id")).eq(org_id))
        .and_where(Expr::col(iden("user_sub")).eq(sub))
        .cond_where(actor_may_manage(actor, managers))
        .cond_where(
            Condition::any()
                .add(Expr::col(iden("role")).ne(OWNER))
                .add(actor_is_owner(actor)),
        )
        .cond_where(
            Condition::any()
                .add(Expr::col(iden("role")).ne(OWNER))
                .add(Expr::col(iden("role")).eq(role))
                .add(another_owner_remains()),
        );
    if role == OWNER {
        update.cond_where(actor_is_owner(actor));
    }
    [lock_org_statement(org_id), Statement::render(&update)]
}

/// The batch that removes a member: the organization's row lock, then the
/// delete.
///
/// Nobody may remove the last owner, including themselves. Removing somebody
/// else is managing, and an owner's membership is the owner's alone to touch;
/// leaving is not managing, so a caller removing themselves is held only by
/// the last-owner guard.
pub(crate) fn remove_member_statements(
    org_id: &str,
    sub: &str,
    actor: &str,
    managers: &[String],
) -> [Statement; 2] {
    let mut delete = Query::delete();
    delete
        .from_table(iden(MEMBERS))
        .and_where(Expr::col(iden("org_id")).eq(org_id))
        .and_where(Expr::col(iden("user_sub")).eq(sub))
        .cond_where(
            Condition::any()
                .add(Expr::col(iden("role")).ne(OWNER))
                .add(another_owner_remains()),
        );
    if actor != sub {
        delete.cond_where(
            Condition::all().add(actor_may_manage(actor, managers)).add(
                Condition::any()
                    .add(Expr::col(iden("role")).ne(OWNER))
                    .add(actor_is_owner(actor)),
            ),
        );
    }
    [lock_org_statement(org_id), Statement::render(&delete)]
}

// ---------------------------------------------------------------------------
// Invitations

/// One invitation row, as the accept path needs it. The token and the
/// address reach it only as hashes, and neither `id` nor `created_at` is read
/// here: the spend is keyed on `token_hash`, the deadline on `expires_at`, and
/// the "who spent it" question on `spend_id`.
pub(crate) struct InvitationRow {
    pub(crate) org_id: String,
    pub(crate) email_hash: String,
    pub(crate) role: String,
    pub(crate) invited_by: String,
    pub(crate) expires_at: String,
    pub(crate) accepted_at: Option<String>,
    pub(crate) spend_id: Option<String>,
}

const INVITATION_COLUMNS: [&str; 7] = [
    "org_id",
    "email_hash",
    "role",
    "invited_by",
    "expires_at",
    "accepted_at",
    "spend_id",
];

fn invitation_from(row: &Row) -> InvitationRow {
    InvitationRow {
        org_id: row.get("org_id").unwrap_or_default(),
        email_hash: row.get("email_hash").unwrap_or_default(),
        role: row.get("role").unwrap_or_default(),
        invited_by: row.get("invited_by").unwrap_or_default(),
        expires_at: row.get("expires_at").unwrap_or_default(),
        accepted_at: row.get("accepted_at"),
        spend_id: row.get("spend_id"),
    }
}

/// One invitation to insert. `token_hash` is the primary key the single-use
/// spend is keyed on, so it is `UNIQUE`.
pub(crate) struct NewInvitation<'a> {
    pub(crate) id: &'a str,
    pub(crate) org_id: &'a str,
    pub(crate) token_hash: &'a str,
    pub(crate) email_hash: &'a str,
    pub(crate) role: &'a str,
    pub(crate) invited_by: &'a str,
    pub(crate) expires_at: &'a str,
    pub(crate) now: &'a str,
}

pub(crate) async fn insert_invitation(
    db: &dyn Database,
    invitation: &NewInvitation<'_>,
) -> Result<u64, DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden(INVITATIONS))
        .columns([
            "id",
            "org_id",
            "token_hash",
            "email_hash",
            "role",
            "invited_by",
            "expires_at",
            "created_at",
        ])
        .values_panic([
            invitation.id.into(),
            invitation.org_id.into(),
            invitation.token_hash.into(),
            invitation.email_hash.into(),
            invitation.role.into(),
            invitation.invited_by.into(),
            invitation.expires_at.into(),
            invitation.now.into(),
        ]);
    db.execute(&Statement::render(&insert)).await
}

/// One invitation by the hash of the token the mail carried.
pub(crate) async fn find_invitation(
    db: &dyn Database,
    token_hash: &str,
) -> Result<Option<InvitationRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(INVITATION_COLUMNS)
        .from(iden(INVITATIONS))
        .and_where(Expr::col(iden("token_hash")).eq(token_hash));
    Ok(db
        .query(&Statement::render(&select))
        .await?
        .first()
        .map(invitation_from))
}

/// The spend and the membership it authorizes, in one transaction.
///
/// The spend stamps `accepted_at` (the moment) and `spend_id` (which accept
/// call spent it) exactly once: an unaccepted, unexpired invitation is claimed
/// by the first caller to match. The membership insert then rides *after* the
/// spend in the same transaction and is conditional on that same `spend_id`,
/// so a caller whose spend did not happen — a replay, or an invitation a
/// concurrent accept or purge took first — adds nobody. The insert stays
/// idempotent through `ON CONFLICT DO NOTHING`, so the one person who can
/// accept (the proved address on the invitation) gets exactly one membership
/// however many times they race themselves.
pub(crate) fn accept_statements(
    org_id: &str,
    sub: &str,
    role: &str,
    invited_by: &str,
    now: &str,
    token_hash: &str,
    spend_id: &str,
) -> [Statement; 2] {
    let mut spend = Query::update();
    spend
        .table(iden(INVITATIONS))
        .value(iden("accepted_at"), now)
        .value(iden("spend_id"), spend_id)
        .and_where(Expr::col(iden("token_hash")).eq(token_hash))
        .and_where(Expr::col(iden("accepted_at")).is_null())
        .and_where(Expr::col(iden("expires_at")).gt(now));

    // A `SELECT … WHERE …` before `ON CONFLICT` is exactly the shape SQLite
    // asks for, so the upsert is not read as a join's `ON`.
    let member = Statement::with_values(
        format!(
            "INSERT INTO {MEMBERS} (org_id, user_sub, role, invited_by, created_at) \
             SELECT ?, ?, ?, ?, ? WHERE EXISTS \
                 (SELECT 1 FROM {INVITATIONS} WHERE spend_id = ?) \
             ON CONFLICT (org_id, user_sub) DO NOTHING"
        ),
        vec![
            org_id.into(),
            sub.into(),
            role.into(),
            invited_by.into(),
            now.into(),
            spend_id.into(),
        ],
    );

    [Statement::render(&spend), member]
}

/// Removes an invitation that was created but never delivered — the rollback
/// for a mailer that is not configured, so no dangling row is left behind.
pub(crate) async fn delete_invitation(db: &dyn Database, id: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(INVITATIONS))
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&delete)).await
}

/// Deletes every invitation past its expiry. An accepted invitation is kept
/// until then: it is what the accept path reads back to tell the caller who
/// spent the token from a caller whose spend a concurrent accept beat, and it
/// holds nothing but hashes. Idempotent, and safe to run as often as the
/// venture's cron fires.
pub(crate) async fn purge_invitations(db: &dyn Database, now: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(INVITATIONS))
        .and_where(Expr::col(iden("expires_at")).lte(now));
    db.execute(&Statement::render(&delete)).await
}
