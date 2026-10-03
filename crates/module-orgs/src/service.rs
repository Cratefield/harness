//! The domain rules: who may do what, and in which order the writes go.
//!
//! Everything here is written against the `Database` port and nothing else —
//! no request, no header, no `Result<_, Problem>` — so the rules read as the
//! rules, and the routes above only translate.
//!
//! The writes that carry a rule ("is another owner left?", "may this actor
//! touch that row?") are single `batch_atomic`s from [`crate::store`], each
//! opening with the organization's row lock so the guard is judged against a
//! snapshot no concurrent writer is inside. `batch_atomic` reports no
//! affected-row count, so each of those calls reads the row back afterwards
//! and the read decides what happened — applied, refused, or gone. The
//! authority checks the routes pre-compute are the friendly answer for the
//! common case; the statement's own guard is what is authoritative.

use cratefield_core::{Database, ModuleContext, normalize_email};

use crate::clock;
use crate::handlers::Settings;
use crate::store;
use crate::{Member, Membership, Org, OrgsError};

/// The length caps a free-text field is held to. A value past its cap is a
/// `validation-failed` 400 before anything is read or written: a name, a
/// subject id or a token that long was never going to match.
pub(crate) const MAX_NAME_CHARS: usize = 100;
pub(crate) const MAX_SUB_CHARS: usize = 200;
pub(crate) const MAX_ROLE_CHARS: usize = 64;
pub(crate) const MAX_EMAIL_CHARS: usize = 254;
pub(crate) const MAX_TOKEN_CHARS: usize = 512;

/// Refuses a value longer than the field accepts.
fn within(field: &'static str, value: &str, max: usize) -> Result<(), OrgsError> {
    if value.chars().count() > max {
        return Err(OrgsError::TooLong { field, max });
    }
    Ok(())
}

/// Whether `role` is the owner role.
pub(crate) fn is_owner(role: &str) -> bool {
    role == store::OWNER
}

/// A role the venture configured, or a 422-shaped refusal. `owner` is always
/// in the set — the builder adds it — so it is never unknown.
fn check_role(settings: &Settings, role: &str) -> Result<(), OrgsError> {
    if settings.roles.iter().any(|known| known == role) {
        Ok(())
    } else {
        Err(OrgsError::UnknownRole(role.to_owned()))
    }
}

/// Whether a holder of `role` may manage members and invitations at all.
/// Owners always may; everyone else only when the venture named their role a
/// manager role.
pub(crate) fn may_manage(settings: &Settings, role: &str) -> bool {
    is_owner(role) || settings.managers.iter().any(|manager| manager == role)
}

fn org_of(row: store::OrgRow) -> Org {
    Org {
        id: row.id,
        name: row.name,
        created_by: row.created_by,
        created_at: row.created_at,
    }
}

fn member_of(row: store::MemberRow) -> Member {
    Member {
        sub: row.sub,
        role: row.role,
        invited_by: row.invited_by,
        joined_at: row.created_at,
    }
}

fn db(ctx: &ModuleContext) -> Result<&dyn Database, OrgsError> {
    ctx.ports
        .db
        .as_deref()
        .ok_or_else(|| OrgsError::Config("no database is mounted".to_owned()))
}

/// The caller's membership, or a `NotFound`. A non-member cannot tell an
/// organization that does not exist from one they are not in — which is the
/// point: the ids do not leak to a caller who has no business reading them.
pub(crate) async fn require_member(
    ctx: &ModuleContext,
    org_id: &str,
    sub: &str,
) -> Result<Member, OrgsError> {
    store::find_member(db(ctx)?, org_id, sub)
        .await?
        .map(member_of)
        .ok_or_else(|| OrgsError::NotFound(org_id.to_owned()))
}

/// The caller's membership when they may manage, and the two refusals that
/// are not the same: a member who may not manage is `Forbidden`, a non-member
/// is `NotFound` — the same answer as an organization that does not exist.
async fn require_manager(
    ctx: &ModuleContext,
    settings: &Settings,
    org_id: &str,
    actor: &str,
) -> Result<Member, OrgsError> {
    let member = require_member(ctx, org_id, actor).await?;
    if may_manage(settings, &member.role) {
        Ok(member)
    } else {
        Err(OrgsError::Forbidden(format!(
            "the `{}` role may not manage members of this organization",
            member.role
        )))
    }
}

/// Refuses a non-owner touching an owner's membership. An owner is never held
/// by this, and neither is a manager acting on anybody who is not an owner.
///
/// This is the friendly 403 for the obvious case; the guarded statement does
/// not rely on it, and a race it loses is still refused by the guard.
fn check_not_an_owner(actor: &Member, target: &Member) -> Result<(), OrgsError> {
    if !is_owner(&actor.role) && is_owner(&target.role) {
        return Err(OrgsError::Forbidden(
            "only the owner role may change an owner's membership".to_owned(),
        ));
    }
    Ok(())
}

/// Refuses a non-owner granting the owner role.
fn check_may_grant(authorised: bool, role: &str) -> Result<(), OrgsError> {
    if !authorised && is_owner(role) {
        return Err(OrgsError::Forbidden(
            "only an owner may grant the owner role".to_owned(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Organizations

/// Creates an organization and the creator's owner membership. The two rows
/// go in one `batch_atomic`, so there is no window in which an organization
/// exists that nobody owns — which the last-owner rule would then make
/// permanently unmanageable.
pub(crate) async fn create(ctx: &ModuleContext, owner: &str, name: &str) -> Result<Org, OrgsError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(OrgsError::InvalidName);
    }
    within("name", name, MAX_NAME_CHARS)?;
    let db = db(ctx)?;
    let at = clock::now(ctx);
    let id = clock::new_id(ctx);
    db.batch_atomic(&[
        store::insert_org_statement(&id, name, owner, &at),
        store::insert_member_statement(&id, owner, store::OWNER, None, &at),
    ])
    .await?;
    Ok(Org {
        id,
        name: name.to_owned(),
        created_by: owner.to_owned(),
        created_at: at,
    })
}

/// One page of the organizations `sub` belongs to, each with their role.
/// `after` is the `(created_at, id)` of the last row of the previous page.
pub(crate) async fn list(
    ctx: &ModuleContext,
    sub: &str,
    after: Option<(&str, &str)>,
    fetch: u64,
) -> Result<Vec<Membership>, OrgsError> {
    Ok(store::list_orgs_for(db(ctx)?, sub, after, fetch)
        .await?
        .into_iter()
        .map(|(org, role)| Membership {
            org: org_of(org),
            role,
        })
        .collect())
}

/// One organization, for a member.
pub(crate) async fn get(
    ctx: &ModuleContext,
    org_id: &str,
    sub: &str,
) -> Result<(Org, Member), OrgsError> {
    let member = require_member(ctx, org_id, sub).await?;
    let org = store::find_org(db(ctx)?, org_id)
        .await?
        .ok_or_else(|| OrgsError::NotFound(org_id.to_owned()))?;
    Ok((org_of(org), member))
}

/// One page of an organization's members, for a member. `after` is the
/// `(created_at, user_sub)` of the last row of the previous page.
pub(crate) async fn members(
    ctx: &ModuleContext,
    org_id: &str,
    sub: &str,
    after: Option<(&str, &str)>,
    fetch: u64,
) -> Result<Vec<Member>, OrgsError> {
    require_member(ctx, org_id, sub).await?;
    Ok(store::list_members(db(ctx)?, org_id, after, fetch)
        .await?
        .into_iter()
        .map(member_of)
        .collect())
}

/// The caller's role, or a `NotFound` when they are not a member.
pub(crate) async fn my_role(
    ctx: &ModuleContext,
    org_id: &str,
    sub: &str,
) -> Result<String, OrgsError> {
    Ok(require_member(ctx, org_id, sub).await?.role)
}

/// One page of every organization, oldest first — the admin listing.
pub(crate) async fn all_orgs(
    ctx: &ModuleContext,
    after: Option<(&str, &str)>,
    fetch: u64,
) -> Result<Vec<Org>, OrgsError> {
    Ok(store::list_all_orgs(db(ctx)?, after, fetch)
        .await?
        .into_iter()
        .map(org_of)
        .collect())
}

// ---------------------------------------------------------------------------
// Memberships

/// Adds a member. A manager may add; only an owner may add an owner.
///
/// The authority is settled before the role is looked at, so a stranger
/// sending nonsense is told they are not a member — 404 — rather than being
/// handed a validation answer about a request they were never entitled to
/// make.
pub(crate) async fn add_member(
    ctx: &ModuleContext,
    settings: &Settings,
    org_id: &str,
    actor: &str,
    sub: &str,
    role: &str,
) -> Result<Member, OrgsError> {
    let actor_member = require_manager(ctx, settings, org_id, actor).await?;
    check_may_grant(is_owner(&actor_member.role), role)?;
    check_role(settings, role)?;
    within("sub", sub, MAX_SUB_CHARS)?;
    within("role", role, MAX_ROLE_CHARS)?;
    let db = db(ctx)?;

    if let Some(existing) = store::find_member(db, org_id, sub).await? {
        // An owner's membership is not a manager's to touch, not even to
        // report that it already exists.
        check_not_an_owner(&actor_member, &member_of(existing))?;
        return Err(OrgsError::AlreadyMember(sub.to_owned()));
    }

    let at = clock::now(ctx);
    let changed = store::insert_member_once(db, org_id, sub, role, Some(actor), &at).await?;
    if changed == 0 {
        // Lost a race with another manager: the row is there, and it was
        // there before this call, so the answer is the same one a
        // read-then-write would have given.
        return Err(OrgsError::AlreadyMember(sub.to_owned()));
    }
    Ok(Member {
        sub: sub.to_owned(),
        role: role.to_owned(),
        invited_by: Some(actor.to_owned()),
        joined_at: at,
    })
}

/// Changes a member's role, through one guarded statement that also judges
/// the actor's authority and refuses to demote the last owner. The row is
/// read back to turn the statement's outcome into an answer.
pub(crate) async fn set_role(
    ctx: &ModuleContext,
    settings: &Settings,
    org_id: &str,
    actor: &str,
    sub: &str,
    role: &str,
) -> Result<Member, OrgsError> {
    let actor_member = require_manager(ctx, settings, org_id, actor).await?;
    let db = db(ctx)?;
    let target = store::find_member(db, org_id, sub)
        .await?
        .ok_or_else(|| OrgsError::NotFound(org_id.to_owned()))?;
    let target = member_of(target);
    check_not_an_owner(&actor_member, &target)?;
    check_may_grant(is_owner(&actor_member.role), role)?;
    check_role(settings, role)?;
    within("sub", sub, MAX_SUB_CHARS)?;
    within("role", role, MAX_ROLE_CHARS)?;

    db.batch_atomic(&store::update_role_statements(
        org_id,
        sub,
        role,
        actor,
        &settings.managers,
    ))
    .await?;

    match store::find_member(db, org_id, sub).await? {
        // The write took: the row now holds the role that was asked for.
        Some(now) if now.role == role => Ok(Member {
            role: role.to_owned(),
            ..member_of(now)
        }),
        // The write was refused. A demoted last owner is a conflict; anything
        // else the guard held on — the actor's authority moved under us — is
        // the same 403 the pre-checks would have given.
        Some(now) => {
            if is_owner(&now.role) && !is_owner(role) && store::count_owners(db, org_id).await? <= 1
            {
                Err(OrgsError::LastOwner)
            } else {
                Err(OrgsError::Forbidden(
                    "this change is not permitted for your role in this organization".to_owned(),
                ))
            }
        }
        // Gone between the pre-read and the write: the same 404 a caller
        // asking about a member who was never there gets.
        None => Err(OrgsError::NotFound(org_id.to_owned())),
    }
}

/// Removes a member, through one guarded statement that also judges the
/// actor's authority and refuses to remove the last owner.
///
/// Owners may remove anyone; a manager may not remove an owner, and nobody
/// may remove the last one. Leaving is not managing: a caller removing
/// themselves is held only by the last-owner guard.
pub(crate) async fn remove_member(
    ctx: &ModuleContext,
    settings: &Settings,
    org_id: &str,
    actor: &str,
    sub: &str,
) -> Result<(), OrgsError> {
    let db = db(ctx)?;
    if actor == sub {
        require_member(ctx, org_id, actor).await?;
    } else {
        let actor_member = require_manager(ctx, settings, org_id, actor).await?;
        // A member who is not there answers the same 404 an organization that
        // is not there does; an owner is not a manager's to remove, and that
        // 403 is the answer whether or not the owner is the last one.
        let target = store::find_member(db, org_id, sub)
            .await?
            .ok_or_else(|| OrgsError::NotFound(org_id.to_owned()))?;
        check_not_an_owner(&actor_member, &member_of(target))?;
    }

    db.batch_atomic(&store::remove_member_statements(
        org_id,
        sub,
        actor,
        &settings.managers,
    ))
    .await?;

    match store::find_member(db, org_id, sub).await? {
        // Gone: the delete took.
        None => Ok(()),
        // Still there. The guard that stopped the last owner leaving is a
        // conflict; anything else is the 403 the pre-checks would have given.
        Some(now) => {
            if is_owner(&now.role) && store::count_owners(db, org_id).await? <= 1 {
                Err(OrgsError::LastOwner)
            } else {
                Err(OrgsError::Forbidden(
                    "this removal is not permitted for your role in this organization".to_owned(),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Invitations

/// Mints an invitation and mails it. The raw token is never returned and never
/// stored: it goes into the mail, and the row keeps only its SHA-256, so a
/// database dump holds nothing that can be redeemed.
///
/// An invitation for a mailer that cannot send is deleted again, so a venture
/// without a sending domain does not accumulate invitations nobody can accept.
///
/// The authority is settled before the role is looked at, so a stranger is a
/// 404 rather than a validation answer.
pub(crate) async fn invite(
    ctx: &ModuleContext,
    settings: &Settings,
    org_id: &str,
    actor: &str,
    email: &str,
    role: &str,
) -> Result<(), OrgsError> {
    let actor_member = require_manager(ctx, settings, org_id, actor).await?;
    check_may_grant(is_owner(&actor_member.role), role)?;
    check_role(settings, role)?;
    within("role", role, MAX_ROLE_CHARS)?;
    within("email", email, MAX_EMAIL_CHARS)?;
    let org = store::find_org(db(ctx)?, org_id)
        .await?
        .ok_or_else(|| OrgsError::NotFound(org_id.to_owned()))?;

    let normalized = normalize_email(email);
    if !cratefield_core::is_valid(&normalized) {
        return Err(OrgsError::InvalidEmail(normalized));
    }

    let db = db(ctx)?;
    let at = clock::now(ctx);
    let token = clock::new_token(ctx);
    let id = clock::new_id(ctx);
    let expires_at = clock::plus_secs(&at, settings.invitation_ttl_secs);
    store::insert_invitation(
        db,
        &store::NewInvitation {
            id: &id,
            org_id,
            token_hash: &crate::sha256_hex(&token),
            email_hash: &crate::sha256_hex(&normalized),
            role,
            invited_by: actor,
            expires_at: &expires_at,
            now: &at,
        },
    )
    .await?;

    let mail = crate::mail::OutgoingInvitation {
        to: &normalized,
        org_name: &org.name,
        role,
        accept_url: &crate::mail::accept_url(ctx, &token),
        token: &token,
        idempotency_key: &format!("orgs-invite-{id}"),
        expires_in_days: (settings.invitation_ttl_secs / 86_400).max(1),
    };
    match crate::mail::send(ctx, &mail).await {
        Ok(()) => Ok(()),
        Err(error) => {
            // Nothing was delivered, so nothing can be accepted: drop the row
            // rather than leave an invitation that only a dump could spend.
            let _ = store::delete_invitation(db, &id).await;
            Err(error)
        }
    }
}

/// Accepts an invitation. The caller's **verified** address must be the one
/// invited, and the token is spent exactly once: a second `accept` finds the
/// row already stamped and answers the same "no longer valid" a stranger gets.
///
/// The spend and the membership it authorizes are one transaction, the
/// membership conditional on that same spend, so a failure between them
/// cannot burn the invitation without adding anybody.
pub(crate) async fn accept(
    ctx: &ModuleContext,
    settings: &Settings,
    token: &str,
    sub: &str,
    email: Option<&str>,
) -> Result<Org, OrgsError> {
    // Unverified is not the same as absent: the port carries an address only
    // when the credential proved it, and an invitation is addressed to a
    // proved address or to nobody.
    let Some(email) = email else {
        return Err(OrgsError::EmailUnverified);
    };
    within("token", token, MAX_TOKEN_CHARS)?;
    within("email", email, MAX_EMAIL_CHARS)?;
    let email = normalize_email(email);
    let db = db(ctx)?;
    let token_hash = crate::sha256_hex(token);
    let invitation = store::find_invitation(db, &token_hash)
        .await?
        .ok_or(OrgsError::InvitationGone)?;

    let at = clock::now(ctx);
    if invitation.accepted_at.is_some() || invitation.expires_at <= at {
        return Err(OrgsError::InvitationGone);
    }
    if !cratefield_core::constant_time_eq(
        crate::sha256_hex(&email).as_bytes(),
        invitation.email_hash.as_bytes(),
    ) {
        return Err(OrgsError::InvitationForSomeoneElse);
    }
    // The role the invitation offers is re-checked against the roles the
    // deployment serves *now*: a role that has since been dropped fails
    // closed rather than granting something nothing can hold.
    check_role(settings, &invitation.role)?;

    // One id names this spend. The guarded spend stamps it, and the membership
    // insert is conditional on it in the same transaction, so exactly one
    // caller adds anybody — the one that actually spent the token.
    let spend_id = clock::new_id(ctx);
    db.batch_atomic(&store::accept_statements(
        &invitation.org_id,
        sub,
        &invitation.role,
        &invitation.invited_by,
        &at,
        &token_hash,
        &spend_id,
    ))
    .await?;

    // Whether the spend is ours is the answer: a caller whose seed a
    // concurrent accept beat, or whose invitation lapsed first, sees somebody
    // else's id (or none) and gets the same 410 a stranger does.
    match store::find_invitation(db, &token_hash).await? {
        Some(row) if row.spend_id.as_deref() == Some(spend_id.as_str()) => {}
        _ => return Err(OrgsError::InvitationGone),
    }

    let org = store::find_org(db, &invitation.org_id)
        .await?
        .ok_or_else(|| OrgsError::NotFound(invitation.org_id.clone()))?;
    Ok(org_of(org))
}

// ---------------------------------------------------------------------------
// Housekeeping

/// Deletes invitations that have lapsed. Idempotent, so it is safe however
/// often the venture's cron fires. An accepted invitation is left until it
/// lapses: the row is what the accept path reads back, and it holds only
/// hashes.
pub(crate) async fn maintain(ctx: &ModuleContext) -> Result<(), OrgsError> {
    let at = clock::now(ctx);
    store::purge_invitations(db(ctx)?, &at).await?;
    Ok(())
}
