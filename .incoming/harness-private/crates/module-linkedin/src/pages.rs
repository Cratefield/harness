//! The page directory (issue #10): which pages this connection can post to,
//! and which of them are showcase pages.
//!
//! Cached deliberately. The Development Tier allows 500 requests a day, so no
//! route asks LinkedIn "what pages exist"; the sync writes the table and every
//! read serves it.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use factory0_core::{ModuleContext, Problem, Scope};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::client::{Client, Organization};
use crate::handlers::{self, EVENT_PAGES_SYNCED, ListQuery, ModuleState, Settings};
use crate::store::{self, PageRow};
use crate::tokens::{self, TokenTrouble};

/// Roles that can publish an organic post. `DIRECT_SPONSORED_CONTENT_POSTER`
/// is deliberately not one of them: it is scoped to direct sponsored content,
/// and it is enough to upload an image but not to put a post in the feed.
/// (The Posts API spells the second one `CONTENT_ADMIN`; the ACL API returns
/// `CONTENT_ADMINISTRATOR`, and this matches what the ACL API returns.)
const ORGANIC_ROLES: [&str; 2] = ["ADMINISTRATOR", "CONTENT_ADMINISTRATOR"];

/// Roles worth keeping in the directory at all.
const USEFUL_ROLES: [&str; 3] = [
    "ADMINISTRATOR",
    "CONTENT_ADMINISTRATOR",
    "DIRECT_SPONSORED_CONTENT_POSTER",
];

const KIND_COMPANY: &str = "company";
const KIND_SHOWCASE: &str = "showcase";
const KIND_SCHOOL: &str = "school";

/// How many ACL pages to walk before giving up. 10 x 50 is far more pages
/// than a Factory Zero account will ever administer, and it bounds the
/// request spend of one sync.
const MAX_ACL_PAGES: u32 = 10;
const ACL_PAGE_SIZE: u32 = 50;
const ORG_BATCH: usize = 20;

/// Walks every page of the member's ACLs, keeping the best role per
/// organization. The organization arrives under `organizationTarget` in some
/// responses and `organization` in others; the client reads both.
///
/// Returns the roles and the member's own URN, which arrives here for free.
async fn collect_roles(
    client: &Client<'_>,
) -> Result<(BTreeMap<String, String>, Option<String>), TokenTrouble> {
    let mut best_role: BTreeMap<String, String> = BTreeMap::new();
    let mut person_urn: Option<String> = None;
    let mut start = 0;

    for _ in 0..MAX_ACL_PAGES {
        let (entries, has_more) = client
            .member_acls(start, ACL_PAGE_SIZE)
            .await
            .map_err(TokenTrouble::Upstream)?;
        let empty = entries.is_empty();
        for entry in entries {
            if person_urn.is_none() {
                person_urn.clone_from(&entry.role_assignee);
            }
            if !USEFUL_ROLES.contains(&entry.role.as_str()) {
                continue;
            }
            let Some(org_id) = crate::urn::page_id(&entry.organization_urn) else {
                continue;
            };
            // A member can hold several roles on one page. Keep the one that
            // can actually publish.
            best_role
                .entry(org_id)
                .and_modify(|existing| {
                    if !ORGANIC_ROLES.contains(&existing.as_str())
                        && ORGANIC_ROLES.contains(&entry.role.as_str())
                    {
                        existing.clone_from(&entry.role);
                    }
                })
                .or_insert(entry.role);
        }
        if !has_more || empty {
            break;
        }
        start += ACL_PAGE_SIZE;
    }
    Ok((best_role, person_urn))
}

/// Organization details in batches, plus the showcase pages hanging off each
/// company page. A 403 on one id inside a batch is normal and must not lose
/// the rest: the client reads `results` and ignores `errors`.
async fn look_up(client: &Client<'_>, ids: &[String]) -> Result<Vec<Organization>, TokenTrouble> {
    let mut organizations: Vec<Organization> = Vec::new();
    for chunk in ids.chunks(ORG_BATCH) {
        organizations.extend(
            client
                .organizations(chunk)
                .await
                .map_err(TokenTrouble::Upstream)?,
        );
    }

    let parents: Vec<String> = organizations
        .iter()
        .filter(|organization| kind_of(&organization.primary_type) == KIND_COMPANY)
        .map(|organization| organization.id.clone())
        .collect();
    for parent in parents {
        let found = client
            .organizations_by_parent(&format!("urn:li:organization:{parent}"))
            .await
            .map_err(TokenTrouble::Upstream)?;
        for showcase in found {
            if !organizations.iter().any(|known| known.id == showcase.id) {
                organizations.push(showcase);
            }
        }
    }
    Ok(organizations)
}

#[derive(Debug, Default)]
pub(crate) struct SyncOutcome {
    pub pages: usize,
    pub showcases: usize,
    pub revoked: u64,
}

fn kind_of(primary_type: &str) -> &'static str {
    match primary_type {
        "BRAND" => KIND_SHOWCASE,
        "SCHOOL" => KIND_SCHOOL,
        _ => KIND_COMPANY,
    }
}

/// Rebuilds the directory from LinkedIn. Safe to run often; it is one ACL
/// walk plus a batch lookup per 20 organizations.
pub(crate) async fn sync(
    ctx: &ModuleContext,
    settings: &Settings,
    scope: &Scope,
) -> Result<SyncOutcome, TokenTrouble> {
    let db = handlers::db(ctx).map_err(|_| TokenTrouble::Config("no database".to_owned()))?;
    let clock = handlers::clock(ctx).map_err(|_| TokenTrouble::Config("no clock".to_owned()))?;
    let http =
        handlers::http(ctx).map_err(|_| TokenTrouble::Config("no http client".to_owned()))?;
    let id_gen = handlers::id_gen(ctx).map_err(|_| TokenTrouble::Config("no id gen".to_owned()))?;

    let session = tokens::session(ctx, settings, scope).await?;
    let client = Client::new(http, &settings.api_version, &session.access_token);
    let outcome = sync_with(ctx, db, clock, id_gen, &client, &session.account_id, scope).await;
    handlers::flush_budget(ctx, client.spent()).await;
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn sync_with(
    ctx: &ModuleContext,
    db: &dyn factory0_core::Database,
    clock: &dyn factory0_core::Clock,
    id_gen: &dyn factory0_core::IdGen,
    client: &Client<'_>,
    account_id: &str,
    scope: &Scope,
) -> Result<SyncOutcome, TokenTrouble> {
    let now = store::now_iso(clock);

    let (best_role, person_urn) = collect_roles(client).await?;

    // The person URN comes free with the ACL listing, which is why the module
    // asks for no OIDC scopes.
    if let Some(person) = person_urn.as_deref()
        && !person.is_empty()
    {
        store::set_person_urn(db, account_id, person, &now).await?;
    }

    let ids: Vec<String> = best_role.keys().cloned().collect();
    let organizations = look_up(client, &ids).await?;

    // 4. Write the directory.
    let mut outcome = SyncOutcome::default();
    for organization in &organizations {
        let kind = kind_of(&organization.primary_type);
        if kind == KIND_SHOWCASE {
            outcome.showcases += 1;
        }
        // A showcase discovered through its parent but absent from the ACL
        // listing is not one we know we can post to: a role on the parent is
        // not a role on the showcase. Record it, refuse to post to it, and
        // let the next sync promote it when the ACL says so.
        let role = best_role
            .get(&organization.id)
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        let can_post_organic = ORGANIC_ROLES.contains(&role.as_str());
        store::upsert_page(
            db,
            &PageRow {
                id: id_gen.ulid(),
                account_id: account_id.to_owned(),
                org_id: organization.id.clone(),
                urn: format!("urn:li:organization:{}", organization.id),
                name: organization.name.clone(),
                vanity_name: organization.vanity_name.clone(),
                kind: kind.to_owned(),
                parent_org_id: organization.parent_org_id.clone(),
                role,
                can_post_organic,
                state: store::PAGE_ACTIVE.to_owned(),
                logo_urn: organization.logo_urn.clone(),
                synced_at: now.clone(),
            },
        )
        .await?;
        outcome.pages += 1;
    }

    // Anything this pass did not touch has lost its role.
    outcome.revoked = store::revoke_pages_not_synced(db, account_id, &now).await?;

    ctx.events.emit_in(
        scope,
        EVENT_PAGES_SYNCED,
        json!({
            "pages": outcome.pages,
            "showcases": outcome.showcases,
            "revoked": outcome.revoked,
        }),
    );
    Ok(outcome)
}

pub(crate) async fn sync_route(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let settings = state.settings();
    match sync(state.ctx.as_ref(), &settings, &scope).await {
        Ok(outcome) => Ok(handlers::ok(json!({
            "pages": outcome.pages,
            "showcases": outcome.showcases,
            "revoked": outcome.revoked,
        }))),
        Err(trouble) => Err(trouble.problem(&scope)),
    }
}

pub(crate) async fn list(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Response, Problem> {
    handlers::admin(&state, &headers)?;
    let db = handlers::db(state.ctx.as_ref())?;

    let kind = match query.kind.as_deref() {
        None => None,
        Some(kind @ (KIND_COMPANY | KIND_SHOWCASE | KIND_SCHOOL)) => Some(kind),
        Some(other) => {
            return Err(Problem::validation_failed(format!(
                "kind must be one of company, showcase, school; got {other:?}"
            )));
        }
    };

    let pages = store::list_pages(db, kind).await.map_err(|error| {
        tracing::error!(error = %error, "could not list linkedin pages");
        handlers::internal(&scope)
    })?;
    Ok(handlers::ok(json!({
        "pages": pages.iter().map(handlers::page_json).collect::<Vec<_>>(),
    })))
}

/// The page a write is aimed at, resolved from any accepted spelling and
/// checked for a role that can actually publish.
pub(crate) async fn require_postable(
    db: &dyn factory0_core::Database,
    org: &str,
) -> Result<PageRow, Problem> {
    let org_id = crate::urn::page_id(org).ok_or_else(|| {
        Problem::validation_failed(
            "the page must be an organization id, urn:li:organization:{id}, or \
             urn:li:organizationBrand:{id}",
        )
    })?;
    let page = store::find_page(db, &org_id)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not read the linkedin page");
            Problem::internal()
        })?
        .ok_or_else(|| {
            Problem::new(&handlers::PAGE_ROLE_MISSING).with_detail(
                "that page is not in the directory; run POST /v1/linkedin/admin/pages/sync",
            )
        })?;

    if page.state != store::PAGE_ACTIVE {
        return Err(Problem::new(&handlers::PAGE_ROLE_MISSING)
            .with_detail("the connected account no longer holds a role on that page"));
    }
    if !page.can_post_organic {
        return Err(
            Problem::new(&handlers::PAGE_ROLE_MISSING).with_detail(format!(
                "the connected account holds {} on that page, which cannot publish organic posts",
                page.role
            )),
        );
    }
    Ok(page)
}

/// The page an upload is aimed at. Image upload only needs admin or DSC
/// rights, so this is deliberately looser than [`require_postable`].
pub(crate) async fn require_known(
    db: &dyn factory0_core::Database,
    org: &str,
) -> Result<PageRow, Problem> {
    let org_id = crate::urn::page_id(org).ok_or_else(|| {
        Problem::validation_failed(
            "the page must be an organization id, urn:li:organization:{id}, or \
             urn:li:organizationBrand:{id}",
        )
    })?;
    store::find_page(db, &org_id)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "could not read the linkedin page");
            Problem::internal()
        })?
        .filter(|page| page.state == store::PAGE_ACTIVE)
        .ok_or_else(|| {
            Problem::new(&handlers::PAGE_ROLE_MISSING)
                .with_detail("that page is not in the directory, or the role was revoked")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_type_decides_the_kind() {
        assert_eq!(kind_of("BRAND"), KIND_SHOWCASE);
        assert_eq!(kind_of("SCHOOL"), KIND_SCHOOL);
        assert_eq!(kind_of("NONE"), KIND_COMPANY);
        assert_eq!(kind_of(""), KIND_COMPANY);
    }

    #[test]
    fn only_admin_and_content_admin_may_publish() {
        assert!(ORGANIC_ROLES.contains(&"ADMINISTRATOR"));
        assert!(ORGANIC_ROLES.contains(&"CONTENT_ADMINISTRATOR"));
        assert!(!ORGANIC_ROLES.contains(&"DIRECT_SPONSORED_CONTENT_POSTER"));
        assert!(USEFUL_ROLES.contains(&"DIRECT_SPONSORED_CONTENT_POSTER"));
    }
}
