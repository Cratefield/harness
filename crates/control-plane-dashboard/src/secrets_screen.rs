//! The secrets manager screen: the page the secrets layer was missing.
//!
//! Everything else in `cratefield-secrets` — envelope encryption, the
//! AAD binding, the hash-chained audit log, DEK rotation and re-wrap —
//! is built and tested, and until this file existed no control-plane
//! page showed any of it. The product held customers' credentials and
//! offered no way to see what it held.
//!
//! One rule outranks every feature here: **the page never reads a secret
//! value.** There is no view-value control, no reveal, no copy button,
//! no masked-but-present field, and no code path from this screen to
//! [`SecretStore::get`]. A value travels inbound only, in the body of
//! the set-a-secret POST, and dies in the same request. The audit trail
//! holds no values by construction and this screen keeps it that way.
//!
//! [`SecretStore::get`]: cratefield_secrets::SecretStore::get

use std::sync::Arc;

use axum::extract::{Path, RawForm, State};
use axum::response::{Html, IntoResponse, Response};
use cratefield_accounts::Venture;
use cratefield_chrome::{Page, escape, render};
use cratefield_console::current_session;
use cratefield_core::{Database, ModuleContext, Statement};
use cratefield_secrets::{
    Actor, RewrapReport, RotationReport, SecretBytes, SecretMeta, SecretStore, Secrets,
    SecretsError, StoreId, chain_sink, verify,
};
use http::{HeaderMap, StatusCode};

use crate::{BASE, DashboardState, account_nav, account_of, card, frame, guard, internal};

/// The store the screen manages, as the URL names it: `global`, or a
/// venture id resolved against the signed-in account's own ventures so
/// one account can never open another's store.
enum Store {
    Global,
    Tenant { venture: Venture },
}

impl Store {
    /// The URL segment for this store's detail page.
    fn slug(&self) -> String {
        match self {
            Store::Global => "global".to_owned(),
            Store::Tenant { venture } => venture.id.clone(),
        }
    }

    /// What the page calls it, and the one-line reason it exists.
    fn label(&self) -> (String, &'static str) {
        match self {
            Store::Global => (
                "global".to_owned(),
                "the control database's own connection strings and platform keys",
            ),
            Store::Tenant { venture } => (
                venture.slug.clone(),
                "this venture's own credentials, sealed to its tenant store",
            ),
        }
    }

    fn id(&self) -> StoreId {
        match self {
            Store::Global => StoreId::Global,
            Store::Tenant { venture } => StoreId::Tenant(venture.tenant_id.clone()),
        }
    }
}

/// Resolves a URL segment to a store the account may touch. A venture
/// that is not this account's is a 404, exactly as the venture screen
/// answers it: the store list is scoped the same way the venture list
/// is, by query.
#[allow(clippy::result_large_err)]
async fn resolve_store(
    ctx: &ModuleContext,
    account: &cratefield_accounts::Account,
    slug: &str,
) -> Result<Store, Response> {
    if slug == "global" {
        return Ok(Store::Global);
    }
    let db = ctx
        .ports
        .db
        .clone()
        .ok_or_else(|| internal("db port unavailable"))?;
    let repo = cratefield_accounts::Repository::new(db);
    match repo.venture_for(&account.id, slug).await {
        Ok(Some(venture)) => Ok(Store::Tenant { venture }),
        Ok(None) => Err((StatusCode::NOT_FOUND, "no such store").into_response()),
        Err(err) => {
            tracing::error!(error = %err, "store lookup failed");
            Err(internal("could not resolve the store"))
        }
    }
}

/// The signed-in operator, who is the actor every access here is
/// attributed to. Never a module name, never a constant: the audit
/// chain's "who did this" is only worth its hashes if it names a person.
fn actor_of(account_id: &str) -> Result<Actor, SecretsError> {
    Actor::new(account_id.to_owned())
}

/// Opens one store through the real API, with the durable audit chain
/// wired the way `Connections` wires it: an access that survives only
/// as a log line is the gap the chain exists to close. Built per
/// request — two `Arc` clones — because the database is resolved from
/// the request's module context, which is the only handle a module
/// legitimately has.
fn open_store(state: &DashboardState, db: &Arc<dyn Database>, store: &Store) -> SecretStore {
    // Every route checks `state.kms.is_none()` before calling here, so
    // the expect is a backstop, not the plan.
    let kms = state
        .kms
        .clone()
        .expect("kms checked before opening a store");
    let secrets = Secrets::new(kms).with_audit(chain_sink(Arc::clone(db)));
    match store {
        Store::Global => secrets.control_plane_global(Arc::clone(db)),
        Store::Tenant { venture } => secrets.tenant(&venture.tenant_id, Arc::clone(db)),
    }
}

/// What `verify` said about one store's audit chain. The distinction
/// between the last two variants is the whole point: a chain that does
/// not verify, and a chain that could not be read, are different facts
/// and only one of them is an accusation.
enum ChainStatus {
    /// Verifies, and has entries. Carries the last entry's seq.
    Verifies(i64),
    /// Verifies and is empty: nothing has touched this store yet.
    Empty,
    /// Does not verify. Carries the full sentence.
    Broken(String),
    /// Could not be read. Carries the (sanitised) infrastructure error.
    Unreadable(String),
}

async fn chain_status(store: &StoreId, db: &dyn Database) -> ChainStatus {
    match verify(store, db).await {
        Ok(anchor) if anchor.seq == 0 => ChainStatus::Empty,
        Ok(anchor) => ChainStatus::Verifies(anchor.seq),
        // `ChainBroken`'s Display is the sentence this screen exists to
        // put in front of an operator; the other variants' Display is
        // safe to render too (`DbError` sanitises deliberately), but
        // only the broken one is rendered as a break.
        Err(SecretsError::ChainBroken { store, seq, detail }) => ChainStatus::Broken(
            SecretsError::ChainBroken {
                store: store.clone(),
                seq,
                detail,
            }
            .to_string(),
        ),
        Err(other) => ChainStatus::Unreadable(other.to_string()),
    }
}

/// The badge at the top of every store page. "This chain verifies as of
/// entry N" is the single most valuable thing on it: the difference
/// between an audit log and a list of claims.
fn chain_badge(status: &ChainStatus) -> String {
    match status {
        ChainStatus::Verifies(seq) => format!(
            "<div class=\"dash__chain\"><span class=\"dash__dot dash__dot--live\"></span>\
             <strong>This chain verifies as of entry {seq}.</strong>\
             <span class=\"dash__note\">Every row's hash follows from its predecessor, \
             walked just now by this page. A chain cannot detect the loss of its own \
             tail — that is what an anchor, published outside the database, is for.</span></div>"
        ),
        ChainStatus::Empty => String::from(
            "<div class=\"dash__chain\"><span class=\"dash__dot\"></span>\
             <strong>This chain is empty.</strong>\
             <span class=\"dash__note\">Nothing has touched this store yet. The first \
             access — including the ones this page makes — begins the chain.</span></div>",
        ),
        ChainStatus::Broken(sentence) => format!(
            "<div class=\"dash__chain dash__chain--bad\"><span class=\"dash__dot \
             dash__dot--bad\"></span><strong>THE AUDIT CHAIN DOES NOT VERIFY.</strong>\
             <span class=\"dash__note\">{sentence} Entries after the break cannot be \
             trusted: the chain is evidence precisely because it stops verifying when \
             it is edited.</span></div>",
            sentence = escape(sentence),
        ),
        ChainStatus::Unreadable(sentence) => format!(
            "<div class=\"dash__chain\"><span class=\"dash__dot dash__dot--warn\"></span>\
             <strong>The chain could not be read.</strong>\
             <span class=\"dash__note\">{sentence}</span></div>",
            sentence = escape(sentence),
        ),
    }
}

/// One row of the audit trail, newest first.
struct AuditRow {
    seq: i64,
    ts: String,
    actor: String,
    name: String,
    version: Option<i64>,
    action: String,
    allowed: bool,
}

async fn audit_of(
    db: &dyn Database,
    store: &str,
) -> Result<Vec<AuditRow>, cratefield_core::DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT seq, ts, actor, name, version, action, allowed FROM harness_secret_audit \
             WHERE store = ? ORDER BY seq DESC LIMIT 200",
            vec![text(store)],
        ))
        .await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| AuditRow {
            seq: row.get("seq").unwrap_or_default(),
            ts: row.get("ts").unwrap_or_default(),
            actor: row.get("actor").unwrap_or_default(),
            name: row.get("name").unwrap_or_default(),
            version: row.get("version"),
            action: row.get("action").unwrap_or_default(),
            allowed: row.get::<i64>("allowed").unwrap_or_default() != 0,
        })
        .collect())
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}

// ---------------------------------------------------------------------------
// The honest no-KMS state
// ---------------------------------------------------------------------------

/// What every secrets route renders when no key manager is wired — the
/// production path today. Says so in the voice the planned screens use,
/// because a 500 here would say the opposite: that there is a store and
/// the page failed to reach it. There is no store, and the page says
/// that.
fn no_kms_page() -> Response {
    let body = "<p class=\"dash__banner\"><span class=\"chip\">No KMS</span>\
         <strong>No key manager is configured in this deployment.</strong></p>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__note\">No secret store can be opened — not read, not written, \
         not audited — because there is nothing to unwrap the stores' data keys with. \
         This is the state of the Cloudflare deployment today: the Workers runtime has \
         no filesystem for a local key and no managed KMS adapter has been written for \
         it, and that adapter is its own issue rather than something this page should \
         paper over.</p>\
         <p class=\"dash__note\">There is no fallback on purpose. A secrets store whose \
         keys come from nowhere is a text field with a label, and every secret ever \
         written through it would be compromised the same way: quietly.</p></div>\
         <p class=\"dash__note\">This page exists so the navigation does not lie in \
         either direction: the secrets layer is built, it is not reachable here, and \
         the screen says so rather than showing an empty list that would read as \
         \u{201c}no secrets\u{201d}.</p>";
    Html(render(&Page {
        title: "Secrets",
        signed_in_as: None,
        body: &format!(
            "<div class=\"page-h\"><h1>Secrets</h1><span class=\"chip\">No KMS</span></div>\
             <p class=\"lede\">No key manager is configured here, so no store can be \
             opened.</p>{frame}",
            frame = frame(&account_nav("secrets"), "Secrets", body),
        ),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// The store list
// ---------------------------------------------------------------------------

/// What one store's row on the list says: how many live secrets, the
/// newest version's timestamp, and whether the chain verifies.
struct StoreSummary {
    store: Store,
    live: usize,
    newest: String,
    chain: ChainStatus,
}

/// The screen's front page: every store this control plane can see. The
/// global store plus one tenant store per venture the account owns —
/// the same scoping the venture list uses, so an account's store list
/// and its venture list can never disagree.
#[allow(clippy::too_many_lines)]
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub(crate) async fn stores(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    if state.kms.is_none() {
        return no_kms_page();
    }
    let (account, repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let ventures = match repo.ventures_for(&account.id).await {
        Ok(ventures) => ventures,
        Err(err) => {
            tracing::error!(error = %err, "venture list failed for the store list");
            return internal("could not load the ventures");
        }
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let Ok(actor) = actor_of(&session.account_id) else {
        return internal("the session carries no actor");
    };

    // `list` is an audited access — the page reads each store through
    // the real API, attributed to the operator, exactly as an operator
    // clicking through would be.
    let mut all: Vec<Store> = vec![Store::Global];
    for venture in ventures {
        all.push(Store::Tenant { venture });
    }
    let mut summaries: Vec<StoreSummary> = Vec::new();
    for store in all {
        let id = store.id();
        let handle = open_store(&state, &db, &store);
        let summary = match handle.list(&actor).await {
            Ok(metas) => {
                let live = metas.iter().filter(|meta| !meta.deleted).count();
                let newest = metas
                    .iter()
                    .map(|meta| meta.created_at.as_str())
                    .max()
                    .unwrap_or("")
                    .to_owned();
                StoreSummary {
                    chain: chain_status(&id, db.as_ref()).await,
                    live,
                    newest,
                    store,
                }
            }
            // A store whose key row is gone or whose database refuses is
            // still a store this control plane can see; the row says
            // what happened rather than disappearing.
            Err(err) => StoreSummary {
                chain: ChainStatus::Unreadable(err.to_string()),
                live: 0,
                newest: String::new(),
                store,
            },
        };
        summaries.push(summary);
    }

    let mut rows = String::from(
        "<div class=\"dash__lrow dash__lrow--head\"><span>Store</span><span>Live \
         secrets</span><span>Newest version</span><span>Audit chain</span></div>",
    );
    for summary in &summaries {
        let (label, why) = summary.store.label();
        let (dot, verdict) = match &summary.chain {
            ChainStatus::Verifies(seq) => (
                "dash__dot dash__dot--live",
                format!("verifies as of entry {seq}"),
            ),
            ChainStatus::Empty => ("dash__dot", "empty".to_owned()),
            ChainStatus::Broken(_) => ("dash__dot dash__dot--bad", "DOES NOT VERIFY".to_owned()),
            ChainStatus::Unreadable(_) => ("dash__dot dash__dot--warn", "unreadable".to_owned()),
        };
        rows.push_str(&format!(
            "<div class=\"dash__lrow\">\
             <span><a href=\"{BASE}/secrets/{slug}\">{label}</a><br><em>{why}</em></span>\
             <span>{live}</span>\
             <span>{newest}</span>\
             <span><span class=\"{dot_class}\"></span> {verdict}</span></div>",
            slug = escape(&summary.store.slug()),
            label = escape(&label),
            why = escape(why),
            live = summary.live,
            newest = escape(&summary.newest),
            dot_class = dot,
            verdict = escape(&verdict),
        ));
    }

    let body = format!(
        "<div class=\"dash__list\">{rows}</div>\
         <p class=\"dash__note\">Every count and every verdict on this page came from \
         the store's own API just now — each row's visit is on that store's audit \
         chain, attributed to you. Secret values are never on this or any other \
         page: this screen shows names and versions only.</p>",
    );

    Html(render(&Page {
        title: "Secrets",
        signed_in_as: Some(&session.account_id),
        body: &format!(
            "<div class=\"page-h\"><h1>Secrets</h1></div>\
             <p class=\"lede\">Every secret store this control plane can see: the \
             global store, and one tenant store per venture. Names and versions, \
             never values.</p>{frame}",
            frame = frame(&account_nav("secrets"), "Secrets", &body),
        ),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// The store detail
// ---------------------------------------------------------------------------

/// Everything the detail page renders, gathered before any HTML is
/// built so the reads and the rendering can be read one at a time.
struct StoreDetail {
    store: Store,
    secrets: Vec<SecretMeta>,
    audit: Vec<AuditRow>,
    chain: ChainStatus,
}

#[allow(clippy::result_large_err)]
async fn load_detail(
    state: &Arc<DashboardState>,
    account: &cratefield_accounts::Account,
    slug: &str,
) -> Result<StoreDetail, Response> {
    let ctx = &state.ctx;
    let store = resolve_store(ctx, account, slug).await?;
    let Some(db) = ctx.ports.db.clone() else {
        return Err(internal("db port unavailable"));
    };
    if state.kms.is_none() {
        return Err(no_kms_page());
    }
    let Ok(actor) = actor_of(&account.identity) else {
        return Err(internal("the session carries no actor"));
    };
    let handle = open_store(state, &db, &store);
    let secrets = match handle.list(&actor).await {
        Ok(metas) => metas,
        Err(err) => {
            tracing::error!(error = %err, "secret list failed");
            return Err(error_page("The secrets could not be listed", &err));
        }
    };
    let id = store.id();
    let audit = match audit_of(db.as_ref(), id.as_str()).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, "audit read failed");
            return Err(internal("could not load the audit trail"));
        }
    };
    Ok(StoreDetail {
        chain: chain_status(&id, db.as_ref()).await,
        store,
        secrets,
        audit,
    })
}

/// One store's page: the chain badge, the secrets, the actions, and the
/// audit trail.
pub(crate) async fn store_detail(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let detail = match load_detail(&state, &account, &slug).await {
        Ok(detail) => detail,
        Err(response) => return response,
    };
    Html(render_detail(&session.account_id, &detail, "")).into_response()
}

/// The detail page itself, separated from the handler so an action can
/// render the same page with a banner saying what it did.
#[allow(clippy::too_many_lines)]
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn render_detail(identity: &str, detail: &StoreDetail, banner: &str) -> String {
    let (label, _why) = detail.store.label();
    let slug = detail.store.slug();

    // The creator shown per version is the actor the audit chain records
    // for the `put` that wrote it. The secret row's own `created_by`
    // column reads "pending" — the store never learns the actor, only
    // the chain does — so the chain is the honest source here.
    let creators: std::collections::HashMap<(String, i64), String> = detail
        .audit
        .iter()
        .filter(|row| row.action == "put" && row.allowed)
        .filter_map(|row| {
            let version = row.version?;
            Some(((row.name.clone(), version), row.actor.clone()))
        })
        .collect();

    let mut secret_rows = String::from(
        "<div class=\"dash__lrow dash__lrow--head\"><span>Name</span><span>Version</span>\
         <span>Created</span><span>By</span><span></span></div>",
    );
    if detail.secrets.is_empty() {
        secret_rows
            .push_str("<p class=\"dash__empty\">No secrets in this store yet. Set one below.</p>");
    }
    for meta in &detail.secrets {
        let creator = creators
            .get(&(meta.name.clone(), i64::from(meta.version)))
            .cloned()
            .unwrap_or_else(|| meta.created_by.clone());
        let deleted = if meta.deleted {
            " <span class=\"chip chip--archived\">deleted</span>"
        } else {
            ""
        };
        secret_rows.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--secrets\">\
             <span><code>{name}</code>{deleted}</span>\
             <span>v{version}</span>\
             <span>{created}</span>\
             <span>{creator}</span>\
             <span><form method=\"post\" action=\"{BASE}/secrets/{slug}/delete\">\
             <input type=\"hidden\" name=\"name\" value=\"{name_attr}\">\
             <button class=\"btn\" type=\"submit\">Delete</button></form></span></div>",
            name = escape(&meta.name),
            deleted = deleted,
            version = meta.version,
            created = escape(&meta.created_at),
            creator = escape(&creator),
            slug = escape(&slug),
            name_attr = escape(&meta.name),
        ));
    }

    let put_form = format!(
        "<form method=\"post\" action=\"{BASE}/secrets/{slug}/put\">\
         <p class=\"field\"><label for=\"secret-name\">Name</label>\
         <input id=\"secret-name\" name=\"name\" required maxlength=\"200\" \
         autocomplete=\"off\" placeholder=\"resend/api_key\"></p>\
         <p class=\"field\"><label for=\"secret-value\">Value</label>\
         <input id=\"secret-value\" name=\"value\" type=\"password\" required \
         autocomplete=\"off\"></p>\
         <div class=\"dash__act\">\
         <button class=\"btn btn--primary\" type=\"submit\">Set secret</button></div>\
         </form>\
         <p class=\"dash__note\">A new name starts at version 1. An existing name \
         gets its next version — one more than the table shows — and the old version \
         stays, because it is what a rollback needs and what the audit trail refers \
         to.</p>\
         <p class=\"dash__note\">The value is never shown again. Not on this page, not \
         on any other, not in the audit trail: it is sealed in the same request you \
         send it in. If something needs to read it back out, that is a different and \
         much more carefully specified feature than a page.</p>",
        slug = escape(&slug),
    );

    let key_actions = format!(
        "<div class=\"dash__act\">\
         <form method=\"post\" action=\"{BASE}/secrets/{slug}/rotate\">\
         <button class=\"btn\" type=\"submit\">Rotate the data key…</button></form>\
         <form method=\"post\" action=\"{BASE}/secrets/{slug}/rewrap\">\
         <button class=\"btn\" type=\"submit\">Re-wrap under the master key…</button></form>\
         </div>\
         <p class=\"dash__note\">Both render a plan first — what would happen, counted \
         — and only run when you press again on the report. A rotation that has never \
         been rehearsed is an outage, so the rehearsal is the button's first press.</p>",
        slug = escape(&slug),
    );

    let mut audit_rows = String::from(
        "<div class=\"dash__lrow dash__lrow--head\"><span>#</span><span>When</span>\
         <span>Action</span><span>Actor</span><span>Secret</span><span>Allowed</span></div>",
    );
    if detail.audit.is_empty() {
        audit_rows.push_str("<p class=\"dash__empty\">No entries yet.</p>");
    }
    for row in &detail.audit {
        let name = if row.name.is_empty() {
            "<em>—</em>".to_owned()
        } else {
            format!("<code>{}</code>", escape(&row.name))
        };
        let version = match row.version {
            Some(version) => format!(" v{version}"),
            None => String::new(),
        };
        let allowed = if row.allowed {
            "yes"
        } else {
            "<strong>REFUSED</strong>"
        };
        audit_rows.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--audit\">\
             <span>{seq}</span><span>{ts}</span><span>{action}</span><span>{actor}</span>\
             <span>{name}{version}</span><span>{allowed}</span></div>",
            seq = row.seq,
            ts = escape(&row.ts),
            action = escape(&row.action),
            actor = escape(&row.actor),
            name = name,
            version = version,
            allowed = allowed,
        ));
    }

    let body = format!(
        "{banner}{chain}\
         <div class=\"dash__grid\">\
         {secrets_card}\
         {audit_card}\
         </div>\
         {put_card}\
         {keys_card}\
         <p class=\"dash__note\">This page never reads a secret value. The list is \
         names and versions from the store's own metadata; the audit trail holds no \
         values by construction. Who visited this store just now — you — is on the \
         trail above, because reading the list is an audited access.</p>",
        banner = banner,
        chain = chain_badge(&detail.chain),
        secrets_card = card(
            "Secrets",
            Some(&detail.secrets.len().to_string()),
            &format!("<div class=\"dash__list\">{secret_rows}</div>"),
            true,
        ),
        audit_card = card(
            "Audit trail",
            Some(&detail.audit.len().to_string()),
            &format!("<div class=\"dash__list\">{audit_rows}</div>"),
            true,
        ),
        put_card = card("Set a secret", None, &put_form, false),
        keys_card = card("Key management", None, &key_actions, false),
    );

    let shell = format!(
        "<p class=\"crumb\"><a href=\"{BASE}\">Ventures</a> / \
         <a href=\"{BASE}/secrets\">Secrets</a> / {label}</p>\
         <div class=\"page-h\"><h1>{label}</h1></div>\
         <p class=\"lede\">One store: what it holds, who touched it, and whether the \
         record of that still verifies.</p>{frame}",
        label = escape(&label),
        frame = frame(&account_nav("secrets"), &label, &body),
    );

    render(&Page {
        title: &format!("Secrets · {label}"),
        signed_in_as: Some(identity),
        body: &shell,
    })
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// An action's failure, rendered rather than a bare status where a page
/// is more useful. `SecretsError`'s and `DbError`'s `Display` are safe
/// to show (the latter sanitises deliberately — see the test at the
/// bottom of `crates/core/src/ports/database.rs`), and an operator told
/// "a secret name cannot be empty" can act; one told only "500" cannot.
/// Invalid input is a 400 and everything else a 500: a database fault is
/// not the caller's mistake.
fn error_page(what: &str, err: &SecretsError) -> Response {
    let status = if matches!(err, SecretsError::Invalid(_)) {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, format!("{what}: {err}")).into_response()
}

/// Sets a secret. The value arrives as form bytes and becomes a
/// [`SecretBytes`] without ever passing through a `String`, a format
/// argument, a tracing field or an error: it is zeroised when this
/// handler returns and nothing survives it but the ciphertext and the
/// audit row.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub(crate) async fn put_secret(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    RawForm(body): RawForm,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let store = match resolve_store(ctx, &account, &slug).await {
        Ok(store) => store,
        Err(response) => return response,
    };
    if state.kms.is_none() {
        return no_kms_page();
    }
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let Ok(actor) = actor_of(&session.account_id) else {
        return internal("the session carries no actor");
    };

    let mut fields = parse_form(&body);
    let Some(name) = field_text(&fields, "name") else {
        return (StatusCode::BAD_REQUEST, "the form has no name").into_response();
    };
    let name = name.trim().to_owned();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "a secret name cannot be empty").into_response();
    }
    // The one field that is a secret leaves the parsed body by move, not
    // copy: there is exactly one buffer and [`SecretBytes`] owns it.
    let Some(value) = take_value(&mut fields, "value") else {
        return (StatusCode::BAD_REQUEST, "the form has no value").into_response();
    };
    if value.expose().is_empty() {
        return (StatusCode::BAD_REQUEST, "a secret value cannot be empty").into_response();
    }

    let handle = open_store(&state, &db, &store);
    let version = match handle.put(&name, &value, &actor).await {
        Ok(version) => version,
        Err(err) => {
            // The name is metadata this page displays and the audit
            // chain records; the value never rides a log line.
            tracing::error!(error = %err, name = %name, "put failed");
            return error_page("the secret could not be set", &err);
        }
    };

    // The response names the secret and its new version, and nothing
    // else. Not the value, not truncated, not hashed: a fragment or a
    // digest of a credential is a thing worth brute-forcing, and the
    // page has nothing to gain by carrying one.
    let first = if version == 1 {
        " — the first version of this name"
    } else {
        ""
    };
    let banner = format!(
        "<p class=\"dash__banner\"><span class=\"chip chip--live\">Set</span>\
         <strong><code>{name}</code> is now at version {version}</strong>{first}. The \
         value is sealed and was not kept anywhere but the ciphertext.</p>",
        name = escape(&name),
        version = version,
        first = first,
    );
    match load_detail(&state, &account, &slug).await {
        Ok(detail) => Html(render_detail(&session.account_id, &detail, &banner)).into_response(),
        // The put succeeded; only the re-read failed. Say that rather
        // than letting a 500 read as "it did not work".
        Err(_) => (
            StatusCode::OK,
            format!(
                "Set {} to version {version}. The page could not be re-read \
                 afterwards; reload it.",
                escape(&name)
            ),
        )
            .into_response(),
    }
}

/// Soft-deletes every version of a secret — in two presses. The first
/// renders the confirmation naming what will die; only the second,
/// carrying `confirmed`, performs it.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub(crate) async fn delete_secret(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    RawForm(body): RawForm,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let store = match resolve_store(ctx, &account, &slug).await {
        Ok(store) => store,
        Err(response) => return response,
    };
    if state.kms.is_none() {
        return no_kms_page();
    }
    let fields = parse_form(&body);
    let Some(name) = field_text(&fields, "name") else {
        return (StatusCode::BAD_REQUEST, "the form has no name").into_response();
    };
    let name = name.trim().to_owned();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "a secret name cannot be empty").into_response();
    }

    if !fields.iter().any(|field| field.name == "confirmed") {
        let body_html = format!(
            "<div class=\"dash__card dash__card--wide\">\
             <p class=\"dash__card-h\">Delete <code>{name}</code>?</p>\
             <p class=\"dash__note\">This soft-deletes <strong>every version</strong> \
             of the secret in this store. The value stops being readable immediately; \
             the rows and the audit trail stay, because a deletion nobody can account \
             for is its own kind of gap.</p>\
             <form method=\"post\" action=\"{BASE}/secrets/{slug}/delete\">\
             <input type=\"hidden\" name=\"name\" value=\"{name_attr}\">\
             <input type=\"hidden\" name=\"confirmed\" value=\"1\">\
             <div class=\"dash__act\">\
             <button class=\"btn\" type=\"submit\">Yes, delete every version</button>\
             <a class=\"btn\" href=\"{BASE}/secrets/{slug}\">Cancel</a></div></form></div>",
            name = escape(&name),
            slug = escape(&slug),
            name_attr = escape(&name),
        );
        let (label, _) = store.label();
        return Html(render(&Page {
            title: &format!("Delete · {label}"),
            signed_in_as: Some(&session.account_id),
            body: &format!(
                "<p class=\"crumb\"><a href=\"{BASE}/secrets\">Secrets</a> / \
                 <a href=\"{BASE}/secrets/{slug}\">{label}</a> / Delete</p>\
                 <div class=\"page-h\"><h1>Delete a secret</h1></div>{frame}",
                label = escape(&label),
                slug = escape(&slug),
                frame = frame(&account_nav("secrets"), &label, &body_html),
            ),
        }))
        .into_response();
    }

    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let Ok(actor) = actor_of(&session.account_id) else {
        return internal("the session carries no actor");
    };
    let handle = open_store(&state, &db, &store);
    if let Err(err) = handle.delete(&name, &actor).await {
        tracing::error!(error = %err, name = %name, "delete failed");
        return error_page("the secret could not be deleted", &err);
    }
    let banner = format!(
        "<p class=\"dash__banner\"><span class=\"chip chip--archived\">Deleted</span>\
         <strong><code>{name}</code> is soft-deleted.</strong> Every version's value \
         is unreadable now; the rows and the audit trail keep their record of \
         it.</p>",
        name = escape(&name),
    );
    match load_detail(&state, &account, &slug).await {
        Ok(detail) => Html(render_detail(&session.account_id, &detail, &banner)).into_response(),
        Err(_) => (
            StatusCode::OK,
            format!("Deleted {}. Reload the store's page.", escape(&name)),
        )
            .into_response(),
    }
}

/// Rotates the store's data key. The first press is a plan — what would
/// happen, counted, nothing changed — and the report carries the second
/// press that runs it. Both presses are audited, because a rotation
/// someone rehearsed is still an event.
pub(crate) async fn rotate(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    RawForm(body): RawForm,
) -> Response {
    key_action(state, headers, slug, body, KeyAction::Rotate).await
}

/// Re-wraps every data key under the master key's current material, in
/// the same plan-then-run shape as [`rotate`].
pub(crate) async fn rewrap(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    RawForm(body): RawForm,
) -> Response {
    key_action(state, headers, slug, body, KeyAction::Rewrap).await
}

enum KeyAction {
    Rotate,
    Rewrap,
}

impl KeyAction {
    fn noun(&self) -> &'static str {
        match self {
            KeyAction::Rotate => "rotation",
            KeyAction::Rewrap => "re-wrap",
        }
    }

    fn path_segment(&self) -> &'static str {
        match self {
            KeyAction::Rotate => "rotate",
            KeyAction::Rewrap => "rewrap",
        }
    }
}

/// The one-of-two report a key action produced. An enum rather than a
/// boxed `Display` because the two reports carry different fields and
/// pretending otherwise would push the difference into string munging,
/// which is where reports start lying.
enum KeyReport {
    Rotation(RotationReport),
    Rewrap(RewrapReport),
}

impl KeyReport {
    fn planned(&self) -> bool {
        match self {
            KeyReport::Rotation(report) => report.planned,
            KeyReport::Rewrap(report) => report.planned,
        }
    }
}

/// The shared body of both key actions: guard, resolve, plan or run,
/// render the report. The plan/run split is the entire safety story —
/// see [`rotate`].
async fn key_action(
    state: Arc<DashboardState>,
    headers: HeaderMap,
    slug: String,
    body: axum::body::Bytes,
    action: KeyAction,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, _repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let store = match resolve_store(ctx, &account, &slug).await {
        Ok(store) => store,
        Err(response) => return response,
    };
    if state.kms.is_none() {
        return no_kms_page();
    }
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let Ok(actor) = actor_of(&session.account_id) else {
        return internal("the session carries no actor");
    };
    let run = parse_form(&body).iter().any(|field| field.name == "run");
    let handle = open_store(&state, &db, &store);
    let report = match (&action, run) {
        (KeyAction::Rotate, _) => match handle.rotate_dek(&actor, !run).await {
            Ok(report) => KeyReport::Rotation(report),
            Err(err) => {
                tracing::error!(error = %err, "rotate failed");
                return error_page("the rotation could not run", &err);
            }
        },
        (KeyAction::Rewrap, _) => match handle.rewrap(&actor, !run).await {
            Ok(report) => KeyReport::Rewrap(report),
            Err(err) => {
                tracing::error!(error = %err, "rewrap failed");
                return error_page("the re-wrap could not run", &err);
            }
        },
    };
    report_page(&session.account_id, &store, &action, &report)
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn report_page(identity: &str, store: &Store, action: &KeyAction, report: &KeyReport) -> Response {
    let (label, _) = store.label();
    let slug = store.slug();
    let (heading, detail) = match report {
        KeyReport::Rotation(report) => {
            let keys = match (&report.from_key, &report.to_key) {
                (Some(from), Some(to)) => format!(
                    "The active key moved from <code>{}</code> to <code>{}</code>.",
                    escape(from),
                    escape(to)
                ),
                (Some(from), None) => format!(
                    "The active key is <code>{}</code>; a new one would replace it.",
                    escape(from)
                ),
                (None, _) => String::from(
                    "There is no active key yet — the store provisions its first data \
                     key on the run.",
                ),
            };
            let retired = if report.planned {
                "The old key would be retired once nothing references it."
            } else if report.retired_old {
                "The old key is retired: nothing references it any more."
            } else {
                "The old key stays <em>retiring</em>: soft-deleted versions still \
                 name it, and a key nothing can read is not the same as a key \
                 nobody needs."
            };
            let verb = planned_verb(report.planned);
            (
                "Data key rotation",
                format!(
                    "<p class=\"dash__note\">{keys}</p>\
                     <p class=\"dash__note\"><strong>{reencrypted}</strong> secret \
                     version(s) {verb} re-encrypted under the new key, one row at a \
                     time, so a read at any point in between saw a valid row under \
                     one key or the other.</p>\
                     <p class=\"dash__note\">{retired}</p>",
                    keys = keys,
                    reencrypted = report.reencrypted,
                    verb = verb,
                    retired = retired,
                ),
            )
        }
        KeyReport::Rewrap(report) => {
            let verb = planned_verb(report.planned);
            (
                "Re-wrap under the master key",
                format!(
                    "<p class=\"dash__note\"><strong>{keys}</strong> data key(s) \
                     {verb} re-wrapped under the master key's current material \
                     (<code>{key_ref}</code>). No secret was re-encrypted: secrets \
                     are sealed under their data keys, and those did not change.</p>",
                    keys = report.keys,
                    verb = verb,
                    key_ref = escape(&report.key_ref),
                ),
            )
        }
    };
    let planned = report.planned();
    let state_word = if planned { " — plan" } else { "" };
    let noun = action.noun();
    let body = format!(
        "<div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">{heading}{state_word}</p>{detail}</div>{run_form}\
         <p class=\"dash__note\">{note}</p>",
        run_form = if planned {
            format!(
                "<form method=\"post\" action=\"{BASE}/secrets/{slug}/{seg}\">\
                 <input type=\"hidden\" name=\"run\" value=\"1\">\
                 <div class=\"dash__act\">\
                 <button class=\"btn btn--primary\" type=\"submit\">Run the {noun}</button>\
                 <a class=\"btn\" href=\"{BASE}/secrets/{slug}\">Back</a></div></form>",
                slug = escape(&slug),
                seg = action.path_segment(),
                noun = noun,
            )
        } else {
            format!(
                "<div class=\"dash__act\"><a class=\"btn\" href=\"{BASE}/secrets/{slug}\">\
                 Back to the store</a></div>",
                slug = escape(&slug),
            )
        },
        note = if planned {
            format!(
                "Nothing has changed yet. This is what the {noun} would do; the \
                 button above is what makes it happen."
            )
        } else {
            format!(
                "The {noun} ran. Both presses are on the store's audit chain, \
                 attributed to you."
            )
        },
    );
    Html(render(&Page {
        title: heading,
        signed_in_as: Some(identity),
        body: &format!(
            "<p class=\"crumb\"><a href=\"{BASE}/secrets\">Secrets</a> / \
             <a href=\"{BASE}/secrets/{slug}\">{label}</a> / {crumb}</p>\
             <div class=\"page-h\"><h1>{heading}</h1></div>{frame}",
            label = escape(&label),
            slug = escape(&slug),
            crumb = match action {
                KeyAction::Rotate => "Rotate",
                KeyAction::Rewrap => "Re-wrap",
            },
            heading = heading,
            frame = frame(&account_nav("secrets"), &label, &body),
        ),
    }))
    .into_response()
}

fn planned_verb(planned: bool) -> &'static str {
    if planned { "would be" } else { "were" }
}

// ---------------------------------------------------------------------------
// Form bodies, parsed without ever making the value a String
// ---------------------------------------------------------------------------

/// One urlencoded form field. The value stays `Vec<u8>` until the one
/// field that is a secret wraps it in [`SecretBytes`]: a value that
/// becomes a `String` is a value that can be formatted, logged and
/// cloned, and this screen's one inbound secret deserves none of those.
struct FormField {
    name: String,
    value: Vec<u8>,
}

/// Parses an `application/x-www-form-urlencoded` body. Names become
/// `String`s (a name is operator-chosen metadata, shown on the page);
/// values stay bytes.
fn parse_form(body: &[u8]) -> Vec<FormField> {
    body.split(|&byte| byte == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = match pair.iter().position(|&byte| byte == b'=') {
                Some(at) => (&pair[..at], &pair[at + 1..]),
                None => (pair, &pair[..0]),
            };
            FormField {
                name: String::from_utf8_lossy(&url_decode(name)).into_owned(),
                value: url_decode(value),
            }
        })
        .collect()
}

/// Percent-decoding with `+` as space, straight into bytes — the form a
/// secret value arrives in and the form it stays in.
fn url_decode(bytes: &[u8]) -> Vec<u8> {
    fn hex_digit(byte: u8) -> Option<u32> {
        (byte as char).to_digit(16)
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some(at) = rest.iter().position(|&byte| byte == b'%' || byte == b'+') {
        out.extend_from_slice(&rest[..at]);
        // An escape consumes three bytes ('%' plus two hex digits); the
        // other arms consume one.
        let mut advance = 1;
        if rest[at] == b'+' {
            out.push(b' ');
        } else {
            let decoded = rest
                .get(at + 1..at + 3)
                .and_then(|digits| {
                    Some((hex_digit(*digits.first()?)?, hex_digit(*digits.get(1)?)?))
                })
                .and_then(|(hi, lo)| u8::try_from(hi * 16 + lo).ok());
            match decoded {
                Some(byte) => {
                    out.push(byte);
                    advance = 3;
                }
                // A malformed escape passes through verbatim rather
                // than being dropped: the difference is visible to a
                // caller who sent it, and a name is not worth
                // silently rewriting.
                None => out.push(b'%'),
            }
        }
        rest = &rest[at + advance..];
    }
    out.extend_from_slice(rest);
    out
}

/// The named field's bytes as text, for non-secret fields only.
fn field_text(fields: &[FormField], name: &str) -> Option<String> {
    let field = fields.iter().find(|field| field.name == name)?;
    Some(String::from_utf8_lossy(&field.value).into_owned())
}

/// Moves the named field's bytes into a zeroising [`SecretBytes`] — by
/// `take`, so there is exactly one buffer and no copy behind it. This
/// is the only way a value leaves the parsed body.
fn take_value(fields: &mut [FormField], name: &str) -> Option<SecretBytes> {
    let field = fields.iter_mut().find(|field| field.name == name)?;
    Some(SecretBytes::new(std::mem::take(&mut field.value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Module as _;
    use cratefield_testing::TestHarness;
    use http::{Method, Request as HttpRequest};
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    const NOW: u64 = 1_800_000_000;
    /// A sentinel no honest page would produce: every "the value does
    /// not appear" assertion below is paired, in the same test, with the
    /// name and version that WOULD have carried it.
    const SENTINEL: &str = "SENTINEL-9f3a-value-do-not-render";

    struct Reply {
        status: StatusCode,
        location: String,
        body: String,
    }

    async fn send(
        kit: &TestHarness,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        form: Option<&str>,
    ) -> Reply {
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(http::header::COOKIE, cookie);
        }
        let body = match form {
            Some(form) => {
                builder = builder.header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                );
                axum::body::Body::from(form.to_owned())
            }
            None => axum::body::Body::empty(),
        };
        let response = kit
            .router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024).await.expect("body");
        Reply {
            status: parts.status,
            location: parts
                .headers
                .get(http::header::LOCATION)
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default(),
            body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
        }
    }

    fn cookie(kit: &TestHarness) -> String {
        let token = cratefield_access::issue_session(
            kit.signer.as_ref(),
            EMAIL,
            NOW,
            cratefield_access::DEFAULT_TTL_SECS,
        );
        format!("cf_session={token}")
    }

    fn kms() -> Arc<dyn cratefield_kms::Kms> {
        let kek = cratefield_kms::Dek::generate().expect("rng");
        Arc::new(
            cratefield_kms::LocalFileKms::from_key(kek, "test-kek", "test")
                .expect("not production"),
        )
    }

    fn modules(kms: Option<Arc<dyn cratefield_kms::Kms>>) -> Vec<Box<dyn cratefield_core::Module>> {
        vec![
            Box::new(cratefield_console::Console),
            Box::new(crate::Dashboard::new(kms)),
        ]
    }

    async fn seeded(kms: Option<Arc<dyn cratefield_kms::Kms>>) -> TestHarness {
        let kit = TestHarness::new(modules(kms));
        let repo = cratefield_accounts::Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        repo.create_venture(
            "v1",
            "acc_1",
            "my-app",
            "my-app.cratefield.app",
            "cms",
            "ten_1",
            "t0",
        )
        .await
        .expect("venture");
        kit
    }

    /// The store, opened the way nothing on this screen ever opens it —
    /// with a `get` — so tests can prove a value round-tripped without
    /// the screen gaining a read path.
    /// The store as a test fixture, under the same KMS the screen was
    /// wired with — a second KMS would make every wrapped key
    /// unopenable.
    fn open(kit: &TestHarness, kms: &Arc<dyn cratefield_kms::Kms>) -> SecretStore {
        Secrets::new(kms.clone())
            .with_audit(chain_sink(Arc::clone(&kit.db)))
            .control_plane_global(Arc::clone(&kit.db))
    }

    async fn audit_count(kit: &TestHarness, store: &str, action: &str) -> i64 {
        kit.db
            .query(&Statement::with_values(
                "SELECT COUNT(*) AS n FROM harness_secret_audit WHERE store = ? AND action = ?",
                vec![text(store), text(action)],
            ))
            .await
            .expect("count")
            .first()
            .and_then(|row| row.get::<i64>("n"))
            .unwrap_or(0)
    }

    // -- the store list -------------------------------------------------

    #[pollster::test]
    async fn the_store_list_renders_the_global_store_and_each_venture() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/secrets"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(reply.body.contains("global"), "{}", reply.body);
        assert!(
            reply.body.contains("my-app"),
            "the venture's tenant store is missing: {}",
            reply.body
        );
        assert!(reply.body.contains("Names and versions"), "{}", reply.body);
    }

    // -- the detail page ------------------------------------------------

    #[pollster::test]
    async fn the_detail_page_lists_secrets_and_badges_a_verifying_chain() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let actor = Actor::new("seed").expect("named");
        open(&kit, &kms)
            .put(
                "stripe/api_key",
                &SecretBytes::from("seed-value-not-rendered"),
                &actor,
            )
            .await
            .expect("seed put");

        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/secrets/global"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(reply.body.contains("stripe/api_key"), "{}", reply.body);
        assert!(
            reply.body.contains("This chain verifies as of entry"),
            "the badge is the point of the page: {}",
            reply.body
        );
        // The trail shows the seed's put, attributed to the actor that
        // did it — and the page's own list visit is on the chain too.
        assert!(reply.body.contains("put"), "{}", reply.body);
        assert!(reply.body.contains("seed"), "{}", reply.body);
        assert!(
            reply.body.contains("type=\"password\""),
            "the set form must be a password field: {}",
            reply.body
        );
        assert!(
            reply.body.contains("autocomplete=\"off\""),
            "the set form must not be autocompleted: {}",
            reply.body
        );
        // The seed value is nowhere, and the name that would have
        // carried it is (the pairing that stops this passing vacuously).
        assert!(
            !reply.body.contains("seed-value-not-rendered"),
            "{}",
            reply.body
        );
    }

    #[pollster::test]
    async fn a_broken_chain_says_where_in_red_at_the_top() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let actor = Actor::new("seed").expect("named");
        open(&kit, &kms)
            .put("stripe/api_key", &SecretBytes::from("v"), &actor)
            .await
            .expect("seed put");
        // Break the chain the only way the schema allows: INSERT is not
        // trigger-refused (only UPDATE and DELETE are), so a row with a
        // false prev_hash lands and every link after it stops
        // verifying.
        kit.db
            .execute(&Statement::with_values(
                "INSERT INTO harness_secret_audit \
                 (seq, ts, actor, name, version, action, allowed, request_id, store, \
                  prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    sea_query::Value::BigInt(Some(99)),
                    text("2026-01-01T00:00:00Z"),
                    text("tamperer"),
                    text("stripe/api_key"),
                    sea_query::Value::BigInt(Some(1)),
                    text("get"),
                    sea_query::Value::BigInt(Some(1)),
                    sea_query::Value::String(None),
                    text("global"),
                    sea_query::Value::Bytes(Some(Box::new(vec![0; 32]))),
                    sea_query::Value::Bytes(Some(Box::new(vec![1; 32]))),
                ],
            ))
            .await
            .expect("plant the broken row");

        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/secrets/global"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(
            reply.body.contains("THE AUDIT CHAIN DOES NOT VERIFY"),
            "{}",
            reply.body
        );
        assert!(
            reply.body.contains("dash__chain--bad"),
            "the break must be red in the markup, not only in the stylesheet: {}",
            reply.body
        );
        assert!(
            reply.body.contains("breaks at seq 99"),
            "where it breaks is the useful part of the sentence: {}",
            reply.body
        );
        // And the list page carries the verdict per store, not just the
        // detail page.
        let list = send(
            &kit,
            Method::GET,
            &format!("{BASE}/secrets"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert!(list.body.contains("DOES NOT VERIFY"), "{}", list.body);
    }

    // -- THE rule: the value never appears, paired with what would
    //    have carried it -----------------------------------------------

    #[pollster::test]
    async fn putting_a_secret_names_the_name_and_version_and_never_the_value() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let form = format!("name=live/api_key&value={SENTINEL}");
        let reply = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/put"),
            Some(&cookie(&kit)),
            Some(&form),
        )
        .await;
        // Both halves, one test: the response is 200, it carries the
        // name and the new version — the things that would have carried
        // the value — and the value is nowhere in it.
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(reply.body.contains("live/api_key"), "{}", reply.body);
        assert!(
            reply.body.contains("version 1"),
            "the response must name the new version: {}",
            reply.body
        );
        assert!(
            reply.body.contains("the first version of this name"),
            "new name or next version — the page says which it was: {}",
            reply.body
        );
        assert!(!reply.body.contains(SENTINEL), "{}", reply.body);

        // A second put of the same name is version 2, and says so.
        let second = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/put"),
            Some(&cookie(&kit)),
            Some(&form),
        )
        .await;
        assert_eq!(second.status, StatusCode::OK, "{}", second.body);
        assert!(second.body.contains("version 2"), "{}", second.body);
        assert!(second.body.contains("live/api_key"), "{}", second.body);
        assert!(!second.body.contains(SENTINEL), "{}", second.body);

        // The value did land, encrypted, and round-trips through the
        // store — proven with the read path this screen does not have.
        let actor = Actor::new("test").expect("named");
        let read = open(&kit, &kms)
            .get("live/api_key", &actor)
            .await
            .expect("read")
            .expect("present");
        assert_eq!(read.expose(), SENTINEL.as_bytes());
    }

    #[pollster::test]
    async fn the_value_appears_in_no_page_this_screen_owns() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let reply = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/put"),
            Some(&cookie(&kit)),
            Some(&format!("name=live/api_key&value={SENTINEL}")),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        // Every GET page: list, the global detail (which carries the
        // audit trail), and the tenant store's detail — which holds none
        // of the global store's secrets and must say so, not inherit
        // them (store attribution). Each page carries its own positive
        // marker — the thing that would have shown the value.
        let list = send(
            &kit,
            Method::GET,
            &format!("{BASE}/secrets"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(list.status, StatusCode::OK, "{}", list.body);
        assert!(list.body.contains("global"), "{}", list.body);
        assert!(!list.body.contains(SENTINEL), "{}", list.body);

        let global_detail = send(
            &kit,
            Method::GET,
            &format!("{BASE}/secrets/global"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(
            global_detail.status,
            StatusCode::OK,
            "{}",
            global_detail.body
        );
        assert!(
            global_detail.body.contains("live/api_key"),
            "{}",
            global_detail.body
        );
        assert!(
            global_detail.body.contains(">put<"),
            "{}",
            global_detail.body
        );
        assert!(
            !global_detail.body.contains(SENTINEL),
            "{}",
            global_detail.body
        );

        let tenant_detail = send(
            &kit,
            Method::GET,
            &format!("{BASE}/secrets/v1"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(
            tenant_detail.status,
            StatusCode::OK,
            "{}",
            tenant_detail.body
        );
        assert!(
            tenant_detail.body.contains("No secrets in this store yet"),
            "the tenant store holds none of the global store's secrets: {}",
            tenant_detail.body
        );
        assert!(
            !tenant_detail.body.contains(SENTINEL),
            "{}",
            tenant_detail.body
        );

        // Every action's rendered result: delete's confirmation, both
        // plans, delete's result. Each carries its own positive marker —
        // the thing that would have shown the value had there been one.
        let confirm = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/delete"),
            Some(&cookie(&kit)),
            Some("name=live/api_key"),
        )
        .await;
        assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.body);
        assert!(
            confirm.body.contains("Delete <code>live/api_key</code>?"),
            "{}",
            confirm.body
        );
        assert!(!confirm.body.contains(SENTINEL), "{}", confirm.body);

        let rotate_plan = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/rotate"),
            Some(&cookie(&kit)),
            Some(""),
        )
        .await;
        assert_eq!(rotate_plan.status, StatusCode::OK, "{}", rotate_plan.body);
        assert!(rotate_plan.body.contains("plan"), "{}", rotate_plan.body);
        assert!(!rotate_plan.body.contains(SENTINEL), "{}", rotate_plan.body);

        let rewrap_plan = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/rewrap"),
            Some(&cookie(&kit)),
            Some(""),
        )
        .await;
        assert_eq!(rewrap_plan.status, StatusCode::OK, "{}", rewrap_plan.body);
        assert!(rewrap_plan.body.contains("plan"), "{}", rewrap_plan.body);
        assert!(!rewrap_plan.body.contains(SENTINEL), "{}", rewrap_plan.body);

        let deleted = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/delete"),
            Some(&cookie(&kit)),
            Some("name=live/api_key&confirmed=1"),
        )
        .await;
        assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.body);
        assert!(deleted.body.contains("is soft-deleted"), "{}", deleted.body);
        assert!(deleted.body.contains("live/api_key"), "{}", deleted.body);
        assert!(!deleted.body.contains(SENTINEL), "{}", deleted.body);
    }

    // -- the audit trail ------------------------------------------------

    #[pollster::test]
    async fn a_put_grows_the_audit_chain_attributed_to_the_operator() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let before = audit_count(&kit, "global", "put").await;
        let reply = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/put"),
            Some(&cookie(&kit)),
            Some(&format!("name=live/api_key&value={SENTINEL}")),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(
            audit_count(&kit, "global", "put").await,
            before + 1,
            "the put is on the chain"
        );
        // The actor is the signed-in operator — never a module name,
        // never a constant.
        let actor: String = kit
            .db
            .query(&Statement::new(
                "SELECT actor FROM harness_secret_audit WHERE store = 'global' AND action = \
                 'put' ORDER BY seq DESC LIMIT 1",
            ))
            .await
            .expect("query")
            .first()
            .and_then(|row| row.get("actor"))
            .expect("the row exists");
        assert_eq!(actor, EMAIL, "who did this must be who is signed in");
        // And the chain still verifies with the new row on it.
        verify(&StoreId::Global, kit.db.as_ref())
            .await
            .expect("the chain verifies after the put");
    }

    // -- key actions ----------------------------------------------------

    #[pollster::test]
    async fn rotation_plans_first_and_only_runs_on_the_second_press() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let actor = Actor::new("seed").expect("named");
        open(&kit, &kms)
            .put("stripe/api_key", &SecretBytes::from("v1-value"), &actor)
            .await
            .expect("seed put");
        let keys_before: i64 = kit
            .db
            .query(&Statement::new(
                "SELECT COUNT(*) AS n FROM harness_secret_keys",
            ))
            .await
            .expect("count")
            .first()
            .and_then(|row| row.get::<i64>("n"))
            .unwrap_or(0);

        // First press: a plan, nothing changed.
        let plan = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/rotate"),
            Some(&cookie(&kit)),
            Some(""),
        )
        .await;
        assert_eq!(plan.status, StatusCode::OK, "{}", plan.body);
        assert!(plan.body.contains("— plan"), "{}", plan.body);
        assert!(plan.body.contains("would be re-encrypted"), "{}", plan.body);
        assert!(plan.body.contains("Run the rotation"), "{}", plan.body);
        let keys_after_plan: i64 = kit
            .db
            .query(&Statement::new(
                "SELECT COUNT(*) AS n FROM harness_secret_keys",
            ))
            .await
            .expect("count")
            .first()
            .and_then(|row| row.get::<i64>("n"))
            .unwrap_or(0);
        assert_eq!(keys_after_plan, keys_before, "a plan must change nothing");

        // Second press: it runs, and the secret survives it.
        let run = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/rotate"),
            Some(&cookie(&kit)),
            Some("run=1"),
        )
        .await;
        assert_eq!(run.status, StatusCode::OK, "{}", run.body);
        assert!(run.body.contains("were re-encrypted"), "{}", run.body);
        assert!(
            run.body.contains("The active key moved from"),
            "{}",
            run.body
        );
        let keys_after_run: i64 = kit
            .db
            .query(&Statement::new(
                "SELECT COUNT(*) AS n FROM harness_secret_keys",
            ))
            .await
            .expect("count")
            .first()
            .and_then(|row| row.get::<i64>("n"))
            .unwrap_or(0);
        assert_eq!(keys_after_run, keys_before + 1, "the run added a key");
        let read = open(&kit, &kms)
            .get("stripe/api_key", &Actor::new("test").expect("named"))
            .await
            .expect("read")
            .expect("present");
        assert_eq!(
            read.expose(),
            b"v1-value",
            "rotation must not lose the value"
        );
    }

    #[pollster::test]
    async fn rewrap_plans_first_and_runs_on_the_second_press() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let actor = Actor::new("seed").expect("named");
        open(&kit, &kms)
            .put("stripe/api_key", &SecretBytes::from("v1-value"), &actor)
            .await
            .expect("seed put");

        let plan = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/rewrap"),
            Some(&cookie(&kit)),
            Some(""),
        )
        .await;
        assert_eq!(plan.status, StatusCode::OK, "{}", plan.body);
        assert!(plan.body.contains("— plan"), "{}", plan.body);
        assert!(plan.body.contains("would be re-wrapped"), "{}", plan.body);
        assert!(plan.body.contains("test-kek"), "{}", plan.body);

        let run = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/rewrap"),
            Some(&cookie(&kit)),
            Some("run=1"),
        )
        .await;
        assert_eq!(run.status, StatusCode::OK, "{}", run.body);
        assert!(run.body.contains("were re-wrapped"), "{}", run.body);
        assert!(
            run.body.contains("No secret was re-encrypted"),
            "{}",
            run.body
        );
        let read = open(&kit, &kms)
            .get("stripe/api_key", &Actor::new("test").expect("named"))
            .await
            .expect("read")
            .expect("present");
        assert_eq!(
            read.expose(),
            b"v1-value",
            "a re-wrap must not touch a secret"
        );
    }

    // -- delete ----------------------------------------------------------

    #[pollster::test]
    async fn delete_needs_a_confirming_second_press_and_then_soft_deletes() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let actor = Actor::new("seed").expect("named");
        open(&kit, &kms)
            .put("stripe/api_key", &SecretBytes::from("v"), &actor)
            .await
            .expect("seed put");

        let first = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/delete"),
            Some(&cookie(&kit)),
            Some("name=stripe/api_key"),
        )
        .await;
        assert_eq!(first.status, StatusCode::OK, "{}", first.body);
        assert!(
            first.body.contains("Yes, delete every version"),
            "the confirmation page carries the second press: {}",
            first.body
        );
        assert!(
            !first.body.contains("is soft-deleted"),
            "the first press must not claim it deleted: {}",
            first.body
        );
        let live: i64 = kit
            .db
            .query(&Statement::new(
                "SELECT COUNT(*) AS n FROM harness_secrets WHERE deleted_at IS NULL",
            ))
            .await
            .expect("count")
            .first()
            .and_then(|row| row.get::<i64>("n"))
            .unwrap_or(0);
        assert_eq!(live, 1, "the first press deleted nothing");

        let second = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/delete"),
            Some(&cookie(&kit)),
            Some("name=stripe/api_key&confirmed=1"),
        )
        .await;
        assert_eq!(second.status, StatusCode::OK, "{}", second.body);
        assert!(second.body.contains("is soft-deleted"), "{}", second.body);
        assert!(
            second.body.contains(">deleted</span>"),
            "the list marks the soft-delete: {}",
            second.body
        );
    }

    // -- the honest no-KMS state -----------------------------------------

    #[pollster::test]
    async fn without_a_kms_every_secrets_route_renders_the_honest_state() {
        let kit = seeded(None).await;
        for uri in [
            &format!("{BASE}/secrets"),
            &format!("{BASE}/secrets/global"),
        ] {
            let page = send(&kit, Method::GET, uri, Some(&cookie(&kit)), None).await;
            assert_eq!(page.status, StatusCode::OK, "{uri}: {}", page.body);
            assert!(
                page.body
                    .contains("No key manager is configured in this deployment"),
                "{uri}: {}",
                page.body
            );
        }
        // The actions too — a POST against a deployment with no KMS is
        // an explained refusal, not a 500 and not a silent no-op.
        let put = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/put"),
            Some(&cookie(&kit)),
            Some("name=x&value=y"),
        )
        .await;
        assert_eq!(put.status, StatusCode::OK, "{}", put.body);
        assert!(
            put.body.contains("No key manager is configured"),
            "{}",
            put.body
        );
        let rotate = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/rotate"),
            Some(&cookie(&kit)),
            Some(""),
        )
        .await;
        assert_eq!(rotate.status, StatusCode::OK, "{}", rotate.body);
        // And nothing was written: there is no store to write to.
        assert!(
            kit.db
                .query(&Statement::new("SELECT name FROM harness_secrets"))
                .await
                .expect("query")
                .is_empty(),
            "a no-KMS deployment must hold no secrets"
        );
    }

    // -- isolation and the gate -------------------------------------------

    #[pollster::test]
    async fn one_account_cannot_open_anothers_store() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let repo = cratefield_accounts::Repository::new(kit.db.clone());
        repo.account_for_login("b@x.co", "B", "acc_2", "t0")
            .await
            .expect("account");
        let token = cratefield_access::issue_session(
            kit.signer.as_ref(),
            "b@x.co",
            NOW,
            cratefield_access::DEFAULT_TTL_SECS,
        );
        let stranger = format!("cf_session={token}");

        let detail = send(
            &kit,
            Method::GET,
            &format!("{BASE}/secrets/v1"),
            Some(&stranger),
            None,
        )
        .await;
        assert_eq!(detail.status, StatusCode::NOT_FOUND, "{}", detail.body);

        let put = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/v1/put"),
            Some(&stranger),
            Some("name=x&value=y"),
        )
        .await;
        assert_eq!(put.status, StatusCode::NOT_FOUND, "{}", put.body);
        assert!(
            kit.db
                .query(&Statement::new("SELECT name FROM harness_secrets"))
                .await
                .expect("query")
                .is_empty(),
            "a refused put must not write"
        );
    }

    #[pollster::test]
    async fn an_unauthenticated_request_is_redirected_to_the_login_gate() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let reply = send(&kit, Method::GET, &format!("{BASE}/secrets"), None, None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_eq!(reply.location, "/v1/console/login");
    }

    // -- the dev-key gate --------------------------------------------------

    #[test]
    fn the_dev_kek_is_refused_in_production_and_allowed_elsewhere() {
        use cratefield_core::MapConfig;
        let module = crate::Dashboard::default();
        let production = MapConfig::from_pairs([
            ("ENV", "production"),
            ("DASHBOARD_DEV_KEK", "/run/secrets/kek"),
        ]);
        assert!(
            module.validate_config(&production).is_err(),
            "a development KEK switched on in production is the one mistake here \
             that cannot be walked back"
        );
        let development = MapConfig::from_pairs([
            ("ENV", "development"),
            ("DASHBOARD_DEV_KEK", "/run/secrets/kek"),
        ]);
        assert!(module.validate_config(&development).is_ok());
        let bare = MapConfig::default();
        assert!(module.validate_config(&bare).is_ok());
    }

    // -- form parsing -----------------------------------------------------

    #[test]
    fn url_decoding_handles_percent_escapes_and_plus_without_strings_for_values() {
        assert_eq!(url_decode(b"a%20b+c"), b"a b c");
        assert_eq!(url_decode(b"%2Fpath"), b"/path");
        assert_eq!(url_decode(b"100%"), b"100%");
        assert_eq!(url_decode(b""), b"");
        let fields = parse_form(b"name=stripe%2Fapi_key&value=SEN%54INEL+9f3a");
        assert_eq!(fields[0].name, "name");
        assert_eq!(fields[0].value, b"stripe/api_key");
        assert_eq!(fields[1].name, "value");
        assert_eq!(fields[1].value, b"SENTINEL 9f3a");
    }

    #[pollster::test]
    async fn a_percent_encoded_value_round_trips_through_the_form() {
        let kms = kms();
        let kit = seeded(Some(kms.clone())).await;
        let reply = send(
            &kit,
            Method::POST,
            &format!("{BASE}/secrets/global/put"),
            Some(&cookie(&kit)),
            Some("name=encoded%2Fkey&value=SEN%54INEL+plus+value"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let read = open(&kit, &kms)
            .get("encoded/key", &Actor::new("test").expect("named"))
            .await
            .expect("read")
            .expect("present");
        assert_eq!(
            read.expose(),
            b"SENTINEL plus value",
            "the form body must decode exactly what was sent"
        );
        assert!(
            !reply.body.contains("SENTINEL plus value"),
            "{}",
            reply.body
        );
    }
}
