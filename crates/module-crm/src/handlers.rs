//! The admin routes under `/v1/crm/admin/*` (issue #572).
//!
//! Every route is an admin action gated by the harness `ADMIN_TOKEN` bearer
//! ([`require_admin`]); the module has no public read or write endpoint, so
//! it needs no captcha and declares no public surface. The store does the
//! writing ([`crate::store`]); this module turns bodies into store calls,
//! store refusals into problem+json, and emits the events other modules may
//! subscribe to.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use cratefield_core::{
    Action, Audience, Clock, Column, Database, IdGen, Json, MAX_EXPORT_ROWS, ModuleContext,
    Outcome, Problem, ProblemDef, Scope, Surface, View, csv_row, require_admin,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::store::{
    self, Contact, ContactUpdate, ContactUpsert, CrmError, Field, Organisation, OrganisationUpdate,
    OrganisationUpsert, Record,
};

/// A contact was filed or changed, keyed on its normalized address.
pub(crate) const EVENT_CONTACT_CREATED: &str = "crm.contact.created";
/// A contact's row was written again: an upsert that matched, a PATCH, or a
/// merge.
pub(crate) const EVENT_CONTACT_UPDATED: &str = "crm.contact.updated";
/// An organisation was filed, keyed on its domain.
pub(crate) const EVENT_ORGANISATION_CREATED: &str = "crm.organisation.created";

/// The `generation` in the body is not the one the row carries now.
///
/// A slug of this module's own: the optimistic-concurrency guard is this
/// module's contract, so a caller branching on the `type` can tell "somebody
/// else edited this record" from every other conflict.
pub(crate) const STALE_GENERATION: ProblemDef = ProblemDef {
    slug: "crm-stale-generation",
    status: StatusCode::CONFLICT,
    title: "The record has changed since you read it",
    description: "The `generation` in the body is not the one the row holds now, so somebody \
                  else wrote to it in between. Nothing was changed: read the record again, \
                  reapply your edit to the current values and retry with the new generation.",
};

/// A write tried to move a record onto another's natural key — a contact's
/// normalized address, or an organisation's domain.
///
/// A slug of this module's own, kept apart from [`STALE_GENERATION`]: the two
/// are both `409`, but a caller resolves them differently, so the `type` has
/// to tell them apart.
pub(crate) const NATURAL_KEY_TAKEN: ProblemDef = ProblemDef {
    slug: "crm-already-exists",
    status: StatusCode::CONFLICT,
    title: "That value is already taken",
    description: "A contact's normalized email address and an organisation's domain are each \
                  unique. Another row already holds the value you tried to set, so nothing was \
                  changed: use a different value, or merge the two records.",
};

pub(crate) fn router(ctx: Arc<ModuleContext>) -> axum::Router {
    axum::Router::new()
        .route("/admin/contacts.csv", get(admin_contacts_export))
        .route("/admin/organisations.csv", get(admin_organisations_export))
        .route("/admin/contacts", post(admin_contact_create))
        .route("/admin/contacts/merge", post(admin_contact_merge))
        .route(
            "/admin/contacts/{id}",
            patch(admin_contact_update).delete(admin_contact_delete),
        )
        .route("/admin/organisations", post(admin_organisation_create))
        .route(
            "/admin/organisations/{id}",
            patch(admin_organisation_update).delete(admin_organisation_delete),
        )
        .route("/admin/tags", post(admin_tag_create))
        .route("/admin/tags/tag", post(admin_tag_subject))
        .route("/admin/tags/untag", post(admin_untag_subject))
        .with_state(ctx)
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// The ports every handler needs, cloned out of the context once.
///
/// A composition missing one is a build error (`requires()`), so a `None`
/// here is a request-time 500 and never a silent default: the guards run
/// against whatever the deployment actually wired.
struct Runtime {
    db: Arc<dyn Database>,
    clock: Arc<dyn Clock>,
    id_gen: Arc<dyn IdGen>,
}

impl Runtime {
    fn of(ctx: &ModuleContext) -> Option<Self> {
        Some(Self {
            db: ctx.ports.db.clone()?,
            clock: ctx.ports.clock.clone()?,
            id_gen: ctx.ports.id_gen.clone()?,
        })
    }

    /// RFC 3339 UTC, second resolution — the format every timestamp column in
    /// this module holds.
    fn now(&self) -> String {
        self.clock
            .now()
            .replace_nanosecond(0)
            .expect("truncation stays in range")
            .format(&Rfc3339)
            .unwrap_or_default()
    }

    fn ulid(&self) -> String {
        self.id_gen.ulid()
    }
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

/// The admin gate plus the ports, the preamble every handler shares.
fn ready(ctx: &ModuleContext, headers: &HeaderMap, scope: &Scope) -> Result<Runtime, Problem> {
    require_admin(&*ctx.config, headers).map_err(|problem| problem.instance(&scope.request_id))?;
    Runtime::of(ctx).ok_or_else(|| internal(scope))
}

/// Turns a store refusal into the problem the route answers with.
///
/// A bad address, a blank name, a non-object JSON field or an unknown
/// `organisation_id` is the caller's input (400); a natural key already
/// another row's is a `409`; a database failure is ours, and is logged rather
/// than described to the caller (500).
fn store_problem(err: CrmError, scope: &Scope) -> Problem {
    match err {
        CrmError::InvalidEmail(reason) => {
            Problem::validation_failed(format!("email: {reason}")).instance(&scope.request_id)
        }
        CrmError::BlankName => Problem::validation_failed("name must not be blank".to_owned())
            .instance(&scope.request_id),
        CrmError::NotAnObject(field) => {
            Problem::validation_failed(format!("{field} must be a JSON object"))
                .instance(&scope.request_id)
        }
        CrmError::Taken(field) => Problem::new(&NATURAL_KEY_TAKEN)
            .with_detail(format!("that {field} is already in use"))
            .instance(&scope.request_id),
        CrmError::UnknownOrganisation => {
            Problem::validation_failed("organisation_id names no organisation".to_owned())
                .instance(&scope.request_id)
        }
        CrmError::Db(err) => {
            tracing::error!(error = %err, "crm: a database statement failed");
            internal(scope)
        }
    }
}

fn stale(scope: &Scope) -> Problem {
    Problem::new(&STALE_GENERATION).instance(&scope.request_id)
}

fn not_found(scope: &Scope) -> Problem {
    Problem::not_found().instance(&scope.request_id)
}

/// The row with this `id`, or a 404. Every route that names a record begins
/// with this, so "no such id" is one problem shape everywhere.
async fn by_id<T: Record>(rt: &Runtime, scope: &Scope, id: &str) -> Result<T, Problem> {
    store::find::<T>(&*rt.db, "id", id)
        .await
        .map_err(|err| store_problem(err.into(), scope))?
        .ok_or_else(|| not_found(scope))
}

/// The `201`/`200` an upsert answers with, by whether it inserted.
fn upsert_status(created: bool) -> StatusCode {
    if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    }
}

fn ok_json() -> Response {
    Json(json!({ "ok": true })).into_response()
}

/// One PATCH field's deserializer: `(absent)`, `null` and a value must stay
/// three different requests, and the derived `Option<Option<T>>` collapses
/// the first two. This reads the field as `Option<T>` and wraps it, so only
/// an absent key yields the outer `None`.
#[allow(clippy::option_option)] // The three states are the point; see the alias.
fn explicit<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// A CSV export: the header, one clamped page of rows, and the
/// `x-cf-export-more` signal. The two exports differ only in their record
/// type, so the paging lives here once.
async fn export<T: Record + CsvRow>(
    rt: &Runtime,
    scope: &Scope,
    query: &ExportQuery,
) -> Result<Response, Problem> {
    let cap = u32::try_from(MAX_EXPORT_ROWS).unwrap_or(u32::MAX);
    let limit = query.limit.unwrap_or(cap).clamp(1, cap);
    let offset = u64::from(query.offset.unwrap_or(0));
    // One row past the page: if it exists, there is more to export.
    let rows = store::list::<T>(&*rt.db, u64::from(limit) + 1, offset)
        .await
        .map_err(|err| store_problem(err.into(), scope))?;
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let more = rows.len() > limit;
    let rows = if more { &rows[..limit] } else { &rows[..] };
    let mut body = String::from(T::HEADER);
    for row in rows {
        let cells = row.cells();
        let cells: Vec<&str> = cells.iter().map(String::as_str).collect();
        body.push_str(&csv_row(&cells));
    }
    Ok(csv_response(body, more))
}

/// A CSV answer, with `x-cf-export-more` when the page was cut short. The
/// caller pages by advancing `offset`.
fn csv_response(body: String, more: bool) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    if more {
        headers.insert(
            axum::http::HeaderName::from_static("x-cf-export-more"),
            HeaderValue::from_static("true"),
        );
    }
    (StatusCode::OK, headers, body).into_response()
}

// ---------------------------------------------------------------------------
// Request bodies and responses
// ---------------------------------------------------------------------------

/// A new (or re-filed) contact. `email` is the natural key.
#[derive(Debug, Deserialize, JsonSchema)]
struct ContactBody {
    #[schemars(extend("x-cf-label" = "Email", "x-cf-widget" = "email"))]
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    locale: Option<String>,
    #[serde(default)]
    organisation_id: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    data: Option<Value>,
}

/// A contact PATCH. The body carries the `generation` it read.
#[derive(Debug, Deserialize, JsonSchema)]
struct ContactPatch {
    /// The generation the caller last read; a mismatch is `409`.
    generation: i64,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    email: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    name: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    phone: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    locale: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    organisation_id: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    source: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<serde_json::Value>")]
    data: Field<Value>,
}

/// A new (or re-filed) organisation. `domain` is the natural key when it is
/// present.
#[derive(Debug, Deserialize, JsonSchema)]
struct OrganisationBody {
    name: String,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    website: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    address: Option<Value>,
    #[serde(default)]
    data: Option<Value>,
}

/// An organisation PATCH.
#[derive(Debug, Deserialize, JsonSchema)]
struct OrganisationPatch {
    generation: i64,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    name: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    domain: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    website: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    email: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<String>")]
    phone: Field<String>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<serde_json::Value>")]
    address: Field<Value>,
    #[serde(default, deserialize_with = "explicit")]
    #[schemars(with = "Option<serde_json::Value>")]
    data: Field<Value>,
}

/// Two contacts to fold into one: `keep` survives, `merge` goes.
#[derive(Debug, Deserialize, JsonSchema)]
struct MergeBody {
    keep: String,
    #[serde(rename = "merge")]
    merge: String,
}

/// A tag to create, or whose colour to set.
#[derive(Debug, Deserialize, JsonSchema)]
struct TagBody {
    name: String,
    #[serde(default)]
    color: Option<String>,
}

/// A subject to file a tag against.
#[derive(Debug, Deserialize, JsonSchema)]
struct TagSubjectBody {
    tag_id: String,
    /// `contact`, `organisation` or `item`.
    subject_type: String,
    subject_id: String,
}

/// The CSV page window, the same two parameters as the waitlist export.
#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ExportQuery {
    limit: Option<u32>,
    offset: Option<u32>,
}

impl ContactBody {
    fn into_upsert(self) -> ContactUpsert {
        ContactUpsert {
            email: self.email,
            name: self.name,
            phone: self.phone,
            locale: self.locale,
            organisation_id: self.organisation_id,
            source: self.source,
            data: self.data,
        }
    }
}

impl ContactPatch {
    fn into_update(self) -> ContactUpdate {
        ContactUpdate {
            email: self.email,
            name: self.name,
            phone: self.phone,
            locale: self.locale,
            organisation_id: self.organisation_id,
            source: self.source,
            data: self.data,
        }
    }
}

impl OrganisationBody {
    fn into_upsert(self) -> OrganisationUpsert {
        OrganisationUpsert {
            name: self.name,
            domain: self.domain,
            website: self.website,
            email: self.email,
            phone: self.phone,
            address: self.address,
            data: self.data,
        }
    }
}

impl OrganisationPatch {
    fn into_update(self) -> OrganisationUpdate {
        OrganisationUpdate {
            name: self.name,
            domain: self.domain,
            website: self.website,
            email: self.email,
            phone: self.phone,
            address: self.address,
            data: self.data,
        }
    }
}

fn contact_json(contact: &Contact) -> Value {
    json!({
        "id": contact.id,
        "email": contact.email,
        "emailNormalized": contact.email_normalized,
        "name": contact.name,
        "phone": contact.phone,
        "locale": contact.locale,
        "organisationId": contact.organisation_id,
        "source": contact.source,
        "data": contact.data,
        "createdAt": contact.created_at,
        "updatedAt": contact.updated_at,
        "generation": contact.generation,
    })
}

fn organisation_json(organisation: &Organisation) -> Value {
    json!({
        "id": organisation.id,
        "name": organisation.name,
        "domain": organisation.domain,
        "website": organisation.website,
        "email": organisation.email,
        "phone": organisation.phone,
        "address": organisation.address,
        "data": organisation.data,
        "createdAt": organisation.created_at,
        "updatedAt": organisation.updated_at,
        "generation": organisation.generation,
    })
}

/// A record the CSV export can write: its header row, and one row's cells in
/// the same order. `cells` clones because the writer needs borrowed `&str`
/// and a numeric column has no other way to become one.
trait CsvRow {
    const HEADER: &'static str;
    fn cells(&self) -> Vec<String>;
}

impl CsvRow for Contact {
    const HEADER: &'static str = "id,email,email_normalized,name,phone,locale,organisation_id,\
                                  source,data,created_at,updated_at,generation\n";

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.email.clone().unwrap_or_default(),
            self.email_normalized.clone().unwrap_or_default(),
            self.name.clone().unwrap_or_default(),
            self.phone.clone().unwrap_or_default(),
            self.locale.clone().unwrap_or_default(),
            self.organisation_id.clone().unwrap_or_default(),
            self.source.clone().unwrap_or_default(),
            self.data.to_string(),
            self.created_at.clone(),
            self.updated_at.clone(),
            self.generation.to_string(),
        ]
    }
}

impl CsvRow for Organisation {
    const HEADER: &'static str =
        "id,name,domain,website,email,phone,address,data,created_at,updated_at,generation\n";

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.name.clone(),
            self.domain.clone().unwrap_or_default(),
            self.website.clone().unwrap_or_default(),
            self.email.clone().unwrap_or_default(),
            self.phone.clone().unwrap_or_default(),
            self.address.to_string(),
            self.data.to_string(),
            self.created_at.clone(),
            self.updated_at.clone(),
            self.generation.to_string(),
        ]
    }
}

// ---------------------------------------------------------------------------
// Contact routes
// ---------------------------------------------------------------------------

async fn admin_contact_create(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Json(body): Json<ContactBody>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    let upserted = store::upsert_contact(&*rt.db, &rt.ulid(), &body.into_upsert(), &rt.now())
        .await
        .map_err(|err| store_problem(err, &scope))?;
    // An update is announced as well: a caller subscribed to "this contact
    // changed" wants both, and `created` in the status tells them which.
    let event = if upserted.created {
        EVENT_CONTACT_CREATED
    } else {
        EVENT_CONTACT_UPDATED
    };
    ctx.events
        .emit_in(&scope, event, json!({ "contact_id": upserted.record.id }));
    Ok((
        upsert_status(upserted.created),
        Json(contact_json(&upserted.record)),
    )
        .into_response())
}

async fn admin_contact_update(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ContactPatch>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    let (generation, update) = (body.generation, body.into_update());
    by_id::<Contact>(&rt, &scope, &id).await?;
    let touched = store::update_contact(&*rt.db, &id, generation, &update, &rt.now())
        .await
        .map_err(|err| store_problem(err, &scope))?;
    if touched == 0 {
        // The row exists (read above without an error), so zero rows can only
        // mean the generation moved under us. Read and write are not atomic
        // together — the guard in the statement is what makes it safe anyway.
        return Err(stale(&scope));
    }
    let updated = by_id::<Contact>(&rt, &scope, &id).await?;
    ctx.events.emit_in(
        &scope,
        EVENT_CONTACT_UPDATED,
        json!({ "contact_id": updated.id }),
    );
    Ok(Json(contact_json(&updated)).into_response())
}

async fn admin_contact_delete(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    by_id::<Contact>(&rt, &scope, &id).await?;
    store::delete_contact(&*rt.db, &id)
        .await
        .map_err(|err| store_problem(err.into(), &scope))?;
    Ok(ok_json())
}

/// `POST /v1/crm/admin/contacts/merge` — fold `merge` into `keep`.
///
/// The whole fold is one `batch_atomic` in [`store::merge_contacts`], so a
/// failure leaves both contacts exactly as they were.
async fn admin_contact_merge(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Json(body): Json<MergeBody>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    if body.keep == body.merge {
        return Err(
            Problem::validation_failed("keep and merge must be two different contacts")
                .instance(&scope.request_id),
        );
    }
    let keep = by_id::<Contact>(&rt, &scope, &body.keep).await?;
    let merge = by_id::<Contact>(&rt, &scope, &body.merge).await?;
    store::merge_contacts(&*rt.db, &keep, &merge, &rt.now())
        .await
        .map_err(|err| store_problem(err.into(), &scope))?;
    let kept = by_id::<Contact>(&rt, &scope, &keep.id).await?;
    ctx.events.emit_in(
        &scope,
        EVENT_CONTACT_UPDATED,
        json!({ "contact_id": kept.id, "merged_from": merge.id }),
    );
    Ok(Json(contact_json(&kept)).into_response())
}

async fn admin_contacts_export(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    export::<Contact>(&rt, &scope, &query).await
}

// ---------------------------------------------------------------------------
// Organisation routes
// ---------------------------------------------------------------------------

async fn admin_organisation_create(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Json(body): Json<OrganisationBody>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    let upserted = store::upsert_organisation(&*rt.db, &rt.ulid(), &body.into_upsert(), &rt.now())
        .await
        .map_err(|err| store_problem(err, &scope))?;
    // Only a create is announced: the module declares no
    // `crm.organisation.updated`, and inventing one here would emit an event
    // no subscription list carries.
    if upserted.created {
        ctx.events.emit_in(
            &scope,
            EVENT_ORGANISATION_CREATED,
            json!({ "organisation_id": upserted.record.id }),
        );
    }
    Ok((
        upsert_status(upserted.created),
        Json(organisation_json(&upserted.record)),
    )
        .into_response())
}

async fn admin_organisation_update(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<OrganisationPatch>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    let (generation, update) = (body.generation, body.into_update());
    by_id::<Organisation>(&rt, &scope, &id).await?;
    let touched = store::update_organisation(&*rt.db, &id, generation, &update, &rt.now())
        .await
        .map_err(|err| store_problem(err, &scope))?;
    if touched == 0 {
        return Err(stale(&scope));
    }
    let updated = by_id::<Organisation>(&rt, &scope, &id).await?;
    Ok(Json(organisation_json(&updated)).into_response())
}

async fn admin_organisation_delete(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    by_id::<Organisation>(&rt, &scope, &id).await?;
    store::delete_organisation(&*rt.db, &id)
        .await
        .map_err(|err| store_problem(err.into(), &scope))?;
    Ok(ok_json())
}

async fn admin_organisations_export(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    export::<Organisation>(&rt, &scope, &query).await
}

// ---------------------------------------------------------------------------
// Tag routes
// ---------------------------------------------------------------------------

async fn admin_tag_create(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Json(body): Json<TagBody>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(
            Problem::validation_failed("name must not be blank").instance(&scope.request_id)
        );
    }
    let tag = store::upsert_tag(&*rt.db, &rt.ulid(), name, body.color.as_deref())
        .await
        .map_err(|err| store_problem(err.into(), &scope))?;
    Ok((
        upsert_status(tag.created),
        Json(json!({ "id": tag.record.id, "name": tag.record.name, "color": tag.record.color })),
    )
        .into_response())
}

/// Validates the polymorphic subject type and resolves the tag, the shared
/// preamble of the two tagging routes.
async fn tag_and_subject(
    rt: &Runtime,
    scope: &Scope,
    body: &TagSubjectBody,
) -> Result<(), Problem> {
    if !store::is_subject_type(&body.subject_type) {
        return Err(Problem::validation_failed(
            "subject_type must be one of: contact, organisation, item",
        )
        .instance(&scope.request_id));
    }
    by_id::<store::Tag>(rt, scope, &body.tag_id).await?;
    Ok(())
}

async fn admin_tag_subject(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Json(body): Json<TagSubjectBody>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    tag_and_subject(&rt, &scope, &body).await?;
    // Deliberately no existence check on `subject_id`: the table is
    // polymorphic, and an `item` is a row another module or the venture owns,
    // which this module cannot see. Its type is the caller's claim.
    store::tag_subject(&*rt.db, &body.tag_id, &body.subject_type, &body.subject_id)
        .await
        .map_err(|err| store_problem(err.into(), &scope))?;
    Ok(ok_json())
}

async fn admin_untag_subject(
    scope: Scope,
    State(ctx): State<Arc<ModuleContext>>,
    headers: HeaderMap,
    Json(body): Json<TagSubjectBody>,
) -> Result<Response, Problem> {
    let rt = ready(&ctx, &headers, &scope)?;
    tag_and_subject(&rt, &scope, &body).await?;
    let removed = store::untag_subject(&*rt.db, &body.tag_id, &body.subject_type, &body.subject_id)
        .await
        .map_err(|err| store_problem(err.into(), &scope))?;
    Ok(Json(json!({ "ok": true, "removed": removed })).into_response())
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

/// An action of this module: admin-only, answering JSON. `Action::delete`
/// already defaults to exactly this; the re-statement is what makes the
/// `PATCH` and export routes match it.
fn admin(action: Action) -> Action {
    action.audience(Audience::Admin).outcome(Outcome::Json)
}

fn table(key: &str, columns: &[(&'static str, &'static str)]) -> View {
    View::table(
        key,
        columns
            .iter()
            .map(|(key, label)| Column::new(*key, *label))
            .collect(),
    )
}

pub(crate) fn surface() -> Surface {
    Surface::new()
        .action(admin(Action::get("contacts-export", "/admin/contacts.csv")).input::<ExportQuery>())
        .action(
            admin(Action::get(
                "organisations-export",
                "/admin/organisations.csv",
            ))
            .input::<ExportQuery>(),
        )
        .action(admin(Action::post("contact-create", "/admin/contacts")).input::<ContactBody>())
        .action(
            admin(Action::new(
                "contact-update",
                Method::PATCH,
                "/admin/contacts/{id}",
            ))
            .input::<ContactPatch>(),
        )
        .action(Action::delete("contact-delete", "/admin/contacts/{id}"))
        .action(admin(Action::post("contact-merge", "/admin/contacts/merge")).input::<MergeBody>())
        .action(
            admin(Action::post("organisation-create", "/admin/organisations"))
                .input::<OrganisationBody>(),
        )
        .action(
            admin(Action::new(
                "organisation-update",
                Method::PATCH,
                "/admin/organisations/{id}",
            ))
            .input::<OrganisationPatch>(),
        )
        .action(Action::delete(
            "organisation-delete",
            "/admin/organisations/{id}",
        ))
        .action(admin(Action::post("tag-create", "/admin/tags")).input::<TagBody>())
        .action(admin(Action::post("tag-subject", "/admin/tags/tag")).input::<TagSubjectBody>())
        .action(admin(Action::post("untag-subject", "/admin/tags/untag")).input::<TagSubjectBody>())
        .view(table(
            "contacts-export",
            &[
                ("id", "Id"),
                ("email", "Email"),
                ("email_normalized", "Normalized email"),
                ("name", "Name"),
                ("phone", "Phone"),
                ("locale", "Locale"),
                ("organisation_id", "Organisation"),
                ("source", "Source"),
                ("data", "Data"),
                ("created_at", "Created"),
                ("updated_at", "Updated"),
                ("generation", "Generation"),
            ],
        ))
        .view(table(
            "organisations-export",
            &[
                ("id", "Id"),
                ("name", "Name"),
                ("domain", "Domain"),
                ("website", "Website"),
                ("email", "Email"),
                ("phone", "Phone"),
                ("address", "Address"),
                ("data", "Data"),
                ("created_at", "Created"),
                ("updated_at", "Updated"),
                ("generation", "Generation"),
            ],
        ))
}
