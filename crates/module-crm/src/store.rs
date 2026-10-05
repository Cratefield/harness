//! The CRM's tables, read and written in the portable SQL subset (ADR 0004)
//! — one statement set that SQLite, D1 and Postgres all accept.
//!
//! [`upsert_contact`] and [`upsert_organisation`] are the module's public
//! write API: another module or a venture's own code files a person or a
//! company idempotently, keyed on the natural key (a contact on its
//! normalized address, an organisation on its domain) rather than on an id it
//! would have to remember. Everything else here is the admin routes' data
//! access.

use cratefield_core::{Database, DbError, Row, Statement, normalize_email, validation_error};
use sea_query::Value as SeaValue;
use serde_json::{Map, Value, json};

/// The `subject_type` a contact's taggings carry. Must match the CHECK in
/// `0001_init.sql`.
pub(crate) const SUBJECT_CONTACT: &str = "contact";
/// The `subject_type` an organisation's taggings carry.
pub(crate) const SUBJECT_ORGANISATION: &str = "organisation";

/// Whether `subject_type` is one of the three the tagging CHECK accepts.
///
/// `item` is for rows a venture owns — the harness cannot know that a
/// `subject_id` filed under it exists, which is exactly why the type is
/// explicit rather than guessed from the id.
#[must_use]
pub fn is_subject_type(subject_type: &str) -> bool {
    matches!(subject_type, "contact" | "organisation" | "item")
}

/// One contact.
#[derive(Debug, Clone, PartialEq)]
pub struct Contact {
    pub id: String,
    pub email: Option<String>,
    pub email_normalized: Option<String>,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub locale: Option<String>,
    pub organisation_id: Option<String>,
    pub source: Option<String>,
    /// The structured fields, as stored; `{}` when the column is blank.
    pub data: Value,
    pub created_at: String,
    pub updated_at: String,
    pub generation: i64,
}

/// One organisation.
#[derive(Debug, Clone, PartialEq)]
pub struct Organisation {
    pub id: String,
    pub name: String,
    pub domain: Option<String>,
    pub website: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// The postal address, as stored; `{}` when the column is blank.
    pub address: Value,
    pub data: Value,
    pub created_at: String,
    pub updated_at: String,
    pub generation: i64,
}

/// One tag.
#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}

/// What [`upsert_contact`] is given. `email` is the natural key; every other
/// field is optional, and on a contact that already exists a field left
/// `None` keeps its stored value.
#[derive(Debug, Clone)]
pub struct ContactUpsert {
    pub email: String,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub locale: Option<String>,
    pub organisation_id: Option<String>,
    pub source: Option<String>,
    /// A JSON object; `None` stores `{}` on a create and leaves the stored
    /// value alone on an update.
    pub data: Option<Value>,
}

/// What [`upsert_organisation`] is given. `name` is required; `domain` is the
/// natural key and is what makes the call idempotent.
#[derive(Debug, Clone)]
pub struct OrganisationUpsert {
    pub name: String,
    pub domain: Option<String>,
    pub website: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// A JSON object; `None` stores `{}` on a create and leaves the stored
    /// value alone on an update.
    pub address: Option<Value>,
    pub data: Option<Value>,
}

/// The stored row, and whether the call inserted it.
#[derive(Debug, Clone, PartialEq)]
pub struct Upserted<T> {
    pub record: T,
    /// `true` when the call inserted a row, `false` when it updated one.
    pub created: bool,
}

/// Why a store call refused: the caller's input was not usable, or the
/// database refused the statement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CrmError {
    /// The address did not normalize to something valid; the payload is the
    /// validator's reason.
    InvalidEmail(&'static str),
    /// A name was empty or whitespace only.
    BlankName,
    /// A JSON field was not an object.
    NotAnObject(&'static str),
    /// A supplied value is another row's natural key; the payload names the
    /// field (`email` or `domain`).
    Taken(&'static str),
    /// A supplied `organisation_id` names no organisation this database holds.
    UnknownOrganisation,
    /// The database refused the statement.
    Db(DbError),
}

impl std::fmt::Display for CrmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEmail(reason) => write!(f, "email: {reason}"),
            Self::BlankName => f.write_str("name must not be blank"),
            Self::NotAnObject(field) => write!(f, "{field} must be a JSON object"),
            Self::Taken(field) => write!(f, "{field} is already in use"),
            Self::UnknownOrganisation => f.write_str("organisation_id names no organisation"),
            Self::Db(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for CrmError {}

impl From<DbError> for CrmError {
    fn from(err: DbError) -> Self {
        Self::Db(err)
    }
}

/// One PATCH field: `None` leaves the column alone, `Some(None)` clears it,
/// `Some(Some(v))` sets it. Spelled out because "absent", "null" and a value
/// are three different requests and `Option<T>` can only carry two.
#[allow(clippy::option_option)]
pub(crate) type Field<T> = Option<Option<T>>;

/// The columns a contact PATCH may set.
pub(crate) struct ContactUpdate {
    pub email: Field<String>,
    pub name: Field<String>,
    pub phone: Field<String>,
    pub locale: Field<String>,
    pub organisation_id: Field<String>,
    pub source: Field<String>,
    pub data: Field<Value>,
}

/// The columns an organisation PATCH may set.
pub(crate) struct OrganisationUpdate {
    pub name: Field<String>,
    pub domain: Field<String>,
    pub website: Field<String>,
    pub email: Field<String>,
    pub phone: Field<String>,
    pub address: Field<Value>,
    pub data: Field<Value>,
}

// ---------------------------------------------------------------------------
// Value plumbing
// ---------------------------------------------------------------------------

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

fn null() -> SeaValue {
    SeaValue::String(None)
}

fn opt_text(value: Option<&str>) -> SeaValue {
    value.map_or_else(null, text)
}

fn json_text(value: &Value) -> SeaValue {
    text(&value.to_string())
}

fn opt_json(value: Option<&Value>) -> SeaValue {
    value.map_or_else(null, json_text)
}

fn int(value: i64) -> SeaValue {
    SeaValue::BigInt(Some(value))
}

fn limit(n: u64) -> SeaValue {
    int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// A stored JSON column, or `{}` when the text does not parse. It is only
/// ever written by the routes, which validate it first; the fallback is for a
/// row some other writer left behind.
fn parse_json(raw: Option<String>) -> Value {
    raw.and_then(|text| serde_json::from_str(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn row_text(row: &Row, column: &str) -> Option<String> {
    row.get::<Option<String>>(column).flatten()
}

fn row_id(row: &Row) -> String {
    row.get::<String>("id").unwrap_or_default()
}

fn row_time(row: &Row, column: &str) -> String {
    row.get::<String>(column).unwrap_or_default()
}

fn row_generation(row: &Row) -> i64 {
    row.get::<i64>("generation").unwrap_or(1)
}

/// A row of one of the module's three record tables: the columns to select
/// and how to read them back.
pub(crate) trait Record: Sized {
    const TABLE: &'static str;
    const COLUMNS: &'static str;
    fn from_row(row: &Row) -> Self;
}

impl Record for Contact {
    const TABLE: &'static str = "crm_contacts";
    const COLUMNS: &'static str = "id, email, email_normalized, name, phone, locale, \
                                   organisation_id, source, data, created_at, updated_at, generation";

    fn from_row(row: &Row) -> Self {
        Self {
            id: row_id(row),
            email: row_text(row, "email"),
            email_normalized: row_text(row, "email_normalized"),
            name: row_text(row, "name"),
            phone: row_text(row, "phone"),
            locale: row_text(row, "locale"),
            organisation_id: row_text(row, "organisation_id"),
            source: row_text(row, "source"),
            data: parse_json(row_text(row, "data")),
            created_at: row_time(row, "created_at"),
            updated_at: row_time(row, "updated_at"),
            generation: row_generation(row),
        }
    }
}

impl Record for Organisation {
    const TABLE: &'static str = "crm_organisations";
    const COLUMNS: &'static str = "id, name, domain, website, email, phone, address, data, \
                                   created_at, updated_at, generation";

    fn from_row(row: &Row) -> Self {
        Self {
            id: row_id(row),
            name: row.get::<String>("name").unwrap_or_default(),
            domain: row_text(row, "domain"),
            website: row_text(row, "website"),
            email: row_text(row, "email"),
            phone: row_text(row, "phone"),
            address: parse_json(row_text(row, "address")),
            data: parse_json(row_text(row, "data")),
            created_at: row_time(row, "created_at"),
            updated_at: row_time(row, "updated_at"),
            generation: row_generation(row),
        }
    }
}

impl Record for Tag {
    const TABLE: &'static str = "crm_tags";
    const COLUMNS: &'static str = "id, name, color";

    fn from_row(row: &Row) -> Self {
        Self {
            id: row_id(row),
            name: row.get::<String>("name").unwrap_or_default(),
            color: row_text(row, "color"),
        }
    }
}

/// The first row of `SELECT <columns> FROM <table> WHERE <column> = ?`.
pub(crate) async fn find<T: Record>(
    db: &dyn Database,
    column: &str,
    value: &str,
) -> Result<Option<T>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            format!("SELECT {} FROM {} WHERE {column} = ?", T::COLUMNS, T::TABLE),
            vec![text(value)],
        ))
        .await?;
    Ok(rows.first().map(T::from_row))
}

/// A page of rows, oldest first. `id` breaks ties so a page boundary can
/// never skip or repeat a row (the same rule as the waitlist export).
pub(crate) async fn list<T: Record>(
    db: &dyn Database,
    fetch: u64,
    offset: u64,
) -> Result<Vec<T>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            format!(
                "SELECT {} FROM {} ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?",
                T::COLUMNS,
                T::TABLE
            ),
            vec![limit(fetch), limit(offset)],
        ))
        .await?;
    Ok(rows.rows.iter().map(T::from_row).collect())
}

// ---------------------------------------------------------------------------
// The public upserts
// ---------------------------------------------------------------------------

const CONTACT_UPSERT: &str = "INSERT INTO crm_contacts \
     (id, email, email_normalized, name, phone, locale, organisation_id, source, data, created_at, \
      updated_at, generation) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, '{}'), ?, ?, 1) \
     ON CONFLICT(email_normalized) DO UPDATE SET \
     email = excluded.email, \
     name = COALESCE(?, crm_contacts.name), \
     phone = COALESCE(?, crm_contacts.phone), \
     locale = COALESCE(?, crm_contacts.locale), \
     organisation_id = COALESCE(?, crm_contacts.organisation_id), \
     source = COALESCE(?, crm_contacts.source), \
     data = COALESCE(?, crm_contacts.data), \
     updated_at = ?, \
     generation = crm_contacts.generation + 1";

/// Creates or updates one contact, keyed on its normalized address.
///
/// The address is normalized the way the rest of the harness normalizes one
/// ([`normalize_email`]: trimmed, NFC, lowercased), so `" Ada@Example.COM "`
/// and `"ada@example.com"` are one contact and the second call updates the
/// row the first inserted rather than inserting a second. Only the fields the
/// caller supplied move; `updated_at` moves to `now` and `generation` is
/// bumped. The call never refuses an address that exists, which is what makes
/// it safe to call from a handler that may run twice. `id` names the row only
/// when the call inserts one.
///
/// # Errors
///
/// [`CrmError::InvalidEmail`] when the address does not normalize to a valid
/// one, [`CrmError::NotAnObject`] when `data` is not a JSON object, and
/// [`CrmError::Db`] when the database refuses the statement.
pub async fn upsert_contact(
    db: &dyn Database,
    id: &str,
    contact: &ContactUpsert,
    now: &str,
) -> Result<Upserted<Contact>, CrmError> {
    let normalized = normalize_email(&contact.email);
    validate_email(&normalized)?;
    if let Some(data) = &contact.data
        && !data.is_object()
    {
        return Err(CrmError::NotAnObject("data"));
    }
    // Checked here rather than left to the foreign key, which would surface
    // the caller's mistake as a database fault (a 500) instead of the input
    // error it is.
    if let Some(organisation_id) = &contact.organisation_id {
        require_organisation(db, organisation_id).await?;
    }

    // The optional columns, in the order the statement names them, used
    // twice: once for the INSERT, once for the ON CONFLICT SET.
    let optional = [
        opt_text(contact.name.as_deref()),
        opt_text(contact.phone.as_deref()),
        opt_text(contact.locale.as_deref()),
        opt_text(contact.organisation_id.as_deref()),
        opt_text(contact.source.as_deref()),
        opt_json(contact.data.as_ref()),
    ];
    // Read first: it is what tells a create from an update. A concurrent
    // first insert can make this answer `true` for a row somebody else
    // created; the row itself is right either way, because the upsert is one
    // statement.
    let created = find::<Contact>(db, "email_normalized", &normalized)
        .await?
        .is_none();

    let mut values = vec![text(id), text(contact.email.trim()), text(&normalized)];
    values.extend(optional.iter().cloned());
    values.push(text(now));
    values.push(text(now));
    values.extend(optional);
    values.push(text(now));
    db.execute(&Statement::with_values(CONTACT_UPSERT, values))
        .await?;

    let found = find::<Contact>(db, "email_normalized", &normalized).await?;
    Ok(Upserted {
        record: reread(found, "contact")?,
        created,
    })
}

const ORGANISATION_INSERT: &str = "INSERT INTO crm_organisations \
     (id, name, domain, website, email, phone, address, data, created_at, updated_at, generation) \
     VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, '{}'), COALESCE(?, '{}'), ?, ?, 1)";
const ORGANISATION_CONFLICT: &str = " ON CONFLICT(domain) DO UPDATE SET \
     name = excluded.name, \
     website = COALESCE(?, crm_organisations.website), \
     email = COALESCE(?, crm_organisations.email), \
     phone = COALESCE(?, crm_organisations.phone), \
     address = COALESCE(?, crm_organisations.address), \
     data = COALESCE(?, crm_organisations.data), \
     updated_at = ?, \
     generation = crm_organisations.generation + 1";

/// Creates or updates one organisation, keyed on its domain.
///
/// The domain is trimmed and lowercased, so `"  ASTRA.example "` and
/// `"astra.example"` are the same company; the name is always written,
/// because the column is required. **Without a domain there is no key**: the
/// row is inserted fresh on every call and `created` is always `true`, since
/// matching on the name would merge two different companies that share one.
///
/// # Errors
///
/// [`CrmError::BlankName`] when `name` is empty or whitespace only,
/// [`CrmError::NotAnObject`] when `address` or `data` is not a JSON object,
/// and [`CrmError::Db`] when the database refuses the statement.
pub async fn upsert_organisation(
    db: &dyn Database,
    id: &str,
    organisation: &OrganisationUpsert,
    now: &str,
) -> Result<Upserted<Organisation>, CrmError> {
    let name = organisation.name.trim();
    if name.is_empty() {
        return Err(CrmError::BlankName);
    }
    for (field, value) in [
        ("address", &organisation.address),
        ("data", &organisation.data),
    ] {
        if let Some(value) = value
            && !value.is_object()
        {
            return Err(CrmError::NotAnObject(field));
        }
    }
    let domain = organisation
        .domain
        .as_deref()
        .map(str::trim)
        .map(str::to_lowercase)
        .filter(|domain| !domain.is_empty());

    let optional = [
        opt_text(organisation.website.as_deref()),
        opt_text(organisation.email.as_deref()),
        opt_text(organisation.phone.as_deref()),
        opt_json(organisation.address.as_ref()),
        opt_json(organisation.data.as_ref()),
    ];
    let created = match &domain {
        Some(domain) => find::<Organisation>(db, "domain", domain).await?.is_none(),
        None => true,
    };

    let mut values = vec![text(id), text(name), opt_text(domain.as_deref())];
    values.extend(optional.iter().cloned());
    values.push(text(now));
    values.push(text(now));
    let sql = match &domain {
        Some(_) => {
            values.extend(optional);
            values.push(text(now));
            format!("{ORGANISATION_INSERT}{ORGANISATION_CONFLICT}")
        }
        None => ORGANISATION_INSERT.to_owned(),
    };
    db.execute(&Statement::with_values(sql, values)).await?;

    let found = match &domain {
        Some(domain) => find::<Organisation>(db, "domain", domain).await?,
        None => find::<Organisation>(db, "id", id).await?,
    };
    Ok(Upserted {
        record: reread(found, "organisation")?,
        created,
    })
}

fn validate_email(normalized: &str) -> Result<(), CrmError> {
    match validation_error(normalized) {
        Some(reason) => Err(CrmError::InvalidEmail(reason)),
        None => Ok(()),
    }
}

/// Refuses an `organisation_id` that names no row. The foreign key would
/// refuse it too, but as a database fault a caller cannot act on; this makes
/// it the validation error it is.
async fn require_organisation(db: &dyn Database, id: &str) -> Result<(), CrmError> {
    if find::<Organisation>(db, "id", id).await?.is_none() {
        return Err(CrmError::UnknownOrganisation);
    }
    Ok(())
}

/// The row a write just produced. Reaching here without it means the write
/// vanished, which is a database fault rather than a caller's mistake.
fn reread<T>(found: Option<T>, what: &str) -> Result<T, CrmError> {
    found.ok_or_else(|| {
        CrmError::Db(DbError::Query(format!(
            "the {what} is gone after its own write"
        )))
    })
}

// ---------------------------------------------------------------------------
// Guarded writes
// ---------------------------------------------------------------------------

/// A contact PATCH, applied as `UPDATE … WHERE id = ? AND generation = ?`: 1
/// row when the id exists **and** still carries `generation`, 0 otherwise.
///
/// The guard is in the statement rather than read-then-write, so two callers
/// holding the same generation cannot both land.
///
/// # Errors
///
/// [`CrmError::InvalidEmail`] when a supplied address does not normalize to a
/// valid one, [`CrmError::Taken`] when it is another contact's,
/// [`CrmError::UnknownOrganisation`] when `organisation_id` names no row,
/// [`CrmError::NotAnObject`] when `data` is not a JSON object, and
/// [`CrmError::Db`] when the database refuses the statement.
pub(crate) async fn update_contact(
    db: &dyn Database,
    id: &str,
    generation: i64,
    update: &ContactUpdate,
    now: &str,
) -> Result<u64, CrmError> {
    let mut normalized_email = None;
    if let Some(Some(email)) = &update.email {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;
        normalized_email = Some(normalized);
    }
    if let Some(Some(organisation_id)) = &update.organisation_id {
        require_organisation(db, organisation_id).await?;
    }
    if let Some(Some(value)) = &update.data
        && !value.is_object()
    {
        return Err(CrmError::NotAnObject("data"));
    }
    // `email_normalized` is UNIQUE, so a PATCH that moves a contact onto
    // another contact's address would be refused by the database as a 500.
    // Checking first makes it the conflict it is; the guard is not atomic
    // with the write, but a lost race is the only thing it can lose.
    if let Some(normalized) = &normalized_email
        && let Some(existing) = find::<Contact>(db, "email_normalized", normalized).await?
        && existing.id != id
    {
        return Err(CrmError::Taken("email"));
    }

    let mut sql = Update::new(now);
    if let Some(field) = &update.email {
        // Stored exactly as the upsert stores it: trimmed, case preserved.
        // The normalized column carries the lowercased form.
        sql.set("email", opt_text(field.as_deref().map(str::trim)));
        sql.set("email_normalized", opt_text(normalized_email.as_deref()));
    }
    for (column, field) in [
        ("name", &update.name),
        ("phone", &update.phone),
        ("locale", &update.locale),
        ("organisation_id", &update.organisation_id),
        ("source", &update.source),
    ] {
        sql.text(column, field);
    }
    sql.json("data", &update.data);
    Ok(sql.run(db, Contact::TABLE, id, generation).await?)
}

/// The same for an organisation; a supplied `domain` is normalized like the
/// upsert's.
///
/// # Errors
///
/// [`CrmError::BlankName`] when a supplied name is empty or whitespace only
/// (the column is required, and an empty name is not a name),
/// [`CrmError::Taken`] when the domain is another organisation's,
/// [`CrmError::NotAnObject`] when `address` or `data` is not a JSON object,
/// and [`CrmError::Db`] when the database refuses the statement.
pub(crate) async fn update_organisation(
    db: &dyn Database,
    id: &str,
    generation: i64,
    update: &OrganisationUpdate,
    now: &str,
) -> Result<u64, CrmError> {
    if let Some(Some(name)) = &update.name
        && name.trim().is_empty()
    {
        return Err(CrmError::BlankName);
    }
    for (field, value) in [("address", &update.address), ("data", &update.data)] {
        if let Some(Some(value)) = value
            && !value.is_object()
        {
            return Err(CrmError::NotAnObject(field));
        }
    }
    // The normalized domain the upsert would key on, kept in the field's
    // three states: absent, cleared (null, or empty once trimmed), and set.
    let normalized_domain = update.domain.as_ref().map(|field| {
        field
            .as_deref()
            .map(str::trim)
            .map(str::to_lowercase)
            .filter(|domain| !domain.is_empty())
    });
    // `domain` is UNIQUE too: refuse a collision as a conflict rather than
    // let the database report it as a fault.
    if let Some(Some(domain)) = &normalized_domain
        && let Some(existing) = find::<Organisation>(db, "domain", domain).await?
        && existing.id != id
    {
        return Err(CrmError::Taken("domain"));
    }

    let mut sql = Update::new(now);
    for (column, field) in [
        ("name", &update.name),
        ("website", &update.website),
        ("email", &update.email),
        ("phone", &update.phone),
    ] {
        sql.text(column, field);
    }
    if let Some(normalized) = &normalized_domain {
        sql.set("domain", opt_text(normalized.as_deref()));
    }
    sql.json("address", &update.address);
    sql.json("data", &update.data);
    Ok(sql.run(db, Organisation::TABLE, id, generation).await?)
}

/// A dynamic `UPDATE … SET … WHERE id = ? AND generation = ?`. Every column
/// is a static name; only values are bound.
struct Update {
    sets: Vec<String>,
    values: Vec<SeaValue>,
}

impl Update {
    fn new(now: &str) -> Self {
        Self {
            sets: vec![
                "updated_at = ?".to_owned(),
                "generation = generation + 1".to_owned(),
            ],
            values: vec![text(now)],
        }
    }

    /// Sets a nullable text column, when the field is present.
    ///
    /// The `&Field<T>` is deliberate: [`Field`] is `Option<Option<T>>`, where
    /// the inner `Option` is the "clear this column" state, so the clippy
    /// rewrite (`Option<&T>`) would change what the argument means.
    #[allow(clippy::ref_option)]
    fn text(&mut self, column: &str, field: &Field<String>) {
        if let Some(value) = field {
            self.set(column, opt_text(value.as_deref()));
        }
    }

    /// Sets a JSON object column, when the field is present. A cleared field
    /// is stored as `{}` rather than NULL, so a read never sees a non-object.
    #[allow(clippy::ref_option)] // As above: `Field<T>` is `Option<Option<T>>`.
    fn json(&mut self, column: &str, field: &Field<Value>) {
        if let Some(value) = field {
            self.set(column, value.as_ref().map_or_else(|| text("{}"), json_text));
        }
    }

    fn set(&mut self, column: &str, value: SeaValue) {
        self.sets.push(format!("{column} = ?"));
        self.values.push(value);
    }

    async fn run(
        self,
        db: &dyn Database,
        table: &str,
        id: &str,
        generation: i64,
    ) -> Result<u64, DbError> {
        let mut values = self.values;
        values.push(text(id));
        values.push(int(generation));
        let sql = format!(
            "UPDATE {table} SET {} WHERE id = ? AND generation = ?",
            self.sets.join(", ")
        );
        db.execute(&Statement::with_values(sql, values)).await
    }
}

/// Deletes a contact and its taggings in one atomic batch, so a half-erased
/// contact — a row whose labels still name it — is not a state any reader can
/// observe.
pub(crate) async fn delete_contact(db: &dyn Database, id: &str) -> Result<(), DbError> {
    delete_with_taggings(db, Contact::TABLE, SUBJECT_CONTACT, id).await
}

/// Deletes an organisation and its taggings in one atomic batch. A contact
/// filed under it keeps its row: the foreign key is `ON DELETE SET NULL`.
pub(crate) async fn delete_organisation(db: &dyn Database, id: &str) -> Result<(), DbError> {
    delete_with_taggings(db, Organisation::TABLE, SUBJECT_ORGANISATION, id).await
}

async fn delete_with_taggings(
    db: &dyn Database,
    table: &str,
    subject_type: &str,
    id: &str,
) -> Result<(), DbError> {
    db.batch_atomic(&[
        Statement::with_values(
            "DELETE FROM crm_taggings WHERE subject_type = ? AND subject_id = ?",
            vec![text(subject_type), text(id)],
        ),
        Statement::with_values(format!("DELETE FROM {table} WHERE id = ?"), vec![text(id)]),
    ])
    .await
}

/// Folds `merge` into `keep` in one atomic batch. The order is the whole of
/// it:
///
/// 1. a tag the keep already carries is dropped from the merge's side, or
///    step 2 would collide with the taggings' composite primary key;
/// 2. the merge's taggings become the keep's;
/// 3. the merge's row goes **before** the keep is updated, so filling the
///    keep's blank address from the merge cannot trip the UNIQUE on
///    `email_normalized` on the way past;
/// 4. the keep takes every field it was missing, the shallow merge of the two
///    `data` objects (the keep wins on a shared key), a bumped generation and
///    the new `updated_at`.
pub(crate) async fn merge_contacts(
    db: &dyn Database,
    keep: &Contact,
    merge: &Contact,
    now: &str,
) -> Result<(), DbError> {
    let data = merged_data(&keep.data, &merge.data);
    let fill = |kept: Option<&str>, merged: Option<&str>| opt_text(kept.or(merged));
    db.batch_atomic(&[
        Statement::with_values(
            "DELETE FROM crm_taggings WHERE subject_type = ? AND subject_id = ? AND tag_id IN \
             (SELECT tag_id FROM crm_taggings WHERE subject_type = ? AND subject_id = ?)",
            vec![
                text(SUBJECT_CONTACT),
                text(&keep.id),
                text(SUBJECT_CONTACT),
                text(&merge.id),
            ],
        ),
        Statement::with_values(
            "UPDATE crm_taggings SET subject_id = ? WHERE subject_type = ? AND subject_id = ?",
            vec![text(&keep.id), text(SUBJECT_CONTACT), text(&merge.id)],
        ),
        Statement::with_values(
            "DELETE FROM crm_contacts WHERE id = ?",
            vec![text(&merge.id)],
        ),
        Statement::with_values(
            "UPDATE crm_contacts SET email = ?, email_normalized = ?, name = ?, phone = ?, \
             locale = ?, organisation_id = ?, source = ?, data = ?, updated_at = ?, \
             generation = generation + 1 WHERE id = ?",
            vec![
                fill(keep.email.as_deref(), merge.email.as_deref()),
                fill(
                    keep.email_normalized.as_deref(),
                    merge.email_normalized.as_deref(),
                ),
                fill(keep.name.as_deref(), merge.name.as_deref()),
                fill(keep.phone.as_deref(), merge.phone.as_deref()),
                fill(keep.locale.as_deref(), merge.locale.as_deref()),
                fill(
                    keep.organisation_id.as_deref(),
                    merge.organisation_id.as_deref(),
                ),
                fill(keep.source.as_deref(), merge.source.as_deref()),
                json_text(&data),
                text(now),
                text(&keep.id),
            ],
        ),
    ])
    .await
}

/// The shallow merge of two `data` objects, one level deep: a key in both
/// belongs to `keep`, a key in one belongs to the result. A value that is not
/// an object is replaced rather than merged, because there is nothing to
/// merge into.
fn merged_data(keep: &Value, merge: &Value) -> Value {
    let (Value::Object(keep), Value::Object(merge)) = (keep, merge) else {
        return keep.clone();
    };
    let mut merged: Map<String, Value> = merge.clone();
    for (key, value) in keep {
        merged.insert(key.clone(), value.clone());
    }
    Value::Object(merged)
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

/// Creates a tag, or updates the colour of the tag of that name. `name` is
/// unique, so this too is idempotent: the same name twice is one tag.
/// `created` tells a create from a re-file, so the route can answer `201`
/// the first time.
pub(crate) async fn upsert_tag(
    db: &dyn Database,
    id: &str,
    name: &str,
    color: Option<&str>,
) -> Result<Upserted<Tag>, DbError> {
    let created = find::<Tag>(db, "name", name).await?.is_none();
    db.execute(&Statement::with_values(
        "INSERT INTO crm_tags (id, name, color) VALUES (?, ?, ?) \
         ON CONFLICT(name) DO UPDATE SET color = COALESCE(?, crm_tags.color)",
        vec![text(id), text(name), opt_text(color), opt_text(color)],
    ))
    .await?;
    let record = find::<Tag>(db, "name", name)
        .await?
        .ok_or_else(|| DbError::Query("the tag is gone after its own upsert".to_owned()))?;
    Ok(Upserted { record, created })
}

/// Files a tag against a subject. `ON CONFLICT DO NOTHING` makes it
/// idempotent — tagging twice is one tagging, not an error.
pub(crate) async fn tag_subject(
    db: &dyn Database,
    tag_id: &str,
    subject_type: &str,
    subject_id: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO crm_taggings (tag_id, subject_type, subject_id) VALUES (?, ?, ?) \
         ON CONFLICT(tag_id, subject_type, subject_id) DO NOTHING",
        vec![text(tag_id), text(subject_type), text(subject_id)],
    ))
    .await?;
    Ok(())
}

/// Removes a tagging, reporting how many rows went (0 when there was none).
pub(crate) async fn untag_subject(
    db: &dyn Database,
    tag_id: &str,
    subject_type: &str,
    subject_id: &str,
) -> Result<u64, DbError> {
    db.execute(&Statement::with_values(
        "DELETE FROM crm_taggings WHERE tag_id = ? AND subject_type = ? AND subject_id = ?",
        vec![text(tag_id), text(subject_type), text(subject_id)],
    ))
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_data_merge_keeps_the_survivors_keys() {
        let merged = merged_data(
            &json!({"tier": "gold", "note": "keep"}),
            &json!({"tier": "bronze", "tags": ["a"], "note": "merge"}),
        );
        assert_eq!(
            merged,
            json!({"tier": "gold", "note": "keep", "tags": ["a"]})
        );
    }

    #[test]
    fn subject_types_are_the_three_the_constraint_accepts() {
        assert!(is_subject_type("contact"));
        assert!(is_subject_type("organisation"));
        assert!(is_subject_type("item"));
        assert!(!is_subject_type("Contact"));
        assert!(!is_subject_type("customer"));
    }
}
