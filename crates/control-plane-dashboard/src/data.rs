//! The data screen (control-plane #28, the read-only half): a schema
//! visualiser over the database the control plane can actually reach —
//! which today is its own, because the control plane is itself a harness
//! venture and no `Deployer` exists to reach anything else (#26).
//!
//! Everything on this screen is a fact the database reported while the
//! page rendered: tables, columns, keys, relations and row counts come
//! from the live catalog via `cratefield-introspect`, and the verdicts
//! come from the composition's personal-data catalogue. Where the screen
//! cannot know something — a venture's schema, a table nobody declared —
//! it says so in plain text, the rule every dashboard screen lives by.
//!
//! Deliberately out of scope here, each named so the boundary reads as a
//! decision rather than an omission: row editing (this pass is read-only),
//! the SQL console (#28's second half — statement whitelisting, timeouts
//! and result caps are their own set of decisions), and reading a
//! venture's published tables contract (harness #153's remaining half,
//! which changes a core surface and shows nothing until ventures deploy).
//! The renderer takes a `cratefield_tables::Schema` so the contract can
//! be a second source without touching it.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use cratefield_chrome::{Page, escape, render};
use cratefield_console::current_session;
use cratefield_core::{Disposition, PersonalDataSet, Rows};
use cratefield_introspect as introspect;
use cratefield_tables::{Schema, TableDef};
use http::{HeaderMap, StatusCode, header};
use sea_query::Value as SeaValue;

use super::{DashboardState, account_nav, card, frame, guard, internal};

/// Where the screen sits under the dashboard.
const PATH: &str = "/v1/dashboard/data";

/// One page of rows on the detail page. Small enough to render inside a
/// Worker, large enough to be worth scrolling.
const PAGE_SIZE: u64 = 25;

/// The export page: rows per read while building the CSV.
const EXPORT_PAGE: u64 = 500;

/// The harness-wide export cap (`MAX_EXPORT_ROWS`), as the loop's
/// arithmetic type: the same bound every admin export in the harness is
/// clamped to, so one Worker-budget decision stays one decision.
const EXPORT_CAP: u64 = cratefield_core::MAX_EXPORT_ROWS as u64;

// ---------------------------------------------------------------------------
// The schema screen
// ---------------------------------------------------------------------------

/// `/v1/dashboard/data` — the diagram, the text list beneath it, and the
/// table list. Server-rendered inline SVG; no JavaScript layout, no
/// library, no CDN.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");

    let Some(db) = ctx.ports.db.clone() else {
        return unreachable_page("the db port is not wired into this deployment");
    };
    let schema = match introspect::schema(db.as_ref()).await {
        Ok(schema) => schema,
        Err(err) => return unreachable_page(&err.to_string()),
    };

    // The owner map for the node chips: which module declared which table,
    // from the composition's personal-data catalogue. A table no module
    // declared still renders, with no chip rather than a guess.
    let owners: Vec<(&str, &str)> = ctx
        .personal_data
        .entries()
        .iter()
        .map(|entry| (entry.set.table, entry.module))
        .collect();

    if schema.tables.is_empty() {
        let body = String::from(
            "<p class=\"dash__banner\"><span class=\"chip\">Empty</span>\
             <strong>The database holds no tables.</strong> The catalog answered, and \
             nothing is in it but the harness's own bookkeeping, which this screen \
             does not draw.</p>\
             <p class=\"dash__note\">That is a fact about the database, not a failure \
             to reach it — an unreachable database says so above instead.</p>",
        );
        return page(
            Some(&session.account_id),
            "Data browser",
            &frame(&account_nav("data"), "0 tables", &body),
        );
    }

    // Row counts for the list. A count that fails fails the page: the
    // catalog was readable a moment ago, so this is a real fault and not
    // something to render as a dash.
    let mut counts: Vec<u64> = Vec::with_capacity(schema.tables.len());
    for table in &schema.tables {
        match introspect::row_count(db.as_ref(), &table.name).await {
            Ok(count) => counts.push(count),
            Err(err) => return internal(&format!("could not count {}: {err}", table.name)),
        }
    }

    let list_rows = table_list_rows(&schema, &counts);

    let body = format!(
        "<p class=\"dash__note\">Read live from the control plane's own database — the \
         one database it can reach today. A venture's own database is not reachable \
         yet: no Deployer exists (#26), so no venture's schema can be read, and this \
         screen does not pretend otherwise. The schema itself is the database's own \
         report of its tables, columns, keys and indexes, not a list kept here.</p>\
         <div class=\"dash__scroll\"><div class=\"dash__card dash__card--canvas\">\
         {diagram}</div></div>\
         <p class=\"dash__note\">One box per table, one row per column, one line per \
         foreign key (the arrow points at the table being referenced; hover a line to \
         read what it connects). Markers: <code>pk</code> primary key, \
         <code>nn</code> not-null, <code>uq</code> unique, <code>ix</code> indexed, \
         <code>fk</code> foreign-key column. The chip on a node names the module that \
         owns the table.</p>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Tables <span class=\"dash__tag\">{tables}</span></p>\
         <div class=\"dash__list\">{list_rows}</div></div>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">The same schema as text</p>{text_list}\
         <p class=\"dash__note\">The same tables and relations as the diagram, as \
         text: this is the accessible path, the no-SVG path, and what the page reads \
         like in a terminal.</p></div>",
        diagram = super::diagram::render(&schema, &owners),
        tables = schema.tables.len(),
        text_list = text_list(&schema),
    );

    let edges: usize = schema
        .tables
        .iter()
        .map(|table| relation_count(&schema, table))
        .sum();
    let crumb = format!(
        "{tables} table{s} · {edges} relation{e}",
        tables = schema.tables.len(),
        s = if schema.tables.len() == 1 { "" } else { "s" },
        edges = edges,
        e = if edges == 1 { "" } else { "s" },
    );
    page(
        Some(&session.account_id),
        "Data browser",
        &frame(&account_nav("data"), &crumb, &body),
    )
}

/// The table list's rows: name (linked to its detail page), column count,
/// row count, relation count.
#[allow(clippy::format_push_string)]
fn table_list_rows(schema: &Schema, counts: &[u64]) -> String {
    let mut list_rows = String::from(
        "<div class=\"dash__lrow dash__lrow--head\"><span>Table</span><span>Columns</span>\
         <span>Rows</span><span>Relations</span></div>",
    );
    for (index, table) in schema.tables.iter().enumerate() {
        list_rows.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--data\">\
             <span><a href=\"{PATH}/{name}\">{name}</a></span> \
             <span>{columns}</span><span>{rows}</span><span>{relations}</span></div>",
            name = escape(&table.name),
            columns = table.fields.len(),
            rows = counts[index],
            relations = relation_count(schema, table),
        ));
    }
    list_rows
}

/// The text rendering of the same facts the diagram draws — the accessible
/// path, and the cross-check that keeps the two honest.
#[allow(clippy::format_push_string)]
fn text_list(schema: &Schema) -> String {
    let mut out = String::from("<ul class=\"dash__erd-text\">");
    for table in &schema.tables {
        let columns: Vec<&str> = table.fields.iter().map(|f| f.name.as_str()).collect();
        let mut line = format!(
            "<li><strong>{name}</strong> — {n} column{s}: {columns}.",
            name = escape(&table.name),
            n = table.fields.len(),
            s = if table.fields.len() == 1 { "" } else { "s" },
            columns = escape(&columns.join(", ")),
        );
        let out_keys: Vec<String> = table
            .foreign_keys
            .iter()
            .map(|key| edge_label(schema, table, key.field.as_str(), &key.references))
            .collect();
        if !out_keys.is_empty() {
            line.push_str(&format!(" References: {}.", escape(&out_keys.join("; "))));
        }
        let in_keys: Vec<String> = schema
            .tables
            .iter()
            .filter(|other| other.name != table.name)
            .flat_map(|other| {
                other
                    .foreign_keys
                    .iter()
                    .filter(|key| key.references == table.name)
                    .map(|key| edge_label(schema, other, key.field.as_str(), &table.name))
                    .collect::<Vec<_>>()
            })
            .collect();
        if !in_keys.is_empty() {
            line.push_str(&format!(" Referenced by: {}.", escape(&in_keys.join("; "))));
        }
        line.push_str("</li>");
        out.push_str(&line);
    }
    out.push_str("</ul>");
    out
}

/// `child.column → parent.key`, resolving the referenced column the way
/// the vocabulary defines it: the parent's single-column primary key.
fn edge_label(schema: &Schema, child: &TableDef, field: &str, parent_name: &str) -> String {
    let parent = schema.table(parent_name);
    let key = parent
        .filter(|table| table.primary_key.len() == 1)
        .and_then(|table| table.primary_key.first())
        .map_or("?", String::as_str);
    format!("{}.{} → {}.{}", child.name, field, parent_name, key)
}

fn relation_count(schema: &Schema, table: &TableDef) -> usize {
    let outgoing = table
        .foreign_keys
        .iter()
        .filter(|key| schema.table(&key.references).is_some())
        .count();
    let incoming = schema
        .tables
        .iter()
        .filter(|other| other.name != table.name)
        .flat_map(|other| &other.foreign_keys)
        .filter(|key| key.references == table.name)
        .count();
    outgoing + incoming
}

// ---------------------------------------------------------------------------
// The table detail screen
// ---------------------------------------------------------------------------

/// `/v1/dashboard/data/{table}` — the columns with full attributes, the
/// relations out and in, the personal-data verdict declared for the table,
/// and the first page of its rows, read-only, ordered by primary key.
#[allow(clippy::format_push_string)]
pub(super) async fn detail(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(table): Path<String>,
    Query(query): Query<Vec<(String, String)>>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let Some(db) = ctx.ports.db.clone() else {
        return unreachable_page("the db port is not wired into this deployment");
    };
    let schema = match introspect::schema(db.as_ref()).await {
        Ok(schema) => schema,
        Err(err) => return unreachable_page(&err.to_string()),
    };
    // Membership in the freshly-read schema is the guard on every query
    // below: a name that is not a table this database reported is a 404,
    // never a statement.
    let Some(table_def) = schema.table(&table) else {
        return (StatusCode::NOT_FOUND, "no such table").into_response();
    };

    let count = match introspect::row_count(db.as_ref(), &table).await {
        Ok(count) => count,
        Err(err) => return internal(&format!("could not count the table: {err}")),
    };
    let page_number = query
        .iter()
        .find(|(key, _)| key == "page")
        .and_then(|(_, value)| value.parse::<u64>().ok())
        .unwrap_or(1)
        .max(1);
    let pages = count.div_ceil(PAGE_SIZE).max(1);
    let page_number = page_number.min(pages);
    let rows = match read_page(db.as_ref(), table_def, page_number).await {
        Ok(rows) => rows,
        Err(err) => return internal(&format!("could not read the rows: {err}")),
    };

    // The personal-data verdict: what the composition declared, or the
    // plain statement that nothing was.
    let declared = ctx
        .personal_data
        .entries()
        .iter()
        .find(|entry| entry.set.table == table);

    let columns_html = columns_list(table_def);
    let relations_html = relations_notes(&schema, &table, table_def);
    let rows_body = rows_card_body(&rows, &table, table_def, page_number, pages);

    let body = format!(
        "<div class=\"dash__grid\">\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Columns <span class=\"dash__tag\">{columns}</span></p>\
         <div class=\"dash__list\">{columns_html}</div></div>\
         {relations}\
         {personal}\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Rows <span class=\"dash__tag\">{count} total</span></p>\
         {rows_body}</div></div>",
        columns = table_def.fields.len(),
        columns_html = columns_html,
        relations = card("Relations", None, &relations_html, false),
        personal = card(
            "Personal data",
            None,
            &personal_data_verdict(declared),
            false
        ),
        rows_body = rows_body,
        count = count,
    );

    let crumb = format!(
        "<a href=\"{PATH}\">Data browser</a> / {table}",
        table = escape(&table),
    );
    page(
        Some(&session.account_id),
        &table,
        &format!(
            "<p class=\"crumb\">{crumb}</p>\
             <div class=\"page-h\"><h1>{table}</h1> \
             <a class=\"btn\" href=\"{PATH}/{table}/export\">Export CSV</a></div>\
             <p class=\"lede\">One table: its columns, its relations, what the \
             composition declared about the data it holds, and its first page of \
             rows.</p>{frame}",
            table = escape(&table),
            frame = frame(&account_nav("data"), &table, &body),
        ),
    )
}

/// The columns card's rows: name, type, and every attribute the catalog
/// reported, spelled out in full words (the diagram abbreviates them).
#[allow(clippy::format_push_string)]
fn columns_list(table_def: &TableDef) -> String {
    let mut columns_html = String::from(
        "<div class=\"dash__lrow dash__lrow--head\"><span>Column</span><span>Type</span>\
         <span>Attributes</span></div>",
    );
    for field in &table_def.fields {
        let mut markers: Vec<&str> = Vec::new();
        let is_key = table_def.is_primary_key(&field.name);
        if is_key {
            markers.push("primary key");
        }
        if field.required && !is_key {
            markers.push("not null");
        }
        if field.unique {
            markers.push("unique");
        }
        if field.indexed {
            markers.push("indexed");
        }
        if table_def
            .foreign_keys
            .iter()
            .any(|key| key.field == field.name)
        {
            markers.push("foreign key");
        }
        columns_html.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--three\">\
             <span><code>{name}</code></span><span><em>{kind}</em></span>\
             <span>{markers}</span></div>",
            name = escape(&field.name),
            kind = escape(field.kind.as_str()),
            markers = escape(&markers.join(", ")),
        ));
    }
    columns_html
}

/// The relations card: this table's foreign keys out (linked to their
/// parents' pages), and the other tables' keys pointing in.
fn relations_notes(schema: &Schema, table: &str, table_def: &TableDef) -> String {
    let out_keys: Vec<String> = table_def
        .foreign_keys
        .iter()
        .map(|key| {
            let label = edge_label(schema, table_def, key.field.as_str(), &key.references);
            match schema.table(&key.references) {
                Some(_) => format!(
                    "<a href=\"{PATH}/{parent}\">{label}</a>",
                    parent = escape(&key.references),
                    label = escape(&label),
                ),
                // A foreign key at a table this screen filtered out — the
                // migration ledger — is still a fact; it just has no page.
                None => escape(&label),
            }
        })
        .collect();
    let in_keys: Vec<String> = schema
        .tables
        .iter()
        .filter(|other| other.name != table)
        .flat_map(|other| {
            other
                .foreign_keys
                .iter()
                .filter(|key| key.references == table)
                .map(|key| {
                    let label = edge_label(schema, other, key.field.as_str(), table);
                    format!(
                        "<a href=\"{PATH}/{child}\">{label}</a>",
                        child = escape(&other.name),
                        label = escape(&label),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    format!(
        "<p class=\"dash__note\">Out (this table's foreign keys): {out}</p>\
         <p class=\"dash__note\">In (other tables pointing here): {in_}</p>",
        out = if out_keys.is_empty() {
            String::from("none")
        } else {
            out_keys.join(", ")
        },
        in_ = if in_keys.is_empty() {
            String::from("none")
        } else {
            in_keys.join(", ")
        },
    )
}

/// The rows preview: the current page as a real table, the pagination
/// links when there is more than one page, and the export note.
#[allow(clippy::format_push_string)]
fn rows_card_body(
    rows: &Rows,
    table: &str,
    table_def: &TableDef,
    page_number: u64,
    pages: u64,
) -> String {
    let mut rows_html = String::new();
    if rows.is_empty() {
        rows_html
            .push_str("<p class=\"dash__empty\">No rows. The table exists and holds nothing.</p>");
    } else {
        rows_html.push_str("<div class=\"dash__scroll\"><table class=\"dash__rows\">");
        let names: Vec<&str> = rows
            .first()
            .map(|row| row.column_names().collect::<Vec<_>>())
            .unwrap_or_default();
        rows_html.push_str("<thead><tr>");
        for name in &names {
            rows_html.push_str(&format!("<th>{}</th>", escape(name)));
        }
        rows_html.push_str("</tr></thead><tbody>");
        for row in &rows.rows {
            rows_html.push_str("<tr>");
            for (_, value) in row.columns() {
                rows_html.push_str(&format!("<td>{}</td>", escape(&cell(value))));
            }
            rows_html.push_str("</tr>");
        }
        rows_html.push_str("</tbody></table></div>");
    }
    let nav = if pages > 1 {
        format!(
            "<p class=\"dash__note\">Page {page_number} of {pages}. \
             <a href=\"{PATH}/{table}?page={prev}\">Previous</a> · \
             <a href=\"{PATH}/{table}?page={next}\">Next</a></p>",
            table = escape(table),
            prev = page_number.saturating_sub(1).max(1),
            next = (page_number + 1).min(pages),
        )
    } else {
        String::new()
    };
    format!(
        "{rows_html}{nav}         <p class=\"dash__note\">Read-only, ordered by primary key{why}. \
         <a href=\"{PATH}/{table}/export\">Export as CSV</a> — up to \
         {MAX} rows, formula-injection guarded.</p>",
        rows_html = rows_html,
        nav = nav,
        why = if table_def.primary_key.len() > 1 {
            " (composite, in column order)"
        } else {
            ""
        },
        table = escape(table),
        MAX = cratefield_core::MAX_EXPORT_ROWS,
    )
}

/// The personal-data verdict for one table, in the three shapes it can
/// take: declared personal, declared as holding nothing personal (or as
/// out of erasure's reach), or not declared at all.
fn personal_data_verdict(declared: Option<&cratefield_core::CatalogEntry>) -> String {
    let Some(entry) = declared else {
        return String::from(
            "<p class=\"dash__note\"><strong>Nothing is declared about this \
             table.</strong> No module in the composition has said whether it holds \
             anything personal — which is a gap, not a verdict of none: \"no \
             declaration\" and \"nothing personal\" look identical in source, and \
             only one of them is a decision.</p>",
        );
    };
    let set: &PersonalDataSet = &entry.set;
    if set.is_unreachable() {
        let Disposition::Unreachable(reason) = set.disposition else {
            unreachable!("is_unreachable and the disposition agree");
        };
        return format!(
            "<p class=\"dash__note\"><strong>Holds {kind} data that erasure cannot \
             reach.</strong> {description}</p>\
             <p class=\"dash__note\">Why it cannot be reached: {reason}</p>",
            kind = escape(set.kind.as_str()),
            description = escape(set.description),
            reason = escape(reason),
        );
    }
    if set.is_none() {
        let Disposition::Retain(reason) = set.disposition else {
            unreachable!("a none declaration retains its reason");
        };
        return format!(
            "<p class=\"dash__note\"><strong>Declared as holding nothing \
             personal.</strong> {reason}</p>",
            reason = escape(reason),
        );
    }
    let disposition = match set.disposition {
        cratefield_core::Disposition::Erase => {
            String::from("the rows are deleted when the person asks")
        }
        cratefield_core::Disposition::Anonymise(columns) => format!(
            "the rows stay and these columns are overwritten: {}",
            columns.join(", ")
        ),
        cratefield_core::Disposition::Retain(reason) => {
            format!("the rows stay: {reason}")
        }
        // `Disposition` is `#[non_exhaustive]`, so the match keeps a
        // wildcard; the unreachable variant was handled above.
        _ => unreachable!("the unreachable disposition was handled above"),
    };
    format!(
        "<p class=\"dash__note\"><strong>Holds {kind} data.</strong> Subject column: \
         <code>{subject}</code>. On erasure: {disposition}.</p>\
         <p class=\"dash__note\">{description}</p>",
        kind = escape(set.kind.as_str()),
        subject = escape(set.subject),
        disposition = escape(&disposition),
        description = escape(set.description),
    )
}

// ---------------------------------------------------------------------------
// The CSV export
// ---------------------------------------------------------------------------

/// `/v1/dashboard/data/{table}/export` — the whole table as CSV, read
/// through the same quoting every admin export in the harness uses
/// (`cratefield_core::csv`, formula-injection guarded), clamped to the
/// harness-wide export cap.
pub(super) async fn export(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(table): Path<String>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let schema = match introspect::schema(db.as_ref()).await {
        Ok(schema) => schema,
        Err(err) => return unreachable_page(&err.to_string()),
    };
    let Some(table_def) = schema.table(&table) else {
        return (StatusCode::NOT_FOUND, "no such table").into_response();
    };

    let order_by: Vec<&str> = order_columns(table_def);
    let mut csv = String::new();
    let mut written = 0_u64;
    let mut header_done = false;
    let mut more = false;
    while written < EXPORT_CAP {
        let page = match introspect::rows(
            db.as_ref(),
            &table,
            &order_by,
            EXPORT_PAGE.min(EXPORT_CAP - written),
            written,
        )
        .await
        {
            Ok(page) => page,
            Err(err) => return internal(&format!("could not read the rows: {err}")),
        };
        if page.is_empty() {
            break;
        }
        if !header_done {
            let names: Vec<&str> = page
                .first()
                .map(|row| row.column_names().collect::<Vec<_>>())
                .unwrap_or_default();
            csv.push_str(&cratefield_core::csv_row(&names));
            header_done = true;
        }
        for row in &page.rows {
            let cells: Vec<String> = row.columns().map(|(_, value)| csv_cell(value)).collect();
            let cells: Vec<&str> = cells.iter().map(String::as_str).collect();
            csv.push_str(&cratefield_core::csv_row(&cells));
            written += 1;
        }
        // A short page means the table ended; a full page at the cap
        // means the file does not carry everything, and the header below
        // says so rather than letting "exported everything" be claimed.
        if u64::try_from(page.len()).unwrap_or(0) < EXPORT_PAGE {
            break;
        }
        more = written >= EXPORT_CAP;
    }

    let mut response = Response::new(axum::body::Body::from(csv));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    // A catalog-sourced name is not an attacker's, but it is not
    // necessarily header-safe either; a name with anything exotic in it
    // degrades to the generic filename rather than losing the header.
    let safe = if table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        table.as_str()
    } else {
        "table"
    };
    let disposition = format!("attachment; filename=\"{safe}.csv\"");
    if let Ok(value) = header::HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    if more {
        // The convention the console's exports set: the header says the
        // cap was reached, so "exported everything" is never claimed by
        // a file that did not.
        response.headers_mut().insert(
            header::HeaderName::from_static("x-cf-export-more"),
            header::HeaderValue::from_static("true"),
        );
    }
    response
}

/// The columns to order a table's rows by: its primary key, or every
/// column when it has none — the two cases where paging through a table
/// is stable.
fn order_columns(table: &TableDef) -> Vec<&str> {
    if table.primary_key.is_empty() {
        table
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect()
    } else {
        table.primary_key.iter().map(String::as_str).collect()
    }
}

/// One page of a table's rows, ordered by its key.
async fn read_page(
    db: &dyn cratefield_core::Database,
    table: &TableDef,
    page: u64,
) -> Result<Rows, cratefield_core::DbError> {
    let order_by = order_columns(table);
    introspect::rows(
        db,
        &table.name,
        &order_by,
        PAGE_SIZE,
        (page - 1) * PAGE_SIZE,
    )
    .await
}

// ---------------------------------------------------------------------------
// Shared rendering helpers
// ---------------------------------------------------------------------------

/// The honest unreachable state, in the voice the planned screens use:
/// what is wrong, what every deployed venture's position is, what to do
/// instead — and never a spinner, an invented schema, or an empty list
/// wearing an error's clothes.
fn unreachable_page(detail: &str) -> Response {
    let body = format!(
        "<p class=\"dash__banner dash__banner--bad\"><span class=\"chip \
         chip--degraded\">Unreachable</span><strong>The database could not be \
         read.</strong> The screen reads a database's own catalog, and nothing \
         came back: <code>{detail}</code></p>\
         <p class=\"dash__note\">Every deployed venture is in this position today: \
         no Deployer exists (#26), so the control plane cannot reach any venture's \
         database, and the screen it would render there says exactly this rather \
         than an empty state. Nothing here is invented and nothing is \
         loading.</p>\
         <p class=\"dash__note\">Today you do this instead: run \
         <code>fz data export</code> against the venture's own database.</p>",
        detail = escape(detail),
    );
    page(
        None,
        "Data browser",
        &frame(&account_nav("data"), "unreachable", &body),
    )
}

/// Renders one finished data page. The unreachable variant is the one
/// page that renders without a session, so it signs in as nobody rather
/// than lying about who is at the keys.
fn page(identity: Option<&str>, title: &str, body: &str) -> Response {
    axum::response::Html(render(&Page {
        title,
        signed_in_as: identity,
        body,
    }))
    .into_response()
}

/// One value as the rows preview shows it: SQL NULL and a missing column
/// both say `NULL` (the honest dim word, not an empty cell that reads as
/// an empty string), and bytes are named, never dumped.
fn cell(value: &SeaValue) -> String {
    use SeaValue::{
        BigInt, Bool, Bytes, Char, Double, Float, Int, SmallInt, String as Text, TinyInt,
    };
    match value {
        Bool(Some(v)) => v.to_string(),
        TinyInt(Some(v)) => v.to_string(),
        SmallInt(Some(v)) => v.to_string(),
        Int(Some(v)) => v.to_string(),
        BigInt(Some(v)) => v.to_string(),
        Float(Some(v)) => v.to_string(),
        Double(Some(v)) => v.to_string(),
        Text(Some(v)) => (**v).clone(),
        Char(Some(v)) => v.to_string(),
        Bytes(Some(v)) => format!("{} bytes", v.len()),
        // `None` inside a variant is SQL NULL; the feature-gated variants
        // never come back through the sqlite and postgres adapters, but a
        // catch-all keeps this honest if one ever does.
        _ => "NULL".to_owned(),
    }
}

/// One value as CSV: NULL is an empty field (the format's own spelling of
/// nothing), and bytes are named exactly as [`cell`] names them.
///
/// The two paths agree on purpose. This screen reads the control plane's
/// own database, and that database holds `harness_secrets.ciphertext`, its
/// nonce, and the wrapped data key in `harness_secret_keys`. A page that
/// says "48 bytes" beside a CSV of the same row that spells those bytes
/// out would be the more dangerous of the two: a file somebody keeps,
/// mails and backs up, holding key material ADR 0015 keeps out of a
/// response body. A lossy decode of ciphertext is not readable data for
/// anyone, so nothing is lost by counting it instead.
fn csv_cell(value: &SeaValue) -> String {
    match value {
        SeaValue::Bytes(Some(v)) => format!("{} bytes", v.len()),
        SeaValue::String(None)
        | SeaValue::Char(None)
        | SeaValue::Bool(None)
        | SeaValue::TinyInt(None)
        | SeaValue::SmallInt(None)
        | SeaValue::Int(None)
        | SeaValue::BigInt(None)
        | SeaValue::Float(None)
        | SeaValue::Double(None)
        | SeaValue::Bytes(None) => String::new(),
        // A text or number value that happens to render as `NULL` is
        // indistinguishable from one that is — that is `cell`'s honest
        // ceiling — so the CSV keeps it verbatim rather than deciding.
        other => match cell(other).strip_prefix("NULL") {
            Some("") => String::new(),
            _ => cell(other),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dashboard, text};
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_core::Statement;
    use cratefield_testing::TestHarness;
    use http::{Method, Request as HttpRequest, StatusCode, header};
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    /// The kit's fixed clock reads `1_800_000_000`; mint sessions "now" so
    /// they are live, not expired.
    const NOW: u64 = 1_800_000_000;

    /// The control plane's own composition, like the suite in `lib.rs`:
    /// the console owns the access/accounts/provisioning schemas, the
    /// dashboard owns `connection`. The data screen reads all of them as
    /// one database, which is the point of the screen.
    fn kit() -> TestHarness {
        // No KMS: the data screen never touches one, and the secrets
        // screen's own tests cover both the wired and unwired cases.
        TestHarness::new(vec![
            Box::new(cratefield_console::Console),
            Box::new(Dashboard::new(None)),
        ])
    }

    fn cookie(kit: &TestHarness) -> String {
        let token = issue_session(kit.signer.as_ref(), EMAIL, NOW, DEFAULT_TTL_SECS);
        format!("cf_session={token}")
    }

    async fn get(
        kit: &TestHarness,
        uri: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, String, Option<String>) {
        let mut builder = HttpRequest::builder().method(Method::GET).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = kit
            .router
            .clone()
            .oneshot(builder.body(axum::body::Body::empty()).expect("request"))
            .await
            .expect("router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
            .await
            .expect("body");
        (
            parts.status,
            String::from_utf8(bytes.to_vec()).expect("utf-8"),
            parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        )
    }

    async fn seed_rows(kit: &TestHarness, sql: &str, values: Vec<sea_query::Value>) {
        kit.db
            .execute(&Statement::with_values(sql.to_owned(), values))
            .await
            .expect("seed");
    }

    #[pollster::test]
    async fn the_data_screen_draws_the_control_planes_own_schema() {
        let kit = kit();
        let (status, body, _) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The diagram: real nodes, a real foreign-key line with a real
        // hover title. A page that renders an empty <svg> is the failure
        // mode this exists to catch.
        assert!(body.contains("<svg"), "{}", body);
        assert!(body.contains("data-table=\"venture\""), "{}", body);
        assert!(body.contains("data-table=\"account\""), "{}", body);
        assert!(body.contains("class=\"dash__erd-edge\""), "{}", body);
        assert!(
            body.contains("<title>venture.account_id → account.id</title>"),
            "{}",
            body
        );
        // The owner chips: the personal-data catalogue knows the console
        // owns these tables.
        assert!(body.contains(">(console)</text>"), "{}", body);

        // The text list says what the diagram draws.
        assert!(body.contains("venture.account_id → account.id"), "{}", body);
        assert!(body.contains("Referenced by:"), "{}", body);

        // The bookkeeping ledger is not on the page, and neither is any
        // catalog table name that should have stayed an implementation
        // detail.
        assert!(!body.contains("harness_migrations"), "{}", body);

        // The nav item took the placeholder's slot.
        assert!(body.contains("href=\"/v1/dashboard/data\""), "{}", body);
        // And the placeholder banner is gone.
        assert!(!body.contains("Not built."), "{}", body);
    }

    #[pollster::test]
    async fn a_table_has_a_detail_page_with_columns_relations_and_rows() {
        let kit = kit();
        seed_rows(
            &kit,
            "INSERT INTO account (id, identity, name, status, created_at) VALUES (?, ?, ?, ?, ?)",
            vec![
                text("acc_1"),
                text("op@cratefield.com"),
                text("Op"),
                text("active"),
                text("t0"),
            ],
        )
        .await;
        seed_rows(
            &kit,
            "INSERT INTO venture (id, account_id, slug, subdomain, module_set, status, \
             tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                text("v1"),
                text("acc_1"),
                text("my-app"),
                text("my-app.cratefield.app"),
                text("cms"),
                text("draft"),
                text("ten_1"),
                text("t0"),
                text("t0"),
            ],
        )
        .await;

        let (status, body, _) = get(&kit, &format!("{PATH}/venture"), Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // Columns with full attributes.
        assert!(body.contains("<code>account_id</code>"), "{}", body);
        assert!(body.contains("foreign key"), "{}", body);
        // Relations out and in, as links.
        assert!(body.contains("venture.account_id → account.id"), "{}", body);
        // The personal-data verdict the console declared.
        assert!(body.contains("Holds identifier data"), "{}", body);
        assert!(body.contains("<code>account_id</code>"), "{}", body);
        // The rows preview and the export.
        assert!(body.contains("dash__rows"), "{}", body);
        assert!(body.contains("my-app.cratefield.app"), "{}", body);
        assert!(body.contains("Export as CSV"), "{}", body);

        // A table declared as holding nothing personal says that. Every
        // table in this composition is declared, so the undeclared case
        // is asserted straight against the renderer below.
        let (_, progress, _) = get(
            &kit,
            &format!("{PATH}/provision_progress"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(
            progress.contains("Declared as holding nothing personal"),
            "{progress}"
        );
    }

    #[test]
    fn a_table_nobody_declared_says_so_plainly() {
        let verdict = personal_data_verdict(None);
        assert!(
            verdict.contains("Nothing is declared about this table"),
            "{verdict}"
        );
        assert!(
            verdict.contains("a gap, not a verdict of none"),
            "{verdict}"
        );
    }

    #[pollster::test]
    async fn rows_are_paginated_in_primary_key_order() {
        let kit = kit();
        seed_rows(
            &kit,
            "INSERT INTO account (id, identity, name, status, created_at) VALUES (?, ?, ?, ?, ?)",
            vec![
                text("acc_1"),
                text("op@cratefield.com"),
                text("Op"),
                text("active"),
                text("t0"),
            ],
        )
        .await;
        for n in 0..30 {
            let id = format!("v{n:02}");
            seed_rows(
                &kit,
                "INSERT INTO venture (id, account_id, slug, subdomain, module_set, status, \
                 tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    text(&id),
                    text("acc_1"),
                    text(&format!("app-{n}")),
                    text(&format!("app-{n}.cratefield.app")),
                    text("cms"),
                    text("draft"),
                    text("ten_1"),
                    text("t0"),
                    text("t0"),
                ],
            )
            .await;
        }

        let (_, page_one, _) = get(&kit, &format!("{PATH}/venture"), Some(&cookie(&kit))).await;
        assert!(page_one.contains("Page 1 of 2"), "{}", page_one);
        assert!(page_one.contains("v00"), "{}", page_one);
        assert!(!page_one.contains(">v25<"), "{}", page_one);

        let (_, page_two, _) =
            get(&kit, &format!("{PATH}/venture?page=2"), Some(&cookie(&kit))).await;
        assert!(page_two.contains("v25"), "{}", page_two);
        assert!(!page_two.contains(">v00<"), "{}", page_two);
    }

    #[pollster::test]
    async fn the_csv_export_uses_the_shared_quoting_and_is_bounded() {
        let kit = kit();
        // A note shaped like a spreadsheet formula: the shared CSV helper
        // must guard it, so the export cannot become an incident.
        seed_rows(
            &kit,
            "INSERT INTO allowlist (value, kind, note, added_by, added_at) \
             VALUES (?, ?, ?, ?, ?)",
            vec![
                text("op@cratefield.com"),
                text("email"),
                text("=cmd|' /C calc'"),
                text("op"),
                text("t0"),
            ],
        )
        .await;

        let (status, body, content_type) = get(
            &kit,
            &format!("{PATH}/allowlist/export"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(content_type.as_deref(), Some("text/csv; charset=utf-8"));
        assert!(
            body.starts_with("value,kind,note,added_by,added_at\n"),
            "{body}"
        );
        assert!(body.contains("'=cmd|' /C calc'"), "{body}");
    }

    #[pollster::test]
    async fn the_csv_export_names_bytes_it_never_dumps_them() {
        // The screen reads the control plane's own database, which holds
        // sealed ciphertext, nonces and a wrapped data key once the
        // secrets layer is wired. The page counts bytes; a CSV that
        // spelled them out instead would be the more dangerous of the
        // two, being a file somebody keeps.
        let kit = kit();
        seed_rows(
            &kit,
            "CREATE TABLE sealed (id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, \
             note TEXT NOT NULL)",
            vec![],
        )
        .await;
        seed_rows(
            &kit,
            "INSERT INTO sealed (id, ciphertext, note) VALUES (?, ?, ?)",
            vec![
                text("row_1"),
                sea_query::Value::Bytes(Some(Box::new(b"sk_live_do_not_export".to_vec()))),
                text("keep me"),
            ],
        )
        .await;

        // Both halves, in both places: the row is there with its other
        // columns — the thing that would have carried the bytes — and the
        // bytes themselves are counted, never spelled.
        let (status, csv, _) =
            get(&kit, &format!("{PATH}/sealed/export"), Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{csv}");
        assert!(csv.contains("row_1"), "{csv}");
        assert!(csv.contains("keep me"), "{csv}");
        assert!(csv.contains("21 bytes"), "{csv}");
        assert!(!csv.contains("sk_live_do_not_export"), "{csv}");

        let (status, page, _) = get(&kit, &format!("{PATH}/sealed"), Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("21 bytes"), "{page}");
        assert!(!page.contains("sk_live_do_not_export"), "{page}");
    }

    #[pollster::test]
    async fn a_table_that_is_not_in_the_schema_is_a_404() {
        let kit = kit();
        for uri in [
            format!("{PATH}/nope"),
            format!("{PATH}/nope/export"),
            // The migration ledger is bookkeeping, not a table with a page.
            format!("{PATH}/harness_migrations"),
        ] {
            let (status, _, _) = get(&kit, &uri, Some(&cookie(&kit))).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }
    }

    #[pollster::test]
    async fn an_unauthenticated_request_is_redirected_to_the_login_gate() {
        let kit = kit();
        let (status, _, _) = get(&kit, PATH, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }
}
