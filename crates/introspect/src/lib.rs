//! Reads a database's own catalog over the [`Database`] port and answers
//! in `cratefield-tables`' schema vocabulary.
//!
//! This is the **one source** the dashboard's data screen renders today:
//! the database itself knows its tables, columns, primary keys, foreign
//! keys and indexes, which is where Supabase's schema visualiser reads
//! them from too. The alternative sources were considered and rejected:
//!
//! - **The migrations** are hand-written SQL strings scattered across the
//!   module crates; parsing DDL to recover a schema is a guess dressed as
//!   a parser, and it could only ever describe the modules this repo
//!   ships, not what a database actually holds.
//! - **The `/__surface` tables contract** (harness #153) is the intended
//!   *second* source: a venture publishing its declared tables there is
//!   more trustworthy than a stranger's live catalog, and the renderer is
//!   written against `cratefield_tables::Schema` so it can take either
//!   without change. But publishing that contract changes a core surface
//!   and shows nothing until ventures deploy, so it is deliberately not
//!   this crate's problem.
//!
//! # Why this crate is the one place with dialect-specific SQL
//!
//! ADR 0004's portability rule — module SQL must run on SQLite and
//! Postgres unchanged — is enforced by
//! [`lint_portable_sql`](cratefield_core::lint_portable_sql), which `fz
//! doctor` runs over a **module's migrations** and the Postgres migration
//! runner runs over its set selection. Neither path ever sees this crate:
//! a catalog query is not a migration, and there is no portable way to
//! ask a database what it contains. `sqlite_master` does not exist on
//! Postgres and `information_schema` does not exist on SQLite; pretending
//! otherwise would mean a third, blander catalog that answers about
//! neither. A catalog is not data — the rule is about data moving between
//! engines — so the dialect-specific SQL lives here, commented, and
//! nowhere else.
//!
//! # What the crate does not do
//!
//! No driver is linked: statements go over `dyn Database` as SQL strings
//! with bound parameters, so the crate stays `wasm32`-clean alongside the
//! kernel and gains whatever engine the port's adapter provides. It does
//! not write, ever — every statement here is a `SELECT`.

#![forbid(unsafe_code)]

use cratefield_core::{Database, DbError, Row, Rows, Statement};
use cratefield_tables::{FieldDef, FieldKind, ForeignKey, Schema, TableDef};

/// The harness's own bookkeeping tables, excluded from every catalog read.
///
/// Named one by one rather than by prefix, because a prefix would be a
/// trap in both directions: `harness_secret_keys` starts with `harness_`
/// and is a real table holding real (enveloped) data, and a future
/// bookkeeping table that does not start with the prefix would vanish
/// silently from every diagram. A name on this list is a claim that the
/// table holds no venture data, and a new one has to argue its way on.
const BOOKKEEPING: &[&str] = &[
    // The migration ledger both adapters write (`apply_migrations`). Its
    // rows are applied-migration ids and checksums: process state, not
    // data, and no relation in any schema points at it.
    "harness_migrations",
];

/// The SQL that keeps [`BOOKKEEPING`] out of a catalog read, as
/// `<column> NOT IN (…)`, so the list and the exclusion cannot drift.
/// The column is passed in because Postgres cannot name a SELECT alias in
/// its WHERE clause.
fn not_bookkeeping(column: &str) -> String {
    let names = BOOKKEEPING
        .iter()
        .map(|name| format!("'{}'", name.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(", ");
    format!("AND {column} NOT IN ({names})")
}

/// Reads a database's catalog and answers it as a [`Schema`].
///
/// # Errors
///
/// [`DbError::Query`] when neither catalog could be read — the SQLite
/// probe and the Postgres catalog both failed — with both drivers'
/// messages, because "cannot reach the database" and "unknown dialect"
/// read differently to the operator the screen renders for.
///
/// The intended second source, once harness #153 lands, is the tables
/// contract a venture publishes at `/__surface`; the caller is written to
/// take a `Schema` from either.
pub async fn schema(db: &dyn Database) -> Result<Schema, DbError> {
    // Dialect probe. The `Database` port exposes no dialect method, and
    // adding one would be a kernel change for a leaf feature, so the
    // catalog is asked in SQLite's dialect first: `sqlite_master` exists
    // only on SQLite, so a success is a positive identification and a
    // failure means "try the next engine", not "broken". The fallback is
    // explicit rather than inferred from some adapter detail.
    match sqlite_tables(db).await {
        Ok(tables) => sqlite_schema(db, tables).await,
        Err(sqlite_probe) => match postgres_schema(db).await {
            Ok(schema) => Ok(schema),
            Err(postgres_probe) => Err(DbError::Query(format!(
                "could not read a schema from either catalog: sqlite said \
                 [{sqlite_probe}]; postgres said [{postgres_probe}]"
            ))),
        },
    }
}

/// How many rows `table` holds, from the engine's own count.
///
/// # Errors
///
/// [`DbError::Query`] when the count cannot run — a table name that is
/// not in the schema the caller read, most likely.
pub async fn row_count(db: &dyn Database, table: &str) -> Result<u64, DbError> {
    let rows = db
        .query(&Statement::new(format!(
            "SELECT COUNT(*) AS n FROM {}",
            quote_ident(table)
        )))
        .await?;
    let count = rows
        .first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or(0);
    Ok(u64::try_from(count).unwrap_or(0))
}

/// One page of `table`'s rows, ordered by `order_by` (the table's primary
/// key, or every column when it has none — the two cases where paging is
/// stable). Read-only by construction: this crate issues no statement
/// that is not a `SELECT`.
///
/// # Errors
///
/// [`DbError::Query`] when the read cannot run.
pub async fn rows(
    db: &dyn Database,
    table: &str,
    order_by: &[&str],
    limit: u64,
    offset: u64,
) -> Result<Rows, DbError> {
    let order = order_by
        .iter()
        .map(|column| quote_ident(column))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = if order.is_empty() {
        format!("SELECT * FROM {} LIMIT ? OFFSET ?", quote_ident(table))
    } else {
        format!(
            "SELECT * FROM {} ORDER BY {order} LIMIT ? OFFSET ?",
            quote_ident(table)
        )
    };
    db.query(&Statement::with_values(
        sql,
        vec![
            sea_query::Value::BigInt(Some(i64::try_from(limit).unwrap_or(i64::MAX))),
            sea_query::Value::BigInt(Some(i64::try_from(offset).unwrap_or(0))),
        ],
    ))
    .await
}

// ---------------------------------------------------------------------------
// The SQLite leg
// ---------------------------------------------------------------------------

/// The table names SQLite knows, minus its own internals and the harness
/// bookkeeping. `sqlite_master` exists only on SQLite, which is what
/// makes this the dialect probe as well as the table list.
async fn sqlite_tables(db: &dyn Database) -> Result<Vec<String>, DbError> {
    let rows = db
        .query(&Statement::new(format!(
            // `sqlite_*` is SQLite's internal namespace (`sqlite_master`
            // itself, `sqlite_sequence` after any AUTOINCREMENT). The
            // escape keeps `_` from eating one character of a name like
            // `sqlitex`; no real table starts with `sqlite_` because the
            // tables crate reserves the prefix.
            "SELECT name FROM sqlite_master \
             WHERE type = 'table' \
             AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
             {excluded} \
             ORDER BY name ASC",
            excluded = not_bookkeeping("name")
        )))
        .await?;
    Ok(rows
        .rows
        .iter()
        .filter_map(|row| row.get::<String>("name"))
        .collect())
}

/// Reads one table's columns, keys and indexes from SQLite's pragmas, as
/// the table-valued functions — because the port takes a query, and
/// `PRAGMA …` is not one.
async fn sqlite_schema(db: &dyn Database, names: Vec<String>) -> Result<Schema, DbError> {
    let mut tables = Vec::with_capacity(names.len());
    for name in names {
        let columns = db
            .query(&Statement::with_values(
                "SELECT name AS column_name, type AS declared, \"notnull\" AS not_null, \
                 pk AS pk_pos FROM pragma_table_info(?) ORDER BY cid",
                vec![text(&name)],
            ))
            .await?;
        let foreign_keys = db
            .query(&Statement::with_values(
                "SELECT \"table\" AS parent, \"from\" AS child_column \
                 FROM pragma_foreign_key_list(?) ORDER BY id, seq",
                vec![text(&name)],
            ))
            .await?;
        let indexes = db
            .query(&Statement::with_values(
                "SELECT name AS index_name, \"unique\" AS is_unique, origin AS origin \
                 FROM pragma_index_list(?) ORDER BY seq",
                vec![text(&name)],
            ))
            .await?;

        // One index's columns per index name, then the per-column verdicts:
        // `unique` for a single-column unique constraint or unique index
        // (origin `u` or `c` — `pk` is the primary key's own autoindex and
        // already has its marker), `indexed` for a single-column plain
        // `CREATE INDEX` (origin `c`). A composite index marks no single
        // column, which matches the declaration vocabulary's meaning of
        // `indexed`: "gets its own CREATE INDEX".
        let mut unique: Vec<String> = Vec::new();
        let mut indexed_columns: Vec<String> = Vec::new();
        for index in &indexes.rows {
            let Some(index_name) = index.get::<String>("index_name") else {
                continue;
            };
            let is_unique = index.get::<i64>("is_unique").unwrap_or(0) == 1;
            let origin = index.get::<String>("origin").unwrap_or_default();
            let members = db
                .query(&Statement::with_values(
                    "SELECT name AS column_name FROM pragma_index_info(?) ORDER BY seqno",
                    vec![text(&index_name)],
                ))
                .await?
                .rows
                .iter()
                .filter_map(|row| row.get::<String>("column_name"))
                .collect::<Vec<_>>();
            if members.len() != 1 || origin == "pk" {
                continue;
            }
            if is_unique {
                unique.push(members[0].clone());
            } else if origin == "c" {
                indexed_columns.push(members[0].clone());
            }
        }

        tables.push(sqlite_table(
            &name,
            &columns.rows,
            &foreign_keys.rows,
            &unique,
            &indexed_columns,
        ));
    }
    Ok(Schema::new(tables))
}

/// Assembles one `TableDef` from SQLite's pragma rows.
fn sqlite_table(
    name: &str,
    columns: &[Row],
    foreign_keys: &[Row],
    unique: &[String],
    indexed: &[String],
) -> TableDef {
    let mut fields = Vec::with_capacity(columns.len());
    // `(column, pk position)` for the columns that carry one; SQLite
    // numbers pk positions from 1 in declaration order.
    let mut key: Vec<(String, i64)> = Vec::new();
    for column in columns {
        let column_name: String = column.get("column_name").unwrap_or_default();
        let declared: String = column.get("declared").unwrap_or_default();
        let not_null = column.get::<i64>("not_null").unwrap_or(0) == 1;
        let pk_pos = column.get::<i64>("pk_pos").unwrap_or(0);
        if pk_pos > 0 {
            key.push((column_name.clone(), pk_pos));
        }
        fields.push(FieldDef {
            kind: field_kind(&declared),
            required: not_null || pk_pos > 0,
            unique: unique.contains(&column_name),
            indexed: indexed.contains(&column_name),
            ..FieldDef::new(column_name, FieldKind::text())
        });
    }
    // The vocabulary orders a primary key by declaration, which is the
    // pragma's pk position.
    key.sort_by_key(|(_, position)| *position);
    TableDef {
        name: name.to_owned(),
        primary_key: key.into_iter().map(|(column, _)| column).collect(),
        foreign_keys: foreign_keys
            .iter()
            .filter_map(|row| {
                // `references` names the parent table; the vocabulary's
                // referenced column is that table's single-column primary
                // key, resolved by whoever holds the whole schema. A
                // composite foreign key degrades to one entry per column,
                // which is all the vocabulary can say.
                Some(ForeignKey::new(
                    row.get::<String>("child_column")?,
                    row.get::<String>("parent")?,
                ))
            })
            .collect(),
        fields,
    }
}

// ---------------------------------------------------------------------------
// The Postgres leg
// ---------------------------------------------------------------------------

/// Reads the whole catalog from `information_schema` and `pg_indexes`:
/// `current_schema()` keeps system schemas out without naming them, so a
/// fresh deployment's tables and nothing else come back.
async fn postgres_schema(db: &dyn Database) -> Result<Schema, DbError> {
    let names = db
        .query(&Statement::new(format!(
            "SELECT table_name AS name FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' \
             {excluded} \
             ORDER BY table_name ASC",
            excluded = not_bookkeeping("table_name")
        )))
        .await?
        .rows
        .iter()
        .filter_map(|row| row.get::<String>("name"))
        .collect::<Vec<_>>();

    let mut tables = Vec::with_capacity(names.len());
    for name in names {
        let columns = db
            .query(&Statement::with_values(
                "SELECT column_name AS column_name, udt_name AS declared, \
                 is_nullable AS is_nullable FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = ? \
                 ORDER BY ordinal_position",
                vec![text(&name)],
            ))
            .await?;
        // Primary keys and unique constraints from the constraint catalog,
        // joined to the columns they bind.
        let keys = db
            .query(&Statement::with_values(
                "SELECT tc.constraint_type AS constraint_type, kcu.column_name AS column_name, \
                 kcu.ordinal_position AS pos \
                 FROM information_schema.table_constraints tc \
                 JOIN information_schema.key_column_usage kcu \
                 ON kcu.constraint_name = tc.constraint_name \
                 AND kcu.constraint_schema = tc.constraint_schema \
                 WHERE tc.table_schema = current_schema() AND tc.table_name = ? \
                 AND tc.constraint_type IN ('PRIMARY KEY', 'UNIQUE') \
                 ORDER BY tc.constraint_name, kcu.ordinal_position",
                vec![text(&name)],
            ))
            .await?;
        let foreign_keys = db
            .query(&Statement::with_values(
                // information_schema cannot pair the columns of a
                // composite foreign key (its `key_column_usage` x
                // `constraint_column_usage` join loses the ordering), so a
                // composite key's pairs can come back crossed. The
                // vocabulary only models single-column keys, every
                // hand-written FK in this workspace is single-column, and
                // the honest fix is `pg_constraint` — noted here so the
                // day a composite FK matters, the next reader knows where
                // to look.
                "SELECT kcu.column_name AS child_column, ccu.table_name AS parent \
                 FROM information_schema.table_constraints tc \
                 JOIN information_schema.key_column_usage kcu \
                 ON kcu.constraint_name = tc.constraint_name \
                 AND kcu.constraint_schema = tc.constraint_schema \
                 JOIN information_schema.constraint_column_usage ccu \
                 ON ccu.constraint_name = tc.constraint_name \
                 AND ccu.constraint_schema = tc.constraint_schema \
                 WHERE tc.table_schema = current_schema() AND tc.table_name = ? \
                 AND tc.constraint_type = 'FOREIGN KEY' \
                 ORDER BY kcu.column_name, ccu.table_name, ccu.column_name",
                vec![text(&name)],
            ))
            .await?;
        let indexes = db
            .query(&Statement::with_values(
                "SELECT indexdef AS indexdef FROM pg_indexes \
                 WHERE schemaname = current_schema() AND tablename = ? \
                 ORDER BY indexname",
                vec![text(&name)],
            ))
            .await?;

        tables.push(postgres_table(
            &name,
            &columns.rows,
            &keys.rows,
            &foreign_keys.rows,
            &indexes.rows,
        ));
    }
    Ok(Schema::new(tables))
}

/// Assembles one `TableDef` from the Postgres catalog rows.
fn postgres_table(
    name: &str,
    columns: &[Row],
    keys: &[Row],
    foreign_keys: &[Row],
    indexes: &[Row],
) -> TableDef {
    let mut key: Vec<(String, i64)> = Vec::new();
    let mut unique_constraints: Vec<String> = Vec::new();
    for row in keys {
        let column: String = row.get::<String>("column_name").unwrap_or_default();
        if row.get::<String>("constraint_type").as_deref() == Some("PRIMARY KEY") {
            key.push((column, row.get::<i64>("pos").unwrap_or(0)));
        } else {
            unique_constraints.push(column);
        }
    }
    key.sort_by_key(|(_, position)| *position);
    let primary_key: Vec<String> = key.into_iter().map(|(column, _)| column).collect();

    // pg_indexes carries the columns inside the `indexdef` DDL string, the
    // only place this catalog exposes them at column granularity without
    // a walk of `pg_index`/`pg_attribute`. The parse is deliberately
    // small: the column list is the parenthesised tail, entries are split
    // on commas and cut at their first space (dropping ASC/DESC/NULLS
    // options), and anything that then fails to name a column — an
    // expression index — matches nothing and is ignored. The primary
    // key's own backing index is skipped by comparing column lists, so it
    // never masquerades as a unique constraint.
    let mut unique: Vec<String> = Vec::new();
    let mut indexed_columns: Vec<String> = Vec::new();
    let column_names: Vec<String> = columns
        .iter()
        .filter_map(|row| row.get::<String>("column_name"))
        .collect();
    for index in indexes {
        let Some(def) = index.get::<String>("indexdef") else {
            continue;
        };
        let Some(members) = pg_index_columns(&def) else {
            continue;
        };
        if members == primary_key {
            continue;
        }
        let is_unique = def.starts_with("CREATE UNIQUE INDEX");
        if members.len() != 1 {
            continue;
        }
        if !column_names.contains(&members[0]) {
            continue;
        }
        if is_unique {
            unique.push(members[0].clone());
        } else {
            indexed_columns.push(members[0].clone());
        }
    }
    for column in unique_constraints {
        if !unique.contains(&column) {
            unique.push(column);
        }
    }

    TableDef {
        name: name.to_owned(),
        primary_key,
        foreign_keys: foreign_keys
            .iter()
            .filter_map(|row| {
                Some(ForeignKey::new(
                    row.get::<String>("child_column")?,
                    row.get::<String>("parent")?,
                ))
            })
            .collect(),
        fields: columns
            .iter()
            .filter_map(|row| {
                let column_name: String = row.get::<String>("column_name")?;
                Some(FieldDef {
                    kind: field_kind(&row.get::<String>("declared").unwrap_or_default()),
                    required: row.get::<String>("is_nullable").as_deref() == Some("NO"),
                    unique: unique.contains(&column_name),
                    indexed: indexed_columns.contains(&column_name),
                    ..FieldDef::new(column_name, FieldKind::text())
                })
            })
            .collect(),
    }
}

/// The column names inside one `pg_indexes.indexdef`, or `None` when the
/// definition is not shaped like `CREATE [UNIQUE] INDEX … ON … USING … (…)`.
fn pg_index_columns(def: &str) -> Option<Vec<String>> {
    // A partial index carries its predicate after the column list; cut it
    // so a `)` inside the WHERE does not end the list early.
    let body = def.split(" WHERE ").next()?;
    let open = body.rfind('(')?;
    let close = body.rfind(')')?;
    if close < open {
        return None;
    }
    Some(
        body[open + 1..close]
            .split(',')
            .map(|entry| {
                entry
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Maps a live column type onto the declaration vocabulary's [`FieldKind`].
///
/// The vocabulary is deliberately small — every variant maps to DDL in
/// both dialects — so this is its inverse: the text family and anything
/// the vocabulary cannot name read as `text`, its generic bucket. The
/// alternative would be an "unknown" variant, which is a second
/// vocabulary, which is what this crate exists not to have. Lengths and
/// enum members do not survive: the live database does not know them.
fn field_kind(declared: &str) -> FieldKind {
    let lowered = declared.trim().to_ascii_lowercase();
    let base = lowered
        .split('(')
        .next()
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("");
    match base {
        "uuid" => FieldKind::Uuid,
        "json" | "jsonb" => FieldKind::Json,
        "bool" | "boolean" => FieldKind::Boolean,
        "date" | "datetime" | "timestamp" | "timestamptz" | "time" => FieldKind::Timestamp,
        "int" | "int2" | "int4" | "int8" | "integer" | "bigint" | "smallint" | "serial"
        | "bigserial" => FieldKind::integer(),
        "real" | "float" | "float4" | "float8" | "double" | "numeric" | "decimal" | "money" => {
            FieldKind::real()
        }
        _ => FieldKind::text(),
    }
}

/// Quotes one identifier for the generated reads, SQL-standard style:
/// double quotes with embedded doubles doubled. Both engines accept it,
/// and it is what keeps a catalog-sourced table name a name and not a
/// statement.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema both legs are asked to read: a parent with a unique
    /// column and a nullable one, and a child with a foreign key, a plain
    /// index and a unique index on a nullable column. Every fact the
    /// reader claims to recover is in here.
    const DDL: &[&str] = &[
        "CREATE TABLE parent (\
             id TEXT PRIMARY KEY, \
             email TEXT NOT NULL UNIQUE, \
             note TEXT)",
        "CREATE TABLE child (\
             id TEXT PRIMARY KEY, \
             parent_id TEXT NOT NULL REFERENCES parent (id), \
             qty INTEGER, \
             created_at TEXT)",
        "CREATE INDEX child_by_created ON child (created_at)",
        "CREATE UNIQUE INDEX child_qty_unique ON child (qty)",
    ];

    async fn seed(db: &dyn Database) {
        for statement in DDL {
            db.execute(&Statement::new(*statement)).await.expect("ddl");
        }
        for id in ["p1", "p2"] {
            db.execute(&Statement::with_values(
                "INSERT INTO parent (id, email, note) VALUES (?, ?, ?)",
                vec![text(id), text(&format!("{id}@example.com")), text("")],
            ))
            .await
            .expect("parent row");
        }
        for (id, parent, qty) in [("c1", "p1", 1), ("c2", "p2", 2), ("c3", "p1", 3)] {
            db.execute(&Statement::with_values(
                "INSERT INTO child (id, parent_id, qty, created_at) VALUES (?, ?, ?, ?)",
                vec![
                    text(id),
                    text(parent),
                    sea_query::Value::Int(Some(qty)),
                    text("2026-01-01T00:00:00Z"),
                ],
            ))
            .await
            .expect("child row");
        }
    }

    /// Every fact the reader is supposed to bring back, over whichever
    /// engine `db` is.
    async fn assert_catalog(db: &dyn Database) {
        let schema = schema(db).await.expect("read the catalog");

        // Table names come back sorted, and the migration ledger — which
        // exists on the SQLite leg because `apply_migrations` created it —
        // is not among them.
        let names: Vec<&str> = schema.tables.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["child", "parent"], "sorted, bookkeeping excluded");

        let parent = schema.table("parent").expect("parent");
        assert_eq!(parent.primary_key, ["id"]);
        let id = parent.field("id").expect("id column");
        assert!(id.required, "a primary key column is NOT NULL");
        assert!(!id.unique, "the pk marker is its own fact, not also unique");
        assert_eq!(id.kind.as_str(), "text");
        let email = parent.field("email").expect("email column");
        assert!(email.required);
        assert!(email.unique, "a UNIQUE column reads as unique");
        assert!(!email.indexed, "unique adds no second index");
        let note = parent.field("note").expect("note column");
        assert!(!note.required, "note is the nullable column");
        assert!(!note.unique);

        let child = schema.table("child").expect("child");
        assert_eq!(child.primary_key, ["id"]);
        assert_eq!(
            child
                .foreign_keys
                .iter()
                .map(|key| (key.field.as_str(), key.references.as_str()))
                .collect::<Vec<_>>(),
            [("parent_id", "parent")],
            "the foreign key comes back"
        );
        let parent_id = child.field("parent_id").expect("parent_id column");
        assert!(parent_id.required);
        assert_eq!(
            child.field("qty").expect("qty column").kind.as_str(),
            "integer",
            "an INTEGER column maps onto the vocabulary"
        );
        assert!(
            child.field("qty").expect("qty column").unique,
            "the unique INDEX reads as unique"
        );
        assert!(
            child
                .field("created_at")
                .expect("created_at column")
                .indexed,
            "the plain index reads as indexed"
        );
        assert!(!parent_id.indexed && !child.field("id").expect("id").indexed);

        // The reads the screen pages with.
        assert_eq!(row_count(db, "parent").await.expect("count"), 2);
        assert_eq!(row_count(db, "child").await.expect("count"), 3);
        let page = rows(db, "child", &["id"], 2, 1).await.expect("page");
        let ids: Vec<String> = page
            .rows
            .iter()
            .map(|row| row.get::<String>("id").unwrap_or_default())
            .collect();
        assert_eq!(ids, ["c2", "c3"], "ordered by primary key, offset applies");
    }

    #[pollster::test]
    async fn the_sqlite_catalog_reads_back_every_declared_fact() {
        let db = cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("sqlite");
        // The ledger exists and is still not in the answer.
        db.apply_migrations("probe", &[]).expect("ledger");
        seed(&db).await;
        assert_catalog(&db).await;
    }

    #[tokio::test]
    async fn the_postgres_catalog_reads_back_the_same_facts() {
        let Some(base) = cratefield_adapter_postgres::testing::base_url() else {
            eprintln!(
                "SKIP: {}",
                cratefield_adapter_postgres::testing::skip_reason()
            );
            return;
        };
        let temp = cratefield_adapter_postgres::testing::TempDb::create(&base, "introspect")
            .await
            .expect("throwaway database");
        let db = cratefield_adapter_postgres::Postgres::connect(&temp.url)
            .await
            .expect("connect");
        seed(&db).await;
        assert_catalog(&db).await;
        db.close().await.expect("close");
        temp.finish().await;
    }

    #[pollster::test]
    async fn an_unreadable_catalog_is_an_error_not_an_empty_schema() {
        // A database that answers neither catalog — the kit's EmptyDatabase
        // services only `SELECT 1` — must fail loudly, because an empty
        // schema would read on screen as "this database holds nothing".
        let err = schema(&EmptyCatalog).await.expect_err("no catalog answers");
        match err {
            DbError::Query(message) => {
                assert!(message.contains("either catalog"), "{message}");
            }
            other => panic!("expected a query error, got {other:?}"),
        }
    }

    /// Answers `SELECT 1`-shaped queries and fails everything else, which
    /// is neither dialect.
    struct EmptyCatalog;

    #[async_trait::async_trait]
    impl Database for EmptyCatalog {
        async fn execute(&self, _stmt: &Statement) -> Result<u64, DbError> {
            Err(DbError::Execute("not a database".to_owned()))
        }
        async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
            if stmt.sql.trim().starts_with("SELECT 1") {
                Ok(Rows::new(Vec::new()))
            } else {
                Err(DbError::Query("no catalog here".to_owned()))
            }
        }
        async fn batch_atomic(&self, _stmts: &[Statement]) -> Result<(), DbError> {
            Err(DbError::Batch("no".to_owned()))
        }
    }

    #[test]
    fn identifiers_are_quoted_so_a_catalog_name_cannot_become_a_statement() {
        assert_eq!(quote_ident("venture"), "\"venture\"");
        assert_eq!(quote_ident("od\"d"), "\"od\"\"d\"");
    }

    #[test]
    fn types_map_onto_the_vocabulary_with_an_explicit_text_fallback() {
        assert_eq!(field_kind("TEXT").as_str(), "text");
        assert_eq!(field_kind("varchar(254)").as_str(), "text");
        assert_eq!(field_kind("INTEGER").as_str(), "integer");
        assert_eq!(field_kind("bigint").as_str(), "integer");
        assert_eq!(field_kind("int4").as_str(), "integer");
        assert_eq!(field_kind("float8").as_str(), "real");
        assert_eq!(field_kind("DOUBLE PRECISION").as_str(), "real");
        assert_eq!(field_kind("BOOLEAN").as_str(), "boolean");
        assert_eq!(field_kind("timestamptz").as_str(), "timestamp");
        assert_eq!(field_kind("uuid").as_str(), "uuid");
        assert_eq!(field_kind("jsonb").as_str(), "json");
        // The vocabulary has no BLOB: it reads as the generic bucket
        // rather than inventing an unknown variant.
        assert_eq!(field_kind("BLOB").as_str(), "text");
    }
}
