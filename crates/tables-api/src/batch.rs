//! Several declared reads in one request (issue #153).
//!
//! A sidecar or a browser client rendering a page from four tables pays
//! four round trips otherwise, and a round trip to a Worker is the
//! expensive part of a read that a database answers in a millisecond.
//!
//! # What this does and does not buy
//!
//! One round trip. **Not** parallelism: the reads run in sequence against
//! the request's one database handle, because that is what a handle is.
//! Saying otherwise would be claiming a property the shape cannot have —
//! and a caller who believed it would size their batches by the wrong
//! number.
//!
//! # All or nothing
//!
//! A batch whose caller may not make one of its reads is refused whole,
//! naming the read. The alternative — a `200` carrying a refusal per
//! result — is a success that is not one, and every client would have to
//! remember to look inside it. A refusal that reads as success is worse
//! than a refusal.
//!
//! # The path cannot be a table
//!
//! `__batch` is not a legal declared table name: a name must start with a
//! lowercase letter and may not contain `__`. So this route cannot shadow
//! a venture's own table, and `the_batch_path_can_never_be_a_table_name`
//! says so rather than leaving it to be noticed.

use std::sync::Arc;

use cratefield_core::{Database, Problem, ProblemDef, Scope};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::read::Tables;

/// The path the batch is served at, under the module's own mount.
pub const PATH: &str = "/__batch";

/// The most reads one batch may ask for.
///
/// A cap, because a batch is a fan-out a single request controls: without
/// one, a caller who may read one table may read it two thousand times in
/// a request the gateway counts as one.
pub const MAX_READS: usize = 20;

/// The batch asked for more reads than one request may carry.
pub const TOO_MANY_READS: ProblemDef = ProblemDef {
    slug: "too-many-reads",
    status: StatusCode::BAD_REQUEST,
    title: "Too many reads in one batch",
    description: "A batch carries at most 20 reads; send the rest as another batch.",
};

/// The batch asked for nothing.
pub const NO_READS: ProblemDef = ProblemDef {
    slug: "no-reads",
    status: StatusCode::BAD_REQUEST,
    title: "A batch with no reads",
    description: "A batch names at least one read; an empty one is a request with no question.",
};

/// One read in a batch.
#[derive(Debug, Deserialize)]
pub struct Read {
    /// The declared table.
    pub table: String,
    /// Where the page starts — the `next` from a previous read of this
    /// table, exactly as it was given.
    #[serde(default)]
    pub after: Option<Value>,
    /// `sort=column` or `sort=-column`, the same shape the query string
    /// takes.
    #[serde(default)]
    pub sort: Option<String>,
    /// Equality filters, keyed by column.
    ///
    /// JSON values rather than the query string's text, because a body
    /// can carry a number as a number. The column's kind still decides
    /// whether the value is one it can be compared against.
    #[serde(default, rename = "where")]
    pub filters: Map<String, Value>,
}

/// What a batch asks for.
#[derive(Debug, Deserialize)]
pub struct Batch {
    /// The reads, answered in this order.
    pub reads: Vec<Read>,
}

/// Runs every read in `batch`, or refuses the batch.
///
/// # Errors
///
/// [`NO_READS`] or [`TOO_MANY_READS`] for a batch that is not one, and
/// the first read's own refusal otherwise — access, an undeclared table,
/// a bad cursor or a bad filter. The refusal names which read it was:
/// "the third read of a batch failed" is not something a caller can act
/// on without being told which the third was.
pub async fn run(
    tables: &Tables,
    conn: &dyn Database,
    headers: &HeaderMap,
    scope: &Scope,
    batch: &Batch,
) -> Result<Value, Problem> {
    if batch.reads.is_empty() {
        return Err(Problem::new(&NO_READS));
    }
    if batch.reads.len() > MAX_READS {
        return Err(Problem::new(&TOO_MANY_READS).with_detail(format!(
            "{} reads were asked for and {MAX_READS} is the most",
            batch.reads.len()
        )));
    }

    let mut results = Vec::with_capacity(batch.reads.len());
    for (at, read) in batch.reads.iter().enumerate() {
        // Each read is decided on its own: the access level of the table
        // it names, against this caller. A batch is a way to ask several
        // questions in one request, never a way to ask one the caller
        // could not ask alone.
        let filters = filters_of(read);
        let body = crate::read::page(
            tables,
            conn,
            headers,
            scope,
            crate::read::Asked {
                table: &read.table,
                after: read.after.as_ref(),
                filters: &filters,
                sort: crate::routes::sort_of(read.sort.as_deref()),
            },
        )
        .await
        .map_err(|problem| {
            // The caller sent an ordered list; the answer says which of
            // them it is about.
            let said = problem.detail.clone();
            problem.with_detail(match said {
                Some(detail) => format!("read {at} (`{}`): {detail}", read.table),
                None => format!("read {at} (`{}`)", read.table),
            })
        })?;
        results.push(json!({ "table": read.table, "rows": body["rows"], "next": body["next"] }));
    }
    Ok(json!({ "results": results }))
}

/// One read's filters, as the query layer takes them.
///
/// The columns are not checked here. `page` checks them against the same
/// declaration, and doing it twice would be two places to keep in step —
/// the batch's job is to reshape the map, not to re-decide anything.
fn filters_of(read: &Read) -> Vec<cratefield_tables::Filter> {
    read.filters
        .iter()
        .map(|(column, value)| cratefield_tables::Filter {
            column: column.clone(),
            value: value.clone(),
        })
        .collect()
}

/// The state the route needs.
pub type State = Arc<Tables>;
