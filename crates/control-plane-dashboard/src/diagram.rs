//! The schema diagram: server-rendered inline SVG, no JavaScript layout,
//! no library, no font metrics beyond the one monospace approximation
//! every terminal makes.
//!
//! The renderer is a pure function of a [`Schema`] and the module-owner
//! map, so it can take its input from the live catalog (via
//! `cratefield-introspect`, today) or from the tables contract a venture
//! will publish at `/__surface` (harness #153, the intended second
//! source) without changing a line.
//!
//! # Determinism
//!
//! The same schema must render byte-identical twice: a snapshot test
//! depends on it, and so does a reviewer reading a diff between two
//! schemas. Every choice here is therefore an ordering, never a race —
//! tables come in [`Schema`]'s name order, edges are emitted in table
//! then declaration order, and no hash map is iterated.
//!
//! # Layout
//!
//! Layered by foreign-key depth: a table referenced by others sits in an
//! earlier column than the tables that reference it, so the arrows the
//! diagram exists for mostly point one way. Order within a layer is name
//! order (which is arrival order — the schema is sorted). Tables with no
//! relations at all go in one final column after every layered one,
//! because a box that connects to nothing has no place in the flow and
//! still has a place on the page.

#![allow(clippy::too_many_lines)] // one renderer, read top to bottom

use cratefield_chrome::escape;
use cratefield_tables::{FieldDef, Schema, TableDef};

/// One node's width. Wide enough for `confirmation_code` plus its type
/// and markers at the monospace estimate below.
const NODE_W: i64 = 320;
/// The table-name header band.
const HEADER_H: i64 = 30;
/// One column row.
const ROW_H: i64 = 18;
/// Horizontal gap between layer columns; the foreign-key curves live in
/// these gaps.
const COL_GAP: i64 = 130;
/// Vertical gap between nodes in a column.
const ROW_GAP: i64 = 42;
/// The page margin around the drawing.
const MARGIN: i64 = 14;
/// Text inset inside a node.
const INSET: i64 = 10;
/// The width of one monospace character at the 11px row font — the
/// classic 0.6em approximation, used only to truncate long names, never
/// to position text.
const CHAR_W: i64 = 7;

/// Where a node was placed, in SVG pixels.
struct Placed {
    x: i64,
    y: i64,
}

/// Renders the diagram as inline SVG. `owners` maps a table name to the
/// module that declared it (from the composition's personal-data
/// catalogue), shown as a chip on the node — the closest honest thing to
/// Supabase's schema selector, which this control plane cannot have
/// because a venture's tables are not partitioned that way.
pub(crate) fn render(schema: &Schema, owners: &[(&str, &str)]) -> String {
    let depths = layer_depths(schema);
    let placed = place(schema, &depths);

    let mut edges = String::new();
    let mut nodes = String::new();
    let mut edge_count = 0_usize;
    for (index, table) in schema.tables.iter().enumerate() {
        for key in &table.foreign_keys {
            let Some(parent) = schema
                .tables
                .iter()
                .position(|candidate| candidate.name == key.references)
            else {
                // A foreign key at a table the reader filtered out — the
                // migration ledger, say — has no node to point at, so it
                // has no edge. The column still carries its fk marker and
                // the detail page still names the target.
                continue;
            };
            edge_count += 1;
            edges.push_str(&edge(schema, index, parent, key.field.as_str(), &placed));
        }
        nodes.push_str(&node(schema, index, &placed[index], owners));
    }

    let (width, height) = canvas(schema, &placed);
    let table_count = schema.tables.len();
    format!(
        "<svg class=\"dash__erd\" xmlns=\"http://www.w3.org/2000/svg\" \
         role=\"img\" width=\"{width}\" height=\"{height}\" \
         viewBox=\"0 0 {width} {height}\" \
         aria-label=\"Schema diagram: {table_count} tables, {edge_count} relations\">\
         <title>Schema diagram: {table_count} tables, {edge_count} relations</title>\
         <desc>Each box is one table with one row per column; each line is a \
         foreign key from the column it leaves to the key of the table it \
         points at. The same tables and relations are listed as text below \
         the diagram.</desc>\
         <defs><marker id=\"cf-erd-arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" \
         markerWidth=\"7\" markerHeight=\"7\" orient=\"auto-start-reverse\">\
         <path d=\"M0,0 L10,5 L0,10 z\" class=\"dash__erd-arrow\"/></marker></defs>\
         <g class=\"dash__erd-edges\">{edges}</g>\
         <g class=\"dash__erd-nodes\">{nodes}</g></svg>"
    )
}

/// The foreign-key depth of every table: the longest chain of outgoing
/// foreign keys below it, so a parent's depth is strictly less than its
/// children's on a well-behaved schema.
///
/// Computed by relaxation capped at `tables + 1` passes. A directed
/// acyclic graph converges well inside the cap; a reference cycle — which
/// a live database may legally hold — would grow forever, so the cap
/// freezes it at a finite, deterministic depth and the cycle's edges
/// simply point wherever their endpoints landed. Terminating matters more
/// than prettiness here, and the alternative (dropping cycle edges) would
/// hide real relations.
fn layer_depths(schema: &Schema) -> Vec<usize> {
    let n = schema.tables.len();
    // Parent indices per table, by foreign keys whose target is in the
    // schema, deduplicated in first-seen order.
    let parents: Vec<Vec<usize>> = schema
        .tables
        .iter()
        .map(|table| {
            let mut seen: Vec<usize> = Vec::new();
            for key in &table.foreign_keys {
                if let Some(parent) = schema
                    .tables
                    .iter()
                    .position(|candidate| candidate.name == key.references)
                    && !seen.contains(&parent)
                {
                    seen.push(parent);
                }
            }
            seen
        })
        .collect();

    let mut depth = vec![0_usize; n];
    for _ in 0..=n {
        let mut changed = false;
        for index in 0..n {
            let deepest = parents[index]
                .iter()
                .map(|parent| depth[*parent] + 1)
                .max()
                .unwrap_or(0);
            if deepest > depth[index] {
                depth[index] = deepest;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    depth
}

/// Assigns every table a column (its layer's rank, or one final column
/// for tables with no relations) and a y offset, stacking each column by
/// name order — which is the schema's arrival order.
fn place(schema: &Schema, depths: &[usize]) -> Vec<Placed> {
    let has_relations = |index: usize| {
        let outgoing = !schema.tables[index].foreign_keys.is_empty();
        let incoming = schema.tables.iter().any(|other| {
            other
                .foreign_keys
                .iter()
                .any(|k| k.references == schema.tables[index].name)
        });
        outgoing || incoming
    };

    // Compact the connected tables' depths to consecutive columns so an
    // absent middle layer leaves no blank gap.
    let mut ranks: Vec<usize> = depths
        .iter()
        .enumerate()
        .filter(|(index, _)| has_relations(*index))
        .map(|(_, depth)| *depth)
        .collect();
    ranks.sort_unstable();
    ranks.dedup();
    let rank_of = |depth: usize| ranks.iter().position(|rank| *rank == depth);

    let columns = ranks.len() + 1;
    let mut cursors = vec![MARGIN; columns];
    schema
        .tables
        .iter()
        .enumerate()
        .map(|(index, table)| {
            let column = if has_relations(index) {
                rank_of(depths[index]).unwrap_or(0)
            } else {
                // No relations: the final column, after every layer.
                ranks.len()
            };
            let placed = Placed {
                x: MARGIN + i64::try_from(column).unwrap_or(0) * (NODE_W + COL_GAP),
                y: cursors[column],
            };
            cursors[column] += node_height(table) + ROW_GAP;
            placed
        })
        .collect()
}

/// The overall canvas size: as wide as the columns, as tall as the
/// deepest one.
fn canvas(schema: &Schema, placed: &[Placed]) -> (i64, i64) {
    let width = placed.iter().map(|p| p.x + NODE_W).max().unwrap_or(MARGIN) + MARGIN;
    let mut height = MARGIN;
    for (index, table) in schema.tables.iter().enumerate() {
        height = height.max(placed[index].y + node_height(table));
    }
    (width, height + MARGIN)
}

fn node_height(table: &TableDef) -> i64 {
    HEADER_H + i64::try_from(table.fields.len()).unwrap_or(0) * ROW_H + 6
}

/// The y centre of one column row inside a node.
fn row_centre(placed: &Placed, row: usize) -> i64 {
    placed.y + HEADER_H + i64::try_from(row).unwrap_or(0) * ROW_H + ROW_H / 2
}

/// One table node: a header with the name and the owning module, then a
/// row per column with name, type and markers.
fn node(schema: &Schema, index: usize, placed: &Placed, owners: &[(&str, &str)]) -> String {
    let table = &schema.tables[index];
    let owner = owners
        .iter()
        .find(|(name, _)| *name == table.name)
        .map(|(_, module)| format!("({})", escape(module)))
        .unwrap_or_default();

    let mut out = format!(
        "<g class=\"dash__erd-node\" data-table=\"{name}\">\
         <rect class=\"dash__erd-box\" x=\"{x}\" y=\"{y}\" width=\"{NODE_W}\" \
         height=\"{h}\" rx=\"4\"/>\
         <path class=\"dash__erd-head\" d=\"M {x} {head_y} h {NODE_W}\"/>\
         <text class=\"dash__erd-name\" x=\"{tx}\" y=\"{name_y}\">{name}</text>\
         <text class=\"dash__erd-owner\" x=\"{owner_x}\" y=\"{name_y}\" \
         text-anchor=\"end\">{owner}</text>",
        name = escape(&table.name),
        x = placed.x,
        y = placed.y,
        h = node_height(table),
        head_y = placed.y + HEADER_H,
        tx = placed.x + INSET,
        name_y = placed.y + 19,
        owner_x = placed.x + NODE_W - INSET,
        owner = owner,
    );

    for (row, field) in table.fields.iter().enumerate() {
        let cy = row_centre(placed, row);
        let markers = marker_text(schema, index, field);
        // The marker text owns the right edge; the type sits left of it.
        let type_x = placed.x + NODE_W
            - INSET
            - 10
            - i64::try_from(markers.chars().count()).unwrap_or(0) * 6;
        let name_budget =
            usize::try_from(((type_x - (placed.x + INSET) - 12) / CHAR_W).max(8)).unwrap_or(8);
        let row = format!(
            "<text class=\"dash__erd-col\" x=\"{tx}\" y=\"{baseline}\">{name}</text>\
             <text class=\"dash__erd-type\" x=\"{type_x}\" y=\"{baseline}\" \
             text-anchor=\"end\">{kind}</text>\
             <text class=\"dash__erd-mark\" x=\"{mark_x}\" y=\"{baseline}\" \
             text-anchor=\"end\">{markers}</text>",
            tx = placed.x + INSET,
            baseline = cy + 4,
            name = escape(&truncate(&field.name, name_budget)),
            kind = escape(field.kind.as_str()),
            mark_x = placed.x + NODE_W - INSET,
        );
        out.push_str(&row);
    }
    out.push_str("</g>");
    out
}

/// The marker tokens for one column, in a fixed order: `pk` first (it
/// subsumes not-null, which every primary key column is), then `nn`,
/// `uq`, `ix`, and `fk` when a foreign key leaves from here. The legend
/// under the diagram is these five words in this order.
fn marker_text(schema: &Schema, index: usize, field: &FieldDef) -> String {
    let table = &schema.tables[index];
    let mut tokens: Vec<&str> = Vec::new();
    if table.is_primary_key(&field.name) {
        tokens.push("pk");
    } else if field.required {
        tokens.push("nn");
    }
    if field.unique {
        tokens.push("uq");
    }
    if field.indexed {
        tokens.push("ix");
    }
    if table.foreign_keys.iter().any(|key| key.field == field.name) {
        tokens.push("fk");
    }
    tokens.join(" ")
}

/// One foreign-key edge, arrowhead at the referenced table, `<title>`
/// naming `child.column → parent.column`.
fn edge(schema: &Schema, child: usize, parent: usize, field: &str, placed: &[Placed]) -> String {
    let child_table = &schema.tables[child];
    let parent_table = &schema.tables[parent];
    let child_row = child_table
        .fields
        .iter()
        .position(|candidate| candidate.name == field);
    let start_y = child_row.map_or(placed[child].y + HEADER_H / 2, |row| {
        row_centre(&placed[child], row)
    });
    // The vocabulary's referenced column is the parent's single-column
    // primary key; when the parent's key is composite or the column
    // cannot be found, the edge points at the header band and the title
    // names the table alone.
    let (parent_row, arrow_label) = match parent_table.primary_key.first() {
        Some(key) if parent_table.primary_key.len() == 1 && parent_table.field(key).is_some() => (
            parent_table
                .fields
                .iter()
                .position(|candidate| candidate.name == *key),
            format!(
                "{}.{} → {}.{}",
                escape(&child_table.name),
                escape(field),
                escape(&parent_table.name),
                escape(key)
            ),
        ),
        _ => (
            None,
            format!(
                "{}.{} → {}",
                escape(&child_table.name),
                escape(field),
                escape(&parent_table.name)
            ),
        ),
    };
    let end_y = parent_row.map_or(placed[parent].y + HEADER_H / 2, |row| {
        row_centre(&placed[parent], row)
    });

    // Leave the child from the side facing the parent; arrive the same
    // way. The control points extend along that direction so an edge
    // leaves its node horizontally, whatever the column gap.
    let (start_x, end_x) = if placed[parent].x < placed[child].x {
        (placed[child].x, placed[parent].x + NODE_W)
    } else {
        (placed[child].x + NODE_W, placed[parent].x)
    };
    let direction: i64 = if end_x < start_x { -1 } else { 1 };
    let reach = ((start_x - end_x).abs() / 2).clamp(40, 110);

    format!(
        "<path class=\"dash__erd-edge\" d=\"M {start_x} {start_y} \
         C {c1x} {start_y}, {c2x} {end_y}, {end_x} {end_y}\" \
         marker-end=\"url(#cf-erd-arrow)\"><title>{arrow_label}</title></path>",
        c1x = start_x + direction * reach,
        c2x = end_x - direction * reach,
    )
}

/// Cuts `text` to at most `max` characters, ending in `…` when it had to
/// cut. Server-side truncation is the only kind available without a font
/// engine, and the estimate errs on the side of cutting early.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_tables::{FieldDef, FieldKind, ForeignKey, Schema, TableDef};

    /// The control plane's own shape, in miniature: an account that
    /// ventures reference, and two tables that reference nothing.
    fn control_plane() -> Schema {
        Schema::new(vec![
            TableDef::new(
                "account",
                "id",
                vec![
                    FieldDef::new("id", FieldKind::Uuid).required(),
                    FieldDef::new("identity", FieldKind::text())
                        .required()
                        .unique(),
                    FieldDef::new("name", FieldKind::text()).required(),
                    FieldDef::new("status", FieldKind::text()).required(),
                    FieldDef::new("created_at", FieldKind::Timestamp).required(),
                ],
            ),
            TableDef::new(
                "allowlist",
                "value",
                vec![FieldDef::new("value", FieldKind::text()).required()],
            ),
            TableDef::new(
                "venture",
                "id",
                vec![
                    FieldDef::new("id", FieldKind::Uuid).required(),
                    FieldDef::new("account_id", FieldKind::Uuid)
                        .required()
                        .indexed(),
                    FieldDef::new("subdomain", FieldKind::text())
                        .required()
                        .unique(),
                ],
            )
            .foreign_key(ForeignKey::new("account_id", "account")),
        ])
    }

    #[test]
    fn the_same_schema_renders_byte_identical_twice() {
        let schema = control_plane();
        let owners = [("account", "console"), ("venture", "console")];
        assert_eq!(render(&schema, &owners), render(&schema, &owners));
    }

    #[test]
    fn the_diagram_names_its_tables_columns_and_relations() {
        let svg = render(&control_plane(), &[("account", "console")]);
        // The accessibility contract: role, title, desc.
        assert!(svg.contains("role=\"img\""), "{svg}");
        assert!(
            svg.contains("<title>Schema diagram: 3 tables, 1 relations</title>"),
            "{svg}"
        );
        assert!(svg.contains("<desc>"), "{svg}");
        // Nodes, columns, types and markers.
        assert!(svg.contains("data-table=\"account\""), "{svg}");
        assert!(svg.contains("identity"), "{svg}");
        assert!(svg.contains("uuid"), "{svg}");
        assert!(svg.contains(">nn uq<"), "the unique marker: {svg}");
        assert!(
            svg.contains(">nn ix fk<"),
            "the index and fk markers: {svg}"
        );
        // The owner chip from the personal-data catalogue.
        assert!(svg.contains(">(console)</text>"), "{svg}");
        // The edge and its hover title.
        assert!(svg.contains("class=\"dash__erd-edge\""), "{svg}");
        assert!(
            svg.contains("<title>venture.account_id → account.id</title>"),
            "{svg}"
        );
        assert!(svg.contains("cf-erd-arrow"), "{svg}");
    }

    #[test]
    fn a_referenced_table_lays_out_before_the_tables_that_reference_it() {
        let svg = render(&control_plane(), &[]);
        // Column position is baked into the x coordinates; account is
        // layer 0, venture layer 1, and allowlist (no relations) last.
        let x = |table: &str| -> i64 {
            let at = svg
                .find(&format!("data-table=\"{table}\""))
                .unwrap_or_else(|| panic!("{table} missing: {svg}"));
            let rect_at = svg[at..].find("class=\"dash__erd-box\"").expect("box") + at;
            let x_at = svg[rect_at..].find("x=\"").expect("x") + 3 + rect_at;
            svg[x_at..svg[x_at..].find('"').expect("end") + x_at]
                .parse()
                .expect("number")
        };
        assert!(x("account") < x("venture"), "parents sit left: {svg}");
        assert!(
            x("venture") < x("allowlist"),
            "tables with no relations sit last: {svg}"
        );
    }

    #[test]
    fn a_reference_cycle_still_renders_and_still_renders_the_same_way() {
        // A live database may hold a cycle; the layout must terminate and
        // stay deterministic rather than hide the edges.
        let schema = Schema::new(vec![
            TableDef::new(
                "left",
                "id",
                vec![FieldDef::new("id", FieldKind::Uuid).required()],
            )
            .foreign_key(ForeignKey::new("right_id", "right")),
            TableDef::new(
                "right",
                "id",
                vec![FieldDef::new("id", FieldKind::Uuid).required()],
            )
            .foreign_key(ForeignKey::new("left_id", "left")),
        ]);
        assert_eq!(render(&schema, &[]), render(&schema, &[]));
        let svg = render(&schema, &[]);
        assert!(svg.contains("data-table=\"left\""), "{svg}");
        assert!(svg.contains("data-table=\"right\""), "{svg}");
        // Both edges drew.
        assert_eq!(svg.matches("class=\"dash__erd-edge\"").count(), 2, "{svg}");
    }

    #[test]
    fn long_column_names_are_cut_rather_than_overlapped() {
        let schema = Schema::new(vec![TableDef::new(
            "wide",
            "id",
            vec![FieldDef::new(
                "a_column_name_far_longer_than_any_node_is_wide",
                FieldKind::text(),
            )],
        )]);
        let svg = render(&schema, &[]);
        assert!(svg.contains('…'), "the cut marker: {svg}");
        assert!(
            !svg.contains("a_column_name_far_longer_than_any_node_is_wide"),
            "the uncut name would overlap the type: {svg}"
        );
        assert!(svg.contains("…</text>"), "the cut is visible: {svg}");
    }

    #[test]
    fn an_empty_schema_renders_an_empty_accessible_diagram() {
        let svg = render(&Schema::default(), &[]);
        assert!(
            svg.contains("<title>Schema diagram: 0 tables, 0 relations</title>"),
            "{svg}"
        );
        assert!(!svg.contains("dash__erd-node\""), "{svg}");
    }
}
