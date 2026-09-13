//! The migration diff (issue #153): what changed, and what it costs.
//!
//! Every case here is one rule, and every rule is a claim about data that
//! already exists. The interesting half is not "the diff spotted a
//! change" — that is arithmetic — but whether it called the change by the
//! right name, because `expand`, `contract` and `rewrite` are three
//! different conversations with whoever has to ship it.

use cratefield_tables::{Change, Schema, Step, diff};
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    tables: Schema,
}

fn schema(fragment: &str) -> Schema {
    toml::from_str::<Manifest>(fragment)
        .expect("the fragment parses")
        .tables
}

/// The one table every case starts from.
const BEFORE: &str = r#"
[tables.post]
primary_key = "id"

[[tables.post.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.post.fields]]
name = "title"
kind = "text"
min_len = 1
max_len = 200
required = true

[[tables.post.fields]]
name = "note"
kind = "text"

[[tables.post.fields]]
name = "status"
kind = "enum"
values = ["draft", "published"]
"#;

/// `BEFORE` with `extra` appended to the `post` table.
fn with_field(extra: &str) -> Schema {
    schema(&format!("{BEFORE}\n[[tables.post.fields]]\n{extra}"))
}

fn steps(changes: &[Change]) -> Vec<(String, Step)> {
    changes
        .iter()
        .map(|change| (change.line(), change.step))
        .collect()
}

/// The single change, cloned so a caller can write `only(&diff(a, b))`
/// without the temporary being dropped out from under the borrow.
fn only(changes: &[Change]) -> Change {
    assert_eq!(
        changes.len(),
        1,
        "expected one change, got {:#?}",
        steps(changes)
    );
    changes[0].clone()
}

#[test]
fn nothing_changed_is_no_changes() {
    // The assertions below all count changes, and a diff that reported
    // everything as changed would satisfy several of them by accident.
    assert!(diff(&schema(BEFORE), &schema(BEFORE)).is_empty());
}

#[test]
fn a_new_optional_column_expands_and_a_required_one_does_not() {
    // The rule an author hits first: a `NOT NULL` with no default has no
    // value to give the rows already there.
    let optional = with_field("name = \"subtitle\"\nkind = \"text\"");
    let change = &diff(&schema(BEFORE), &optional)[0];
    assert_eq!(change.step, Step::Expand);
    assert_eq!(change.field.as_deref(), Some("subtitle"));

    let required = with_field("name = \"author\"\nkind = \"text\"\nrequired = true");
    let change = &diff(&schema(BEFORE), &required)[0];
    assert_eq!(change.step, Step::Rewrite, "{}", change.line());
    assert!(
        change.detail.contains("every existing row"),
        "{}",
        change.line()
    );

    // With a default the database has something to write, so it is
    // additive again. This is the pair that makes the rule a rule rather
    // than "required columns are scary".
    let defaulted =
        with_field("name = \"author\"\nkind = \"text\"\nrequired = true\ndefault = \"nobody\"");
    assert_eq!(diff(&schema(BEFORE), &defaulted)[0].step, Step::Expand);
}

#[test]
fn a_new_unique_column_is_a_rewrite_however_it_is_declared() {
    // Every existing row takes the same value — the default, or NULL on
    // an engine that treats NULLs as equal — and collides.
    let unique = with_field("name = \"slug\"\nkind = \"text\"\nunique = true");
    let change = only(&diff(&schema(BEFORE), &unique));
    assert_eq!(change.step, Step::Rewrite);
    assert!(change.detail.contains("collide"), "{}", change.line());
}

#[test]
fn removing_things_contracts_and_says_what_goes_with_them() {
    let without_note = schema(&BEFORE.replace(
        "[[tables.post.fields]]\nname = \"note\"\nkind = \"text\"\n",
        "",
    ));
    let change = only(&diff(&schema(BEFORE), &without_note));
    assert_eq!(change.step, Step::Contract);
    assert_eq!(change.field.as_deref(), Some("note"));
    assert!(change.detail.contains("values in it"), "{}", change.line());

    // A whole table is the same conversation, one level up.
    let change = only(&diff(&schema(BEFORE), &schema("[tables.other]\n[[tables.other.fields]]\nname = \"id\"\nkind = \"uuid\"\nrequired = true\n"))
        .iter()
        .filter(|change| change.table == "post")
        .cloned()
        .collect::<Vec<_>>());
    assert_eq!(change.step, Step::Contract);
    assert!(change.field.is_none());
    assert!(change.detail.contains("every row"), "{}", change.line());
}

#[test]
fn narrowing_a_bound_is_a_rewrite_and_widening_is_not() {
    // The rows already stored were written under the old rule. Nothing
    // here can see them, which is exactly why the answer is "rewrite"
    // rather than "this will be fine".
    let tighter = schema(&BEFORE.replace("max_len = 200", "max_len = 50"));
    let change = only(&diff(&schema(BEFORE), &tighter));
    assert_eq!(change.step, Step::Rewrite);
    assert!(
        change.detail.contains("already be outside"),
        "{}",
        change.line()
    );

    let looser = schema(&BEFORE.replace("max_len = 200", "max_len = 500"));
    assert_eq!(only(&diff(&schema(BEFORE), &looser)).step, Step::Expand);

    // Adding a bound where there was none is narrowing: `None` admitted
    // everything. This is the case a `>` comparison alone gets wrong.
    let bounded = schema(&BEFORE.replace(
        "name = \"note\"\nkind = \"text\"",
        "name = \"note\"\nkind = \"text\"\nmax_len = 10",
    ));
    let change = only(&diff(&schema(BEFORE), &bounded));
    assert_eq!(change.step, Step::Rewrite, "{}", change.line());

    // And dropping one is widening.
    assert_eq!(only(&diff(&bounded, &schema(BEFORE))).step, Step::Expand);
}

#[test]
fn an_enum_that_loses_a_member_is_a_rewrite_and_one_that_gains_is_not() {
    let gained = schema(&BEFORE.replace(
        r#"values = ["draft", "published"]"#,
        r#"values = ["draft", "published", "archived"]"#,
    ));
    let change = only(&diff(&schema(BEFORE), &gained));
    assert_eq!(change.step, Step::Expand);
    assert!(change.detail.contains("gains 1"), "{}", change.line());

    // Rows already holding `published` would fail the new CHECK, and the
    // message names the member so the author knows what to look for.
    let lost = schema(&BEFORE.replace(
        r#"values = ["draft", "published"]"#,
        r#"values = ["draft", "archived"]"#,
    ));
    let changes = diff(&schema(BEFORE), &lost);
    let rewrite = changes
        .iter()
        .find(|change| change.step == Step::Rewrite)
        .unwrap_or_else(|| panic!("no rewrite in {:#?}", steps(&changes)));
    assert!(rewrite.detail.contains("`published`"), "{}", rewrite.line());
}

#[test]
fn required_and_unique_move_in_both_directions() {
    let required = schema(&BEFORE.replace(
        "name = \"note\"\nkind = \"text\"",
        "name = \"note\"\nkind = \"text\"\nrequired = true",
    ));
    assert_eq!(only(&diff(&schema(BEFORE), &required)).step, Step::Rewrite);
    // Relaxing it is additive: nothing stored stops being valid.
    assert_eq!(only(&diff(&required, &schema(BEFORE))).step, Step::Expand);

    let unique = schema(&BEFORE.replace(
        "name = \"note\"\nkind = \"text\"",
        "name = \"note\"\nkind = \"text\"\nunique = true",
    ));
    assert_eq!(only(&diff(&schema(BEFORE), &unique)).step, Step::Rewrite);
    assert_eq!(only(&diff(&unique, &schema(BEFORE))).step, Step::Expand);
}

#[test]
fn an_index_costs_nothing_in_either_direction() {
    // The one change here that holds no data: both engines build and drop
    // an index without touching a row's contents.
    let indexed = schema(&BEFORE.replace(
        "name = \"note\"\nkind = \"text\"",
        "name = \"note\"\nkind = \"text\"\nindexed = true",
    ));
    assert_eq!(only(&diff(&schema(BEFORE), &indexed)).step, Step::Expand);
    assert_eq!(only(&diff(&indexed, &schema(BEFORE))).step, Step::Expand);
}

#[test]
fn changing_a_type_or_a_primary_key_is_a_rewrite() {
    let retyped = schema(&BEFORE.replace(
        "name = \"note\"\nkind = \"text\"",
        "name = \"note\"\nkind = \"integer\"",
    ));
    let change = only(&diff(&schema(BEFORE), &retyped));
    assert_eq!(change.step, Step::Rewrite);
    assert!(change.detail.contains("text"), "{}", change.line());
    assert!(change.detail.contains("integer"), "{}", change.line());

    let repointed = schema(&BEFORE.replace("primary_key = \"id\"", "primary_key = \"title\""));
    let change = only(&diff(&schema(BEFORE), &repointed));
    assert_eq!(change.step, Step::Rewrite);
    assert!(change.field.is_none());
    assert!(change.detail.contains("primary key"), "{}", change.line());
}

#[test]
fn a_default_changes_only_what_is_written_next() {
    // Worth reporting and worth reporting as additive: a default is read
    // when a write omits the column, so the rows already there are
    // untouched. An author who expects a backfill needs to be told they
    // are not getting one.
    let defaulted = schema(&BEFORE.replace(
        "name = \"note\"\nkind = \"text\"",
        "name = \"note\"\nkind = \"text\"\ndefault = \"none\"",
    ));
    let change = only(&diff(&schema(BEFORE), &defaulted));
    assert_eq!(change.step, Step::Expand);
    assert!(
        change.detail.contains("keep the value they have"),
        "{}",
        change.line()
    );
}

#[test]
fn the_report_is_deterministic_and_reads_as_lines() {
    let after = with_field("name = \"subtitle\"\nkind = \"text\"");
    let once = diff(&schema(BEFORE), &after);
    let twice = diff(&schema(BEFORE), &after);
    assert_eq!(once, twice);
    assert_eq!(once[0].line(), "post.subtitle: new optional column");
    assert_eq!(Step::Expand.to_string(), "expand");
    assert_eq!(Step::Contract.to_string(), "contract");
    assert_eq!(Step::Rewrite.to_string(), "rewrite");
}
