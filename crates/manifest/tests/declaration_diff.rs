//! What changed about who may reach a declared table, and what it holds.
//!
//! The gap this closes: `fz tables diff` compared schemas only, so
//! flipping one table from `owner` to `public-read` — an edit that
//! publishes every subject's private rows — changed no column, reported
//! "No change", and exited zero.

use cratefield_manifest::{
    Access, AccessMap, DeclarationChange, Disposition, Move, TablePrivacy, TablePrivacyMap,
    declaration_diff,
};

fn access(level: Access) -> AccessMap {
    let mut map = AccessMap::new();
    map.insert("note".to_owned(), level);
    map
}

fn personal(subject: &str, description: &str) -> TablePrivacyMap {
    let mut map = TablePrivacyMap::new();
    map.insert(
        "note".to_owned(),
        TablePrivacy::Personal {
            subject: subject.to_owned(),
            kind: "content".to_owned(),
            disposition: Disposition::Erase,
            description: description.to_owned(),
            redacted: Vec::new(),
        },
    );
    map
}

fn nothing(reason: &str) -> TablePrivacyMap {
    let mut map = TablePrivacyMap::new();
    map.insert(
        "note".to_owned(),
        TablePrivacy::Nothing {
            reason: reason.to_owned(),
        },
    );
    map
}

/// The one change, when there is exactly one.
fn only(changes: &[DeclarationChange]) -> DeclarationChange {
    assert_eq!(changes.len(), 1, "{changes:?}");
    changes[0].clone()
}

fn moved(from: Access, to: Access) -> Move {
    let privacy = personal("author", "The notes you wrote.");
    match only(&declaration_diff(
        &access(from),
        &access(to),
        &privacy,
        &privacy,
    )) {
        DeclarationChange::Access { direction, .. } => direction,
        other => panic!("{other:?}"),
    }
}

#[test]
fn publishing_a_private_table_is_reported_and_named_a_widening() {
    // The edit that reported nothing.
    assert_eq!(moved(Access::Owner, Access::PublicRead), Move::Widens);
}

#[test]
fn taking_a_public_table_private_is_a_narrowing() {
    // Safe for the data, and a breaking change for whatever was reading
    // it — which is why it is reported rather than passed over.
    assert_eq!(moved(Access::PublicRead, Access::Owner), Move::Narrows);
}

#[test]
fn letting_members_see_each_others_rows_is_a_widening() {
    // Same people, more rows: under `owner` a caller reached their own,
    // under `tenant-members` they reach everyone's.
    assert_eq!(moved(Access::Owner, Access::TenantMembers), Move::Widens);
}

#[test]
fn moving_off_admin_is_a_widening_even_though_admins_see_more_rows() {
    // The rank puts `admin` at the bottom because this is the moment
    // somebody who is not an operator can reach the table at all, which
    // is the thing a reviewer is looking for.
    assert_eq!(moved(Access::Admin, Access::Owner), Move::Widens);
    assert_eq!(moved(Access::Admin, Access::PublicRead), Move::Widens);
    assert_eq!(moved(Access::Owner, Access::Admin), Move::Narrows);
}

#[test]
fn an_unchanged_declaration_reports_nothing() {
    let privacy = personal("author", "The notes you wrote.");
    assert!(
        declaration_diff(
            &access(Access::Owner),
            &access(Access::Owner),
            &privacy,
            &privacy
        )
        .is_empty()
    );
}

#[test]
fn a_table_leaving_export_and_erasure_is_reported() {
    // `personal` -> `nothing` takes the table out of `fz data export`,
    // out of subject access and out of erasure. Nothing about the schema
    // changes, and an erasure that would have cleared it will not.
    let change = only(&declaration_diff(
        &access(Access::PublicRead),
        &access(Access::PublicRead),
        &personal("author", "The notes you wrote."),
        &nothing("Reference data, nobody is in it."),
    ));
    let DeclarationChange::Privacy { detail, .. } = change else {
        panic!("{change:?}");
    };
    assert!(detail.contains("leaves export and erasure"), "{detail}");
}

#[test]
fn a_table_entering_export_and_erasure_is_reported() {
    let change = only(&declaration_diff(
        &access(Access::PublicRead),
        &access(Access::PublicRead),
        &nothing("Reference data, nobody is in it."),
        &personal("author", "The notes you wrote."),
    ));
    let DeclarationChange::Privacy { detail, .. } = change else {
        panic!("{change:?}");
    };
    assert!(detail.contains("enters export and erasure"), "{detail}");
}

#[test]
fn changing_the_subject_column_is_reported_because_owner_matches_on_it() {
    // Every row's owner is decided by a different column afterwards, and
    // `access = "owner"` matches a caller against exactly that column.
    let change = only(&declaration_diff(
        &access(Access::Owner),
        &access(Access::Owner),
        &personal("author", "The notes you wrote."),
        &personal("owner_id", "The notes you wrote."),
    ));
    let DeclarationChange::Privacy { detail, .. } = change else {
        panic!("{change:?}");
    };
    assert!(
        detail.contains("`author`") && detail.contains("`owner_id`"),
        "{detail}"
    );
}

#[test]
fn changing_the_published_sentence_is_reported() {
    // It is published verbatim to the person asking, so an edit to it is
    // an edit to what a venture tells a subject about their data.
    let change = only(&declaration_diff(
        &access(Access::Owner),
        &access(Access::Owner),
        &personal("author", "The notes you wrote."),
        &personal("author", "Notes."),
    ));
    let DeclarationChange::Privacy { detail, .. } = change else {
        panic!("{change:?}");
    };
    assert!(detail.contains("published verbatim"), "{detail}");
}

#[test]
fn what_erasure_does_is_reported_when_it_changes() {
    let mut retained = personal("author", "The notes you wrote.");
    retained.insert(
        "note".to_owned(),
        TablePrivacy::Personal {
            subject: "author".to_owned(),
            kind: "content".to_owned(),
            disposition: Disposition::Retain("A statutory record.".to_owned()),
            description: "The notes you wrote.".to_owned(),
            redacted: Vec::new(),
        },
    );
    let change = only(&declaration_diff(
        &access(Access::Owner),
        &access(Access::Owner),
        &personal("author", "The notes you wrote."),
        &retained,
    ));
    let DeclarationChange::Privacy { detail, .. } = change else {
        panic!("{change:?}");
    };
    assert!(detail.contains("what erasure does"), "{detail}");
}

#[test]
fn a_table_that_is_only_on_one_side_is_left_to_the_schema_diff() {
    // It already says a table arrived or left. Repeating it here would
    // double every such line in a report that prints both.
    let added = declaration_diff(
        &AccessMap::new(),
        &access(Access::PublicRead),
        &TablePrivacyMap::new(),
        &nothing("Reference data."),
    );
    assert!(added.is_empty(), "{added:?}");

    let removed = declaration_diff(
        &access(Access::PublicRead),
        &AccessMap::new(),
        &nothing("Reference data."),
        &TablePrivacyMap::new(),
    );
    assert!(removed.is_empty(), "{removed:?}");
}
