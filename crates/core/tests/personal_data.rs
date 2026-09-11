//! The personal-data declaration refuses what it cannot mean.
//!
//! Every case here is a mistake somebody makes once: a table renamed without
//! the declaration following it, an `Anonymise` that names no column and so
//! erases nothing while reporting success, a `Retain` with no reason. The point
//! of validating at build is that all of them are cheap to make and expensive
//! to notice — a personal-data declaration is only read when somebody exercises
//! their rights, which is exactly when being wrong costs the most.

use cratefield_core::{DataKind, Disposition, PersonalDataSet};

const OWNED: &[&str] = &["practice_sessions", "pose_library"];

fn valid() -> PersonalDataSet {
    PersonalDataSet {
        table: "practice_sessions",
        subject: "account_id",
        kind: DataKind::Fitness,
        disposition: Disposition::Erase,
        description: "Joint angles and scores for one practice, with its date.",
        redacted: &[],
    }
}

#[test]
fn a_well_formed_declaration_passes() {
    assert!(valid().validate("practice", OWNED).is_empty());
}

#[test]
fn a_table_the_module_does_not_own_is_refused() {
    let set = PersonalDataSet {
        table: "accounts",
        ..valid()
    };
    let errors = set.validate("practice", OWNED);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("does not own"), "{errors:?}");
}

#[test]
fn anonymising_nothing_is_refused() {
    // The failure this prevents is silent: erasure runs, reports success, and
    // changes no column.
    let set = PersonalDataSet {
        disposition: Disposition::Anonymise(&[]),
        ..valid()
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("would erase nothing")),
        "{errors:?}"
    );
}

#[test]
fn anonymising_the_subject_column_is_refused() {
    // Overwriting the column erasure matches on makes the row unreachable: a
    // second request for the same subject would report nothing to erase, and
    // the row would stay forever.
    let set = PersonalDataSet {
        disposition: Disposition::Anonymise(&["account_id"]),
        ..valid()
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("could then never find")),
        "{errors:?}"
    );
}

#[test]
fn retaining_without_a_reason_is_refused() {
    let set = PersonalDataSet {
        disposition: Disposition::Retain("   "),
        ..valid()
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("without saying why")),
        "{errors:?}"
    );
}

#[test]
fn a_published_description_cannot_be_blank() {
    let set = PersonalDataSet {
        description: "",
        ..valid()
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("published verbatim")),
        "{errors:?}"
    );
}

#[test]
fn a_table_holding_nothing_personal_is_declared_with_a_reason() {
    let set = PersonalDataSet::none(
        "pose_library",
        "Reference poses, identical for every member.",
    );
    assert!(set.is_none());
    assert!(set.validate("practice", OWNED).is_empty());
}

#[test]
fn declaring_nothing_personal_without_a_reason_is_refused() {
    // "No declaration" and "nothing personal here" look the same in source.
    // Only one of them is a decision, and this is what makes it say so.
    let set = PersonalDataSet::none("pose_library", "");
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("without saying why")),
        "{errors:?}"
    );
}

#[test]
fn a_retained_row_keeps_its_row_and_an_erased_one_does_not() {
    assert!(Disposition::Retain("tax").keeps_row());
    assert!(Disposition::Anonymise(&["name"]).keeps_row());
    assert!(!Disposition::Erase.keeps_row());
}

#[test]
fn every_kind_has_a_distinct_wire_name() {
    let kinds = [
        DataKind::Contact,
        DataKind::Identifier,
        DataKind::Fitness,
        DataKind::Usage,
        DataKind::Content,
        DataKind::Financial,
    ];
    let mut names: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before, "two kinds share a wire name");
}

#[test]
fn a_table_name_that_is_not_an_identifier_is_refused() {
    // The privacy module builds SQL from these names. This is the rule that
    // means it never has to wonder whether it can.
    for bad in [
        "practice sessions",
        "practice\"; drop table accounts; --",
        "practice.sessions",
        "1practice",
        "práctica",
    ] {
        assert!(
            !cratefield_core::is_plain_identifier(bad),
            "{bad:?} was accepted as an identifier"
        );
    }
    for good in ["practice_sessions", "_internal", "t1", "A_b_2"] {
        assert!(
            cratefield_core::is_plain_identifier(good),
            "{good:?} was rejected"
        );
    }
}

#[test]
fn a_declaration_with_a_quoted_column_is_refused_at_build() {
    let set = PersonalDataSet {
        table: "practice_sessions",
        subject: "account_id\"; --",
        kind: DataKind::Fitness,
        disposition: Disposition::Erase,
        description: "Angles.",
        redacted: &[],
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("not a plain identifier")),
        "{errors:?}"
    );
}

#[test]
fn an_anonymise_column_that_is_not_an_identifier_is_refused() {
    let set = PersonalDataSet {
        table: "practice_sessions",
        subject: "account_id",
        kind: DataKind::Fitness,
        disposition: Disposition::Anonymise(&["name = 'x' --"]),
        description: "Angles.",
        redacted: &[],
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("not a plain identifier")),
        "{errors:?}"
    );
}

#[test]
fn a_credential_column_can_be_declared_and_still_be_kept_out_of_an_export() {
    // The case this exists for: the row is the subject's and erasure must
    // reach it, but one column is a bearer capability and an export is a file
    // somebody forwards.
    let set = PersonalDataSet {
        redacted: &["recipient_json"],
        ..valid()
    };
    assert!(set.validate("practice", OWNED).is_empty());
}

#[test]
fn a_redacted_column_that_is_not_an_identifier_is_refused() {
    let set = PersonalDataSet {
        redacted: &["recipient_json, account_id"],
        ..valid()
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("not a plain identifier")),
        "{errors:?}"
    );
}

#[test]
fn redacting_the_subject_column_is_refused() {
    // It protects nothing — the caller supplied that value to get the row —
    // and a list that reads as a protection and is not one is worse than no
    // list at all.
    let set = PersonalDataSet {
        redacted: &["account_id"],
        ..valid()
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("already has")),
        "{errors:?}"
    );
}

#[test]
fn redacting_a_column_of_a_table_declared_as_holding_nothing_is_refused() {
    // Nothing is exported from a `none` table, so the list would protect a
    // value that is never read: the mistake it hides is the declaration being
    // `none` when it should not be.
    let set = PersonalDataSet {
        redacted: &["token"],
        ..PersonalDataSet::none(
            "pose_library",
            "Reference poses, identical for every member.",
        )
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("nothing is exported")),
        "{errors:?}"
    );
}
