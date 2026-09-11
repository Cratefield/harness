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
        subject_via: None,
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
    assert!(Disposition::Unreachable("no subject column").keeps_row());
    assert!(!Disposition::Erase.keeps_row());
}

// ------------------------------------------------------------- unreachable

const UNREACHABLE: PersonalDataSet = PersonalDataSet::unreachable(
    "notifications_outbox",
    DataKind::Content,
    "A notification waiting to be sent, holding the message.",
    "The message is filed under the send, not under a subject column, so an \
     erasure request cannot match the row.",
);

#[test]
fn an_unreachable_declaration_counts_as_holding_personal_data() {
    // The case issue #274 gets wrong when declared `none`: a catalog whose
    // ONLY declaration is this one must not answer "holds nothing". An
    // export over it is empty, but the deployment is not.
    let catalog = cratefield_core::PersonalDataCatalog::compose([(
        "fixture",
        std::slice::from_ref(&UNREACHABLE),
    )]);
    assert!(!catalog.is_empty());
    assert!(catalog.subject_sets().next().is_none());
}

#[test]
fn an_unreachable_declaration_with_a_reason_and_description_passes() {
    let set = UNREACHABLE;
    assert!(set.is_none());
    assert!(set.is_unreachable());
    assert!(
        set.validate("fixture", &["notifications_outbox"])
            .is_empty()
    );
}

#[test]
fn an_unreachable_declaration_without_a_reason_is_refused() {
    let set = PersonalDataSet {
        disposition: Disposition::Unreachable("   "),
        ..UNREACHABLE
    };
    let errors = set.validate("fixture", &["notifications_outbox"]);
    assert!(
        errors.iter().any(|e| e.contains("without saying why")),
        "{errors:?}"
    );
}

#[test]
fn an_unreachable_declaration_without_a_description_is_refused() {
    // The description is published in the manifest's unreachable bucket, so
    // a blank one names a table and says nothing about it.
    let set = PersonalDataSet {
        description: "",
        ..UNREACHABLE
    };
    let errors = set.validate("fixture", &["notifications_outbox"]);
    assert!(
        errors.iter().any(|e| e.contains("published verbatim")),
        "{errors:?}"
    );
}

#[test]
fn a_subject_via_on_an_unreachable_table_is_refused() {
    // The two halves contradict each other: unreachable says no predicate
    // can reach the row, `subject_via` names the road to it.
    let set = PersonalDataSet {
        subject_via: Some(cratefield_core::SubjectVia {
            table: "accounts",
            subject: "id",
            key: "account_id",
        }),
        ..UNREACHABLE
    };
    let errors = set.validate("fixture", &["notifications_outbox"]);
    assert!(
        errors.iter().any(|e| e.contains("one or the other")),
        "{errors:?}"
    );
}

#[test]
fn redacting_a_column_of_an_unreachable_table_is_refused() {
    // Nothing is exported from a table with no queryable subject, so the
    // list would protect a value that is never read.
    let set = PersonalDataSet {
        redacted: &["payload"],
        ..UNREACHABLE
    };
    let errors = set.validate("fixture", &["notifications_outbox"]);
    assert!(
        errors.iter().any(|e| e.contains("nothing is exported")),
        "{errors:?}"
    );
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
        subject_via: None,
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
        subject_via: None,
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
        subject_via: None,
        ..valid()
    };
    assert!(set.validate("practice", OWNED).is_empty());
}

#[test]
fn a_redacted_column_that_is_not_an_identifier_is_refused() {
    let set = PersonalDataSet {
        redacted: &["recipient_json, account_id"],
        subject_via: None,
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
        subject_via: None,
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
        subject_via: None,
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

#[test]
fn a_subject_via_with_a_name_that_is_not_an_identifier_is_refused() {
    // The privacy module interpolates all three names into SQL. A bad one
    // must die at build, where the declaration is written, not at the first
    // subject access request, where being wrong costs the most.
    let set = PersonalDataSet {
        subject_via: Some(cratefield_core::SubjectVia {
            table: "identities; DROP TABLE users",
            subject: "user_id",
            key: "provider_subject",
        }),
        ..valid()
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("via table") && e.contains("not a plain identifier")),
        "{errors:?}"
    );
}

#[test]
fn a_subject_via_on_a_table_declared_as_holding_nothing_is_refused() {
    // The two halves contradict each other: `none` says nobody can be
    // reached here, `subject_via` names the road to them.
    let set = PersonalDataSet {
        subject_via: Some(cratefield_core::SubjectVia {
            table: "users",
            subject: "id",
            key: "email",
        }),
        ..PersonalDataSet::none(
            "pose_library",
            "Reference poses, identical for every member.",
        )
    };
    let errors = set.validate("practice", OWNED);
    assert!(
        errors.iter().any(|e| e.contains("one or the other")),
        "{errors:?}"
    );
}

#[test]
fn a_well_formed_subject_via_passes() {
    let set = PersonalDataSet {
        subject_via: Some(cratefield_core::SubjectVia {
            table: "users",
            subject: "id",
            key: "email",
        }),
        ..valid()
    };
    assert!(set.validate("practice", OWNED).is_empty());
}
