//! Dispositions (ADR 0026, Decision 5) without a Postgres server: a fixture
//! report, a file that decides some of it, and the refusals. The report is
//! built directly so the test needs no database.

use cratefield_import_supabase::{
    Auth, Classification, Coverage, Disposition, DispositionsFile, EdgeFunctions, Finding, Policy,
    PolicyPattern, PolicySource, Project, ReadOnlyEvidence, Realtime, Report, SourceStatus,
    Storage, Summary, Tool, apply_dispositions, skeleton,
};

fn finding(id: &str, kind: &str, classification: Classification) -> Finding {
    let (_kind, object) = id.split_once(':').expect("the id has a kind");
    Finding {
        id: id.to_owned(),
        kind: kind.to_owned(),
        object: object.to_owned(),
        classification,
        phase: "code".to_owned(),
        reason: format!("why {kind} is classified so"),
        cratefield_equivalent: "what it becomes".to_owned(),
    }
}

fn policy(table: &str, name: &str) -> Policy {
    Policy {
        schema: "public".to_owned(),
        table: table.to_owned(),
        name: name.to_owned(),
        command: "SELECT".to_owned(),
        permissive: true,
        roles: vec!["anon".to_owned()],
        using: Some("true".to_owned()),
        with_check: None,
        pattern: PolicyPattern::PublicRead,
        confidence: 1.0,
        source: PolicySource::Rule,
        classifier_label: None,
        suggested_equivalent: "a public read route".to_owned(),
        test_stub: "todo!()".to_owned(),
        disposition: Disposition::Undecided,
    }
}

/// One automatic finding, two policies that need work, a needs-work
/// function, and a blocker.
fn fixture() -> Report {
    let mut report = Report {
        report_version: 1,
        tool: Tool {
            name: "cratefield-import-supabase".to_owned(),
            version: "0.1.0".to_owned(),
        },
        project: Project {
            project_ref: "fixture".to_owned(),
            host: "db.test".to_owned(),
            port: 5432,
            database: "postgres".to_owned(),
            server_version: "16.0".to_owned(),
        },
        read_only: ReadOnlyEvidence {
            transaction_read_only: true,
            session_read_only: true,
            no_transaction_id_assigned: true,
            role: "ro".to_owned(),
            role_is_superuser: false,
            role_can_write: false,
        },
        coverage: Coverage {
            database: SourceStatus::Inspected,
            management_api: SourceStatus::NotInspected,
            policy_classifier: SourceStatus::NotInspected,
        },
        summary: Summary {
            automatic: 1,
            needs_work: 3,
            blockers: 1,
            decided: 0,
            undecided: 0,
            ready: false,
            tables: 0,
            estimated_rows: 0,
            data_bytes: 0,
            index_bytes: 0,
            storage_objects: 0,
            storage_bytes: 0,
            transfer_assumed_mbps: 100,
            estimated_transfer_seconds: 0,
        },
        dispositions: cratefield_import_supabase::DispositionsReport::default(),
        schemas: Vec::new(),
        tables: Vec::new(),
        views: Vec::new(),
        sequences: Vec::new(),
        enums: Vec::new(),
        extensions: Vec::new(),
        functions: Vec::new(),
        triggers: Vec::new(),
        policies: vec![
            policy("posts", "Anyone can read posts"),
            policy("posts", "Old policy"),
        ],
        api_role_grants: Vec::new(),
        auth: Auth::default(),
        storage: Storage::default(),
        edge_functions: EdgeFunctions {
            status: SourceStatus::NotInspected,
            functions: Vec::new(),
        },
        realtime: Realtime {
            publications: Vec::new(),
        },
        cron_jobs: Vec::new(),
        findings: vec![
            finding("extension:dblink", "extension", Classification::Blocker),
            finding(
                "function:public.handle_new_user()",
                "function",
                Classification::NeedsWork,
            ),
            finding(
                "policy:public.posts.Anyone can read posts",
                "policy",
                Classification::NeedsWork,
            ),
            finding(
                "policy:public.posts.Old policy",
                "policy",
                Classification::NeedsWork,
            ),
            finding("table:public.users", "table", Classification::Automatic),
        ],
        warnings: Vec::new(),
    };
    // As `inspect` does: an empty file leaves everything undecided.
    apply_dispositions(&mut report, &DispositionsFile::default());
    report
}

const FILE: &str = r#"
[items."policy:public.posts.Anyone can read posts"]
status = "covered"
ref = "src/posts/read.rs#list"

[items."policy:public.posts.Old policy"]
status = "waived"
reason = "superseded by the admin route"

[items."function:public.handle_new_user()"]
status = "undecided"

[items."policy:public.posts.Gone"]
status = "undecided"

[items."cron_job:nightly"]
status = "waived"
reason = "replaced by a scheduled handler"
"#;

#[test]
fn a_file_decides_what_it_names_and_the_rest_stays_undecided() {
    let mut report = fixture();
    let file = DispositionsFile::parse(FILE).expect("the file parses");
    apply_dispositions(&mut report, &file);

    assert_eq!(report.summary.decided, 2);
    assert_eq!(report.summary.undecided, 2);
    assert_eq!(report.summary.needs_work + report.summary.blockers, 4);
    // The policy list carries the same decision.
    assert_eq!(report.policies[0].disposition, Disposition::Covered);
    assert_eq!(report.policies[1].disposition, Disposition::Waived);
    // A placeholder entry and a missing one are both undecided, not stale.
    assert!(
        report
            .dispositions
            .stale
            .iter()
            .all(|id| id != "function:public.handle_new_user()")
    );
    assert!(
        report
            .dispositions
            .stale
            .iter()
            .all(|id| id != "extension:dblink")
    );
    // Entries that match no needs-work or blocker item, sorted.
    assert_eq!(
        report.dispositions.stale,
        ["cron_job:nightly", "policy:public.posts.Gone"]
    );
    let kinds: Vec<&str> = report
        .dispositions
        .by_kind
        .iter()
        .map(|kind| kind.kind.as_str())
        .collect();
    assert_eq!(kinds, ["extension", "function", "policy"]);

    let snapshot = serde_json::json!({
        "summary": { "decided": report.summary.decided, "undecided": report.summary.undecided },
        "by_kind": report.dispositions.by_kind,
        "decided": report.dispositions.decided,
        "stale": report.dispositions.stale,
        "policy_dispositions": report
            .policies
            .iter()
            .map(|policy| policy.disposition)
            .collect::<Vec<_>>(),
    });
    insta::assert_snapshot!(
        "report-dispositions",
        serde_json::to_string_pretty(&snapshot).expect("serializes")
    );
}

#[test]
fn the_skeleton_round_trips_to_everything_undecided() {
    let mut report = fixture();
    assert_eq!(report.summary.undecided, 4);
    let text = skeleton(&report);

    // The skeleton parses, and applied leaves every item undecided.
    let file = DispositionsFile::parse(&text).expect("the skeleton parses");
    apply_dispositions(&mut report, &file);
    assert_eq!(report.summary.decided, 0);
    assert_eq!(report.summary.undecided, 4);
    assert!(
        report.dispositions.stale.is_empty(),
        "{:?}",
        report.dispositions.stale
    );
    // One block per undecided item, keyed by the finding id (spaces and all).
    assert!(
        text.contains("[items.\"policy:public.posts.Anyone can read posts\"]"),
        "{text}"
    );
    assert!(text.contains("[items.\"extension:dblink\"]"), "{text}");
    assert!(!text.contains("table:public.users"), "{text}");
}

#[test]
fn awkward_ids_are_escaped_onto_one_line_and_round_trip() {
    let mut report = fixture();
    // Both quote kinds, a backslash, and a newline: the cases a plain TOML
    // string writer turns into an unparseable multi-line `[items.KEY]` header.
    for id in [
        r#"policy:public.posts.Only "owner's" can read"#,
        r"policy:public.posts.Back\slash",
        "policy:public.posts.New\nline",
    ] {
        report
            .findings
            .push(finding(id, "policy", Classification::NeedsWork));
    }
    // A reason with a newline must stay inside its `#` comment line.
    report.findings[0].reason = "dblink\nis not supported".to_owned();

    let text = skeleton(&report);
    // Every header is one line, escaped, and the reason is flattened.
    assert!(
        text.lines()
            .filter(|line| line.starts_with("[items."))
            .all(|line| line.ends_with(']')),
        "{text}"
    );
    assert!(
        text.contains(r#"[items."policy:public.posts.Only \"owner's\" can read"]"#),
        "{text}"
    );
    assert!(
        text.contains(r#"[items."policy:public.posts.Back\\slash"]"#),
        "{text}"
    );
    assert!(
        text.contains(r#"[items."policy:public.posts.New\nline"]"#),
        "{text}"
    );
    assert!(
        text.contains("# extension (blocker): dblink is not supported"),
        "{text}"
    );

    // The skeleton parses, and applied leaves every item undecided, none stale.
    let file = DispositionsFile::parse(&text).expect("the skeleton parses");
    apply_dispositions(&mut report, &file);
    assert_eq!(report.summary.decided, 0);
    assert_eq!(report.summary.undecided, 7);
    assert!(
        report.dispositions.stale.is_empty(),
        "{:?}",
        report.dispositions.stale
    );
}

#[test]
fn an_entry_keeps_only_the_field_its_status_uses() {
    let mut report = fixture();
    // A covered entry with a stray reason, and a waived entry with a stray ref.
    let file = DispositionsFile::parse(
        "[items.\"policy:public.posts.Anyone can read posts\"]\nstatus = \"covered\"\n\
         ref = \"src/posts/read.rs#list\"\nreason = \"stray\"\n\n\
         [items.\"policy:public.posts.Old policy\"]\nstatus = \"waived\"\n\
         reason = \"superseded\"\nref = \"stray\"\n",
    )
    .expect("parses");
    apply_dispositions(&mut report, &file);

    let decided = &report.dispositions.decided;
    let covered = decided
        .iter()
        .find(|item| item.status == Disposition::Covered);
    let waived = decided
        .iter()
        .find(|item| item.status == Disposition::Waived);
    assert_eq!(
        covered.and_then(|item| item.reference.as_deref()),
        Some("src/posts/read.rs#list")
    );
    assert_eq!(covered.and_then(|item| item.reason.as_deref()), None);
    assert_eq!(
        waived.and_then(|item| item.reason.as_deref()),
        Some("superseded")
    );
    assert_eq!(waived.and_then(|item| item.reference.as_deref()), None);
}

#[test]
fn a_waived_entry_without_a_reason_is_refused() {
    let error = DispositionsFile::parse(
        "[items.\"policy:public.posts.Anyone can read posts\"]\nstatus = \"waived\"\n",
    )
    .expect_err("no reason");
    let message = error.to_string();
    assert!(
        message.contains("policy:public.posts.Anyone can read posts"),
        "{message}"
    );
    assert!(message.contains("reason"), "{message}");
}

#[test]
fn a_covered_entry_without_a_ref_is_refused() {
    let error = DispositionsFile::parse(
        "[items.\"function:public.handle_new_user()\"]\nstatus = \"covered\"\n",
    )
    .expect_err("no ref");
    let message = error.to_string();
    assert!(
        message.contains("function:public.handle_new_user()"),
        "{message}"
    );
    assert!(message.contains("ref"), "{message}");
}

#[test]
fn a_glob_wildcard_key_is_refused_but_a_question_mark_is_a_literal() {
    let error =
        DispositionsFile::parse("[items.\"policy:public.posts.*\"]\nstatus = \"undecided\"\n")
            .expect_err("a wildcard");
    let message = error.to_string();
    assert!(message.contains("policy:public.posts.*"), "{message}");
    assert!(message.contains("never in bulk"), "{message}");

    // `?` can name a real policy, so it is not a wildcard.
    DispositionsFile::parse("[items.\"policy:public.posts.Who? am I\"]\nstatus = \"undecided\"\n")
        .expect("a literal question mark");
}

#[test]
fn a_key_that_is_not_a_finding_id_is_refused() {
    let error = DispositionsFile::parse("[items.\"public.posts\"]\nstatus = \"undecided\"\n")
        .expect_err("no kind");
    let message = error.to_string();
    assert!(message.contains("public.posts"), "{message}");
    assert!(message.contains("finding id"), "{message}");
}

#[test]
fn an_unknown_field_surfaces_the_toml_error() {
    let error =
        DispositionsFile::parse("[items.\"policy:a.b.c\"]\nstatus = \"undecided\"\nnope = 1\n")
            .expect_err("an unknown field");
    assert!(error.to_string().contains("nope"), "{error}");
}
