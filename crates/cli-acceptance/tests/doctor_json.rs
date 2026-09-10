//! `fz doctor --json` acceptance tests (harness #140): the seed the MCP
//! server (issue #160) will drive. Proves the JSON payload parses, the
//! `schema` field is present, a clean run is `ok: true` with an empty
//! failure list, a failing run carries the right stable code from
//! `cratefield_cli::codes`, and the human path's error message is
//! unchanged.

use cratefield_cli::doctor::{doctor, doctor_report_json};
use cratefield_cli::run;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use venture_fixture::harness_v1;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fz-doctor-json-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn migrations(&self) -> PathBuf {
        self.0.join("migrations")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(ToString::to_string).collect()
}

fn collect_into(dir: &std::path::Path) {
    let code = run(
        harness_v1,
        args(&["migrations", "collect", "--out", dir.to_str().unwrap()]),
    );
    assert_eq!(code, ExitCode::SUCCESS, "collect must succeed");
}

/// The exact stdout payload `fz doctor --json` emits for a clean run:
/// one object, one line, empty failures — the wire contract pinned.
#[test]
fn clean_run_is_ok_with_an_empty_failure_list() {
    let tmp = TempDir::new("clean");
    collect_into(&tmp.migrations());

    let report = doctor_report_json(&harness_v1(), &tmp.migrations(), None, None);
    let payload = report.render_json().expect("serializes");
    assert!(!payload.contains('\n'), "one line, no embedded newlines");
    assert_eq!(payload, "{\"schema\":1,\"ok\":true,\"failures\":[]}");

    // The same payload parses as JSON and carries the fields an agent
    // branches on.
    let parsed: serde_json::Value = serde_json::from_str(&payload).expect("parses");
    assert_eq!(parsed["schema"], serde_json::json!(1), "schema present");
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(
        parsed["failures"],
        serde_json::json!([]),
        "clean run: empty failure list"
    );
}

/// Every failure carries its catalogue code: the edited, missing and
/// not-collected lockfile situations each land on their own stable code.
#[test]
fn failing_run_carries_the_stable_code() {
    let tmp = TempDir::new("codes");
    let out = tmp.migrations();
    collect_into(&out);

    // Edited after being applied.
    let target = out.join("0001_email-signup_0001_init.sql");
    let original = fs::read_to_string(&target).expect("read");
    fs::write(&target, original.replace("subscribers", "tampered")).expect("write");

    let report = doctor_report_json(&harness_v1(), &out, None, None);
    assert!(!report.ok());
    let payload = report.render_json().expect("serializes");
    let parsed: serde_json::Value = serde_json::from_str(&payload).expect("parses");
    assert_eq!(parsed["ok"], serde_json::json!(false));
    let failures = parsed["failures"].as_array().expect("failure list");
    assert_eq!(failures.len(), 1, "one failure for one tampered file");
    assert_eq!(
        failures[0]["code"],
        serde_json::json!("locked-migration-edited")
    );
    assert_eq!(
        failures[0]["message"],
        serde_json::json!(
            "locked migration \"email-signup/0001\" was edited after being applied \
             (0001_email-signup_0001_init.sql) — restore the file or add a new migration instead"
        )
    );

    // Deleted entirely.
    fs::remove_file(&target).expect("delete");
    let parsed: serde_json::Value = serde_json::from_str(
        &doctor_report_json(&harness_v1(), &out, None, None)
            .render_json()
            .expect("serializes"),
    )
    .expect("parses");
    assert_eq!(
        parsed["failures"][0]["code"],
        serde_json::json!("locked-migration-missing")
    );

    // Nothing collected at all.
    let empty = TempDir::new("not-collected");
    fs::create_dir_all(empty.migrations()).expect("dir");
    let parsed: serde_json::Value = serde_json::from_str(
        &doctor_report_json(&harness_v1(), &empty.migrations(), None, None)
            .render_json()
            .expect("serializes"),
    )
    .expect("parses");
    let codes: Vec<&str> = parsed["failures"]
        .as_array()
        .expect("failure list")
        .iter()
        .map(|failure| failure["code"].as_str().expect("code is a string"))
        .collect();
    assert_eq!(
        codes,
        vec!["migration-not-collected", "migration-not-collected"],
        "one code per unlocked module migration"
    );
}

/// The human path is unchanged: `fz doctor` (no `--json`) reports the
/// same failure message the JSON carries, in the prose shape it has
/// always had.
#[test]
fn human_path_error_message_is_unchanged() {
    let tmp = TempDir::new("human");
    let out = tmp.migrations();
    collect_into(&out);

    let target = out.join("0001_email-signup_0001_init.sql");
    let original = fs::read_to_string(&target).expect("read");
    fs::write(&target, original.replace("subscribers", "tampered")).expect("write");

    let human = doctor(&harness_v1(), &out, None, None);
    let Err(message) = human else {
        panic!("doctor must fail on a tampered locked file");
    };
    assert_eq!(
        message,
        "locked migration \"email-signup/0001\" was edited after being applied \
         (0001_email-signup_0001_init.sql) — restore the file or add a new migration instead",
        "the prose error is byte-for-byte the pre-json message"
    );

    // Both disciplines speak the same words — the JSON message is the
    // prose message, plus its code.
    let json_report = doctor_report_json(&harness_v1(), &out, None, None);
    assert_eq!(json_report.failures.len(), 1);
    assert_eq!(json_report.failures[0].message, message);
}

/// `fz doctor --json` keeps the exit-code contract: success on a clean
/// venture, failure when a check fails.
#[test]
fn json_flag_exit_codes_mirror_the_verdict() {
    let tmp = TempDir::new("exit");
    let out = tmp.migrations();
    collect_into(&out);
    assert_eq!(
        run(
            harness_v1,
            args(&["doctor", "--out", out.to_str().unwrap(), "--json"])
        ),
        ExitCode::SUCCESS,
        "clean venture: --json exits success"
    );

    let target = out.join("0001_email-signup_0001_init.sql");
    let original = fs::read_to_string(&target).expect("read");
    fs::write(&target, original.replace("subscribers", "tampered")).expect("write");
    assert_eq!(
        run(
            harness_v1,
            args(&["doctor", "--out", out.to_str().unwrap(), "--json"])
        ),
        ExitCode::FAILURE,
        "tampered lock: --json exits failure"
    );
}
