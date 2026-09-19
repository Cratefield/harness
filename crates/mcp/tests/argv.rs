//! The argv each tool builds, pinned word for word: the wrapper's whole
//! value is running the right command, so a renamed flag, a lost
//! positional or a stray `--non-interactive` must fail here. Driven
//! through `Server::handle` so what is tested is the wire path, not the
//! builder in isolation.

mod common;

use common::{call_tool, printing};

use cratefield_mcp::server::Server;

/// The clean envelope the stubbed `fz` prints; the argv is the subject
/// here, so what it says does not matter, only that it is an object.
const CLEAN: &str = r#"{"schema":1,"ok":true,"failures":[]}"#;

#[test]
fn doctor_runs_json_alone_when_every_argument_is_absent() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", "{}");
    assert_eq!(result["isError"], false);
    // The one verb with no `--non-interactive`: it has no prompts to
    // suppress, and the flag is its siblings'.
    assert_eq!(calls.single(), ["doctor", "--json"]);
}

#[test]
fn doctor_passes_its_optional_flags_when_present() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(
        &mut server,
        "fz_doctor",
        r#"{"out":"migrations","allow_no_captcha":"no captcha port yet"}"#,
    );
    assert_eq!(
        calls.single(),
        [
            "doctor",
            "--json",
            "--out",
            "migrations",
            "--allow-no-captcha",
            "no captcha port yet",
        ]
    );
}

#[test]
fn plan_with_no_arguments_pins_json_and_non_interactive() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(&mut server, "fz_plan", "{}");
    assert_eq!(calls.single(), ["plan", "--json", "--non-interactive"]);
}

#[test]
fn plan_passes_its_optional_paths_in_argument_order() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(
        &mut server,
        "fz_plan",
        r#"{"manifest":"venture.json","migrations":"m"}"#,
    );
    assert_eq!(
        calls.single(),
        [
            "plan",
            "--json",
            "--non-interactive",
            "--manifest",
            "venture.json",
            "--migrations",
            "m",
        ]
    );
}

#[test]
fn verify_is_non_interactive_and_passes_its_optional_paths() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(
        &mut server,
        "fz_verify",
        r#"{"manifest":"other.json","migrations":"db"}"#,
    );
    assert_eq!(
        calls.single(),
        [
            "verify",
            "--json",
            "--non-interactive",
            "--manifest",
            "other.json",
            "--migrations",
            "db",
        ]
    );
}

#[test]
fn init_carries_name_host_and_the_optional_manifest_and_force() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(
        &mut server,
        "fz_init",
        r#"{"name":"venture","host":"example.com","manifest":"other.json","force":true}"#,
    );
    assert_eq!(
        calls.single(),
        [
            "init",
            "--json",
            "--non-interactive",
            "--name",
            "venture",
            "--host",
            "example.com",
            "--manifest",
            "other.json",
            "--force",
        ]
    );
}

#[test]
fn init_omits_force_when_it_is_explicitly_false() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(
        &mut server,
        "fz_init",
        r#"{"name":"venture","host":"example.com","force":false}"#,
    );
    assert_eq!(
        calls.single(),
        [
            "init",
            "--json",
            "--non-interactive",
            "--name",
            "venture",
            "--host",
            "example.com",
        ]
    );
}

#[test]
fn add_appends_the_module_positionally_before_the_optional_manifest() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(
        &mut server,
        "fz_add",
        r#"{"module":"cms","manifest":"venture.json"}"#,
    );
    assert_eq!(
        calls.single(),
        [
            "add",
            "--json",
            "--non-interactive",
            "cms",
            "--manifest",
            "venture.json",
        ]
    );
}

#[test]
fn deploy_carries_the_digest_and_only_the_true_consent_flags() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(
        &mut server,
        "fz_deploy",
        r#"{"plan":"deadbeef","manifest":"venture.json","migrations":"m","i_am_deploying_to_production":true,"i_am_removing_modules":false}"#,
    );
    // `i_am_removing_modules` is `false` and must be absent: a consent
    // flag that fires on `false` is not consent.
    assert_eq!(
        calls.single(),
        [
            "deploy",
            "--json",
            "--non-interactive",
            "--plan",
            "deadbeef",
            "--manifest",
            "venture.json",
            "--migrations",
            "m",
            "--i-am-deploying-to-production",
        ]
    );
}

#[test]
fn deploy_sets_both_consent_flags_when_both_are_true() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(
        &mut server,
        "fz_deploy",
        r#"{"plan":"deadbeef","i_am_deploying_to_production":true,"i_am_removing_modules":true}"#,
    );
    assert_eq!(
        calls.single(),
        [
            "deploy",
            "--json",
            "--non-interactive",
            "--plan",
            "deadbeef",
            "--i-am-deploying-to-production",
            "--i-am-removing-modules",
        ]
    );
}

#[test]
fn deploy_with_no_arguments_runs_its_fixed_flags_only() {
    let (runner, calls) = printing(CLEAN);
    let mut server = Server::new(runner);
    call_tool(&mut server, "fz_deploy", "{}");
    assert_eq!(calls.single(), ["deploy", "--json", "--non-interactive"]);
}
