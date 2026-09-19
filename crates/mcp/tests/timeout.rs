//! The time limit: a child that outlives it is killed and its call
//! comes back as the fourth wrapper code, `mcp-fz-timeout`, instead of
//! hanging a serial server forever; `0` — no limit — waits as long as
//! the child takes; a value that is not a whole number of seconds is a
//! startup misuse, never a silent fallback to the default.

mod common;

use common::{call_tool, envelope_of, failure_code, text_of};

use cratefield_mcp::fz::{ProcessRunner, parse_timeout_secs};
use cratefield_mcp::server::Server;

/// The clean envelope the stub prints, so a run that finishes counts as
/// a real answer.
const CLEAN: &str = r#"{"schema":1,"ok":true,"failures":[]}"#;

/// The grammar of `FZ_MCP_TIMEOUT_SECS`: a whole number of seconds,
/// `0` meaning no limit. Pinned on the pure parser because a test
/// cannot set process-global environment state — the edition forbids
/// it — and because the parser is the whole contract.
#[test]
fn a_zero_limit_parses_to_no_limit_at_all() {
    assert_eq!(parse_timeout_secs("0"), Ok(None));
    assert_eq!(
        parse_timeout_secs(" 0\n"),
        Ok(None),
        "whitespace around the number is not a refusal"
    );
}

#[test]
fn a_number_parses_to_whole_seconds() {
    assert_eq!(
        parse_timeout_secs("600"),
        Ok(Some(std::time::Duration::from_secs(600)))
    );
}

#[test]
fn a_non_numeric_limit_is_refused_not_silently_defaulted() {
    let error = parse_timeout_secs("soon").expect_err("a non-number is a misuse");
    assert!(
        error.contains("FZ_MCP_TIMEOUT_SECS"),
        "the refusal names the variable: {error}"
    );
    assert!(
        error.contains("soon"),
        "the refusal names the value it refused: {error}"
    );
    assert!(parse_timeout_secs("").is_err(), "an empty value is not 0");
}

/// The defect the limit exists for: a child that never finishes comes
/// back as `mcp-fz-timeout`, naming the program and the limit — and
/// the limit bounds how long the call takes, which is the whole point
/// of it. The stub is a shell running `sleep 60`: killing the shell
/// leaves the `sleep` behind, and the `sleep` inherited the piped
/// stdout and stderr, so the pipes reach EOF only when the grandchild
/// exits. Joining the reader threads on the timeout path — the
/// pre-fix behaviour — made this call take the grandchild's full
/// sixty seconds; `run` must return near the limit instead. Five
/// limit-widths of headroom cannot flake on a loaded CI machine, and
/// a regression — waiting out the grandchild — fails it decisively.
#[cfg(unix)]
#[test]
fn a_child_that_outlives_the_limit_is_killed_and_reported_as_mcp_fz_timeout() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    use cratefield_testing::TempDir;

    let dir = TempDir::new("fz-mcp-timeout");
    let stub = dir.join("slow-fz.sh");
    // `sh` is bash here, which does not exec-optimise its last command:
    // the `sleep` runs as a grandchild and outlives the killed shell,
    // holding the inherited pipe write ends open.
    fs::write(&stub, "#!/bin/sh\nsleep 60\n").expect("writes the stub");
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod the stub");

    let runner = ProcessRunner::new(
        None,
        vec![stub.display().to_string()],
        Some(Duration::from_secs(1)),
    );
    let mut server = Server::new(runner);
    let started = Instant::now();
    let result = call_tool(&mut server, "fz_doctor", "{}");
    let elapsed = started.elapsed();
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(failure_code(&envelope), "mcp-fz-timeout");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("slow-fz.sh"),
        "the message names the program: {message}"
    );
    assert!(
        message.contains("1s"),
        "the message names the limit it outlived: {message}"
    );
    // The same envelope as text: one refusal shape, whatever produced it.
    assert!(
        text_of(&result).contains("mcp-fz-timeout"),
        "the text content carries the same failure"
    );
    // And the limit actually bounded the call: back well within a few
    // seconds even though the orphaned grandchild holds the pipe write
    // ends open for another minute.
    assert!(
        elapsed < Duration::from_secs(5),
        "the timeout must bound the call while the orphaned grandchild still holds the pipes open: took {elapsed:?}"
    );
}

/// `FZ_MCP_TIMEOUT_SECS=0` reaches the runner as no limit at all: a
/// child that takes longer than any plausible small default finishes
/// and answers. Pinned with a two-second sleeper, so any limit of two
/// seconds or less — the default misread as a constant, say — fails here.
#[cfg(unix)]
#[test]
fn a_zero_limit_waits_for_the_child_however_long_it_takes() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use cratefield_testing::TempDir;

    let dir = TempDir::new("fz-mcp-no-timeout");
    let stub = dir.join("unhurried-fz.sh");
    fs::write(
        &stub,
        format!("#!/bin/sh\nsleep 2\nprintf '%s' '{CLEAN}'\n"),
    )
    .expect("writes the stub");
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod the stub");

    let runner = ProcessRunner::new(
        None,
        vec![stub.display().to_string()],
        None, // FZ_MCP_TIMEOUT_SECS=0 parses to exactly this
    );
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", "{}");
    assert_eq!(result["isError"], false);
    assert_eq!(envelope_of(&result)["ok"], true);
}
