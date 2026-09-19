//! The one seam that touches a process, proven for real: `ProcessRunner`
//! spawns the configured program, appends the tool argv after the
//! configured leading arguments, runs it in the configured directory,
//! and reports an unspawnable command as `mcp-fz-unavailable`.

mod common;

use common::{call_tool, envelope_of};

use cratefield_mcp::fz::ProcessRunner;
use cratefield_mcp::server::Server;

#[test]
fn an_unspawnable_command_comes_back_as_mcp_fz_unavailable() {
    let runner = ProcessRunner::new(
        None,
        vec!["cratefield-mcp-definitely-not-a-binary-anywhere".to_owned()],
        None,
    );
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", "{}");
    assert_eq!(result["isError"], true);
    let envelope = envelope_of(&result);
    assert_eq!(envelope["failures"][0]["code"], "mcp-fz-unavailable");
    let message = envelope["failures"][0]["message"]
        .as_str()
        .expect("message");
    assert!(
        message.contains("cratefield-mcp-definitely-not-a-binary-anywhere"),
        "the configured program is named: {message}"
    );
}

/// End to end with a real child: a shell stub stands in for `fz`, the
/// configured leading argument precedes the tool argv, and the child
/// runs in the configured directory. Needs a shebang and a chmod, so it
/// stays on unix.
#[cfg(unix)]
#[test]
fn the_real_runner_spawns_the_stub_with_leading_args_in_the_configured_cwd() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use cratefield_testing::TempDir;

    let dir = TempDir::new("fz-mcp-process");
    let stub = dir.join("fake-fz.sh");
    fs::write(
        &stub,
        "#!/bin/sh\nprintf '{\"argv\":\"%s\",\"cwd\":\"%s\"}' \"$*\" \"$(pwd)\"\n",
    )
    .expect("writes the stub");
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod the stub");

    let runner = ProcessRunner::new(
        Some(dir.path().to_path_buf()),
        vec![stub.display().to_string(), "leading-arg".to_owned()],
        None,
    );
    let mut server = Server::new(runner);
    let result = call_tool(&mut server, "fz_doctor", r#"{"out":"migrations"}"#);
    assert_eq!(result["isError"], false);

    let envelope = envelope_of(&result);
    assert_eq!(
        envelope["argv"], "leading-arg doctor --json --out migrations",
        "the tool argv follows the configured leading argument"
    );
    assert_eq!(
        envelope["cwd"],
        // Canonicalised on both sides: on macOS the temp dir is handed out
        // as `/var/...`, which is a symlink to `/private/var/...`, and the
        // child reports the resolved path. Comparing the unresolved string
        // fails there and nowhere else, so the test only ever held on the
        // Linux runner.
        dir.path()
            .canonicalize()
            .expect("the temp dir exists")
            .display()
            .to_string(),
        "the child runs in the configured directory"
    );
}
