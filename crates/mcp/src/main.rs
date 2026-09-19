//! `fz-mcp` — the binary half of the MCP server: parse `--cwd` and the
//! `--` command, wire the runner, serve stdio until EOF.
//!
//! All of the protocol lives in the library ([`cratefield_mcp`]); this
//! file is argument parsing and wiring only, because the server must be
//! drivable as a library before it is runnable as a process.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use cratefield_mcp::fz::FzConfig;
use cratefield_mcp::server::{self, Server};

/// Printed for `--help`/`-h` on stdout, and for a usage mistake on
/// stderr with exit 2. This is not an MCP message, so it may only ever
/// be printed before the server loop starts — once serving, stdout
/// belongs to the protocol alone.
const USAGE: &str = "\
fz-mcp: a Model Context Protocol server over `fz --json` (issue #160)

usage: fz-mcp [--cwd <dir>] [-- <fz program and leading args>...]

  --cwd <dir>   the directory fz runs in; env FZ_MCP_CWD
  -- <words>    the fz program to run, plus any leading arguments, e.g.
                `fz-mcp --cwd ./my-venture -- cargo run -q --bin fz --`;
                env FZ_MCP_COMMAND (split on whitespace, no shell
                interpretation); default: fz

A child that has not exited after FZ_MCP_TIMEOUT_SECS seconds (default
600 — generous, because fz deploy legitimately takes minutes; 0 disables
the limit) is killed, and its call comes back as an `mcp-fz-timeout`
envelope. A non-numeric value is refused here, at startup.

Answers newline-delimited JSON on stdout until stdin ends.
";

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    let (cwd, command) = match parse_args(&argv) {
        Ok(parsed) => parsed,
        Err(ParseOutcome::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(ParseOutcome::Misuse(message)) => {
            eprintln!("fz-mcp: {message}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let config = match FzConfig::resolve(cwd, command) {
        Ok(config) => config,
        // A bad environment fallback is the same kind of mistake as a
        // bad flag: say so, print the usage, exit 2 — before anything
        // is served, while stderr is still ours to talk on.
        Err(message) => {
            eprintln!("fz-mcp: {message}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if config.command.is_empty() {
        eprintln!("fz-mcp: the fz command is empty (FZ_MCP_COMMAND, or the words after --)");
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    // One diagnostic line, on stderr: stdout belongs to the protocol,
    // and an operator starting this by hand deserves to see what it
    // will run and where.
    let place = config.cwd.as_deref().map_or_else(
        || "the current directory".to_owned(),
        |cwd| format!("cwd {}", cwd.display()),
    );
    eprintln!(
        "fz-mcp: running `{}` from {}, serving MCP over stdio until EOF",
        config.command.join(" "),
        place
    );
    let mut server = Server::new(config.runner());
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    match server::serve(&mut server, &mut input, &mut output) {
        Ok(()) => ExitCode::SUCCESS,
        // The transport itself broke; there is no client left to say
        // anything MCP-shaped to.
        Err(error) => {
            eprintln!("fz-mcp: stdio failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// What argv parsing produced: help, a usage mistake, or the resolved
/// flags (the directory, the explicit command words after `--`).
enum ParseOutcome {
    Help,
    Misuse(String),
}

fn parse_args(argv: &[OsString]) -> Result<(Option<PathBuf>, Option<Vec<String>>), ParseOutcome> {
    let mut cwd = None;
    let mut command = None;
    let mut remaining = argv.iter();
    while let Some(arg) = remaining.next() {
        let arg = utf8(arg)?;
        match arg.as_str() {
            "--help" | "-h" => return Err(ParseOutcome::Help),
            "--cwd" => {
                let value = remaining.next().map(utf8).transpose()?.ok_or_else(|| {
                    ParseOutcome::Misuse("--cwd needs a directory argument".to_owned())
                })?;
                if value.is_empty() {
                    // An empty directory is not "the current directory",
                    // it is nothing: it names no directory the child
                    // could run in, so the flag form is refused here,
                    // with a message, instead of surfacing later as a
                    // spawn failure. The fallback is not the same
                    // refusal — an empty FZ_MCP_CWD counts as unset,
                    // because a variable exported empty looks like
                    // nothing was configured, not like an operator
                    // typing an empty flag.
                    return Err(ParseOutcome::Misuse(
                        "--cwd needs a non-empty directory argument".to_owned(),
                    ));
                }
                cwd = Some(PathBuf::from(value));
            }
            // Everything after `--` belongs to the fz command, including
            // any further `--`: our surface ends at the first one.
            "--" => {
                let mut words = Vec::new();
                for word in remaining {
                    words.push(utf8(word)?);
                }
                command = Some(words);
                break;
            }
            _ if arg.starts_with('-') => {
                return Err(ParseOutcome::Misuse(format!("unknown flag {arg}")));
            }
            _ => {
                return Err(ParseOutcome::Misuse(format!(
                    "unexpected argument {arg} (only --cwd and -- are accepted)"
                )));
            }
        }
    }
    Ok((cwd, command))
}

/// Non-UTF-8 arguments are refused, not mangled: this argv becomes the
/// child's argv and its paths, and a lossy conversion would run
/// something other than what the operator typed.
fn utf8(arg: &OsString) -> Result<String, ParseOutcome> {
    arg.clone()
        .into_string()
        .map_err(|_| ParseOutcome::Misuse("arguments must be valid UTF-8".to_owned()))
}
