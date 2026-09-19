//! The process boundary: which `fz` runs, how it runs, and how its
//! stdout turns back into the envelope.
//!
//! `fz` must be a child process, never a library call: in a venture it
//! is a `[[bin]]` linked against that venture's compiled-in harness, and
//! the harness-bound verbs (`fz doctor` most of all) cannot run in a
//! process that lacks it. [`FzRunner`] is the seam that keeps the rest
//! of the crate testable without spawning anything — the tools see only
//! the trait, and [`ProcessRunner`] is the one implementation that
//! touches the operating system.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::codes::{DoctorCodeDef, FZ_TIMEOUT, FZ_UNAVAILABLE};

/// The `schema` field of every envelope this crate synthesises — the
/// CLI's own constant, read through its public path rather than copied:
/// the crate already depends on `cratefield-cli` for the catalogue, so
/// a second literal would be one more place that can disagree. When the
/// CLI bumps its schema, these envelopes must claim the version the
/// child's real ones already do.
pub const SCHEMA: u32 = cratefield_cli::workflow::SCHEMA;

/// How long a child may run when `FZ_MCP_TIMEOUT_SECS` says nothing.
/// Generous on purpose — `fz deploy` legitimately takes minutes — the
/// point is only that a wedged child eventually surfaces as an error
/// instead of hanging the server forever: the serve loop answers one
/// call at a time, so a child that never exits would stop even `ping`
/// from being answered. Not exotic when the documented invocation is
/// `cargo run -q --bin fz --`, and cargo blocks on its package lock
/// whenever another cargo holds it.
pub const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Reads the time limit from `FZ_MCP_TIMEOUT_SECS`:
/// [`DEFAULT_TIMEOUT_SECS`] when unset, [`None`] — no limit at all —
/// when it is `0`.
///
/// # Errors
///
/// A non-UTF-8 or non-numeric value is `Err`, never a silent fallback
/// to the default: a limit that quietly meant something else would look
/// like a working server that never kills anything. `main` prints the
/// message with the usage and exits 2.
pub fn timeout_from_env() -> Result<Option<Duration>, String> {
    match std::env::var("FZ_MCP_TIMEOUT_SECS") {
        Ok(text) => parse_timeout_secs(&text),
        Err(std::env::VarError::NotPresent) => Ok(Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS))),
        Err(std::env::VarError::NotUnicode(_)) => Err(
            "FZ_MCP_TIMEOUT_SECS is set but is not valid UTF-8; refusing rather than guessing the limit"
                .to_owned(),
        ),
    }
}

/// Parses one `FZ_MCP_TIMEOUT_SECS` value: a whole number of seconds,
/// `0` meaning no limit. Split from [`timeout_from_env`] so the grammar
/// is testable without mutating process-global state.
///
/// # Errors
///
/// Anything but a whole number of seconds is `Err`, naming the variable
/// and the value that was refused.
pub fn parse_timeout_secs(text: &str) -> Result<Option<Duration>, String> {
    match text.trim().parse::<u64>() {
        Ok(0) => Ok(None),
        Ok(secs) => Ok(Some(Duration::from_secs(secs))),
        Err(_) => Err(format!(
            "FZ_MCP_TIMEOUT_SECS must be a whole number of seconds (0 for no limit), not `{text}`"
        )),
    }
}

/// One failure as it travels on the wire: the stable catalogue slug plus
/// the human message, exactly the shape an `fz` failure carries.
#[derive(Debug, Serialize)]
pub struct FailRef {
    /// The stable kebab-case code.
    pub code: &'static str,
    /// The human message; wording may change freely.
    pub message: String,
}

/// The envelope one tool result carries, in both representations the
/// server needs: the line the agent reads and the object it parses.
///
/// `text` is what goes into `content[0].text` — for an envelope born of
/// an [`FzOutput`], exactly the line `fz` printed, byte for byte, so
/// the agent sees precisely what `fz` said even where a re-serialised
/// copy would differ (`serde_json`'s map orders keys its own way). For
/// an envelope this crate synthesises, the struct-serialised form,
/// whose field order serde keeps. `value` is the same object parsed or
/// built, read for `ok` and served as `structuredContent`; its keys
/// travel in `serde_json`'s map order, which is the representation the
/// protocol puts no promise on.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The envelope on one line, as `content[0].text`.
    pub text: String,
    /// The same envelope parsed, for `ok` and `structuredContent`.
    pub value: serde_json::Value,
}

impl Envelope {
    /// Serialises one payload both ways: its exact bytes as the text —
    /// a struct's field order is serde's own, kept without any feature
    /// — and the parsed value beside it. The constructor for every
    /// envelope with no upstream line to pass through.
    ///
    /// # Panics
    ///
    /// Only if `payload` is not plain JSON, which the type system
    /// cannot rule out here; every caller passes a struct of strings,
    /// numbers, booleans and arrays, and serialising those cannot fail.
    #[must_use]
    pub fn serialised<T: Serialize>(payload: &T) -> Self {
        Self {
            text: serde_json::to_string(payload)
                .expect("an envelope payload is plain JSON; serialisation cannot fail"),
            value: serde_json::to_value(payload)
                .expect("an envelope payload is plain JSON; serialisation cannot fail"),
        }
    }
}

/// One synthesised envelope as it serialises: a struct, not a `json!`
/// map, because a map's keys come out in `serde_json`'s sort order
/// while the envelope's documented shape is `schema`, `ok`, `failures`
/// first.
#[derive(Serialize)]
struct FailureEnvelope {
    schema: u32,
    ok: bool,
    failures: Vec<FailRef>,
}

/// Builds one envelope in `fz`'s failure shape — the only way this
/// crate says "no": `schema`, `ok` false, and the reasons under
/// `failures`, each carrying its stable code. A wrapper failure must be
/// indistinguishable in shape from an `fz` failure, because an agent
/// parses exactly one object shape forever.
#[must_use]
pub fn failure_envelope(code: &DoctorCodeDef, message: impl Into<String>) -> Envelope {
    Envelope::serialised(&FailureEnvelope {
        schema: SCHEMA,
        ok: false,
        failures: vec![FailRef {
            code: code.code,
            message: message.into(),
        }],
    })
}

/// Whether the envelope reports a failure: exactly when its `ok` is
/// `false`. This is the only thing a result's `isError` may key on.
#[must_use]
pub fn is_failure(envelope: &serde_json::Value) -> bool {
    matches!(envelope.get("ok"), Some(serde_json::Value::Bool(false)))
}

/// What one `fz` run produced.
#[derive(Debug, Clone)]
pub struct FzOutput {
    /// The child's exit code, or `None` when it was killed by a signal
    /// and so never exited at all.
    pub status: Option<i32>,
    /// Everything the child wrote to stdout, lossily UTF-8.
    pub stdout: String,
    /// Everything the child wrote to stderr, lossily UTF-8.
    pub stderr: String,
}

/// The process boundary. One method, so a test fake is three lines.
pub trait FzRunner {
    /// Run the configured `fz` program with `args`; `Err` means no
    /// envelope can exist, and says which of the two ways that happens
    /// it was.
    ///
    /// # Errors
    ///
    /// [`FzFailure::Unavailable`] when the child could not be started at
    /// all — a missing binary, a configured working directory that does
    /// not exist. [`FzFailure::Timeout`] when the child outlived the
    /// configured limit and was killed. A child that ran and then failed
    /// is `Ok`: its exit status travels inside [`FzOutput`].
    fn run(&self, args: &[String]) -> Result<FzOutput, FzFailure>;
}

/// Why a configured `fz` run produced no envelope at all. Two different
/// things that land on two different catalogue codes, so they are two
/// variants rather than two wordings of one string.
#[derive(Debug, Clone)]
pub enum FzFailure {
    /// The child could not be spawned at all — a missing binary, a
    /// configured working directory that does not exist. Carries the
    /// reason: the program name plus the OS error.
    Unavailable(String),
    /// The child outlived the configured limit and was killed. Carries
    /// the configured command line and the limit it outlived — what the
    /// `mcp-fz-timeout` message names.
    Timeout {
        /// The configured command line, as the operator wrote it.
        program: String,
        /// The limit the child outlived.
        limit: Duration,
    },
}

impl FzFailure {
    /// The wrapper code this failure is reported under.
    #[must_use]
    pub fn code(&self) -> &'static DoctorCodeDef {
        match self {
            Self::Unavailable(_) => &FZ_UNAVAILABLE,
            Self::Timeout { .. } => &FZ_TIMEOUT,
        }
    }

    /// The human message the failure carries, naming what the operator
    /// can act on.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Unavailable(reason) => reason.clone(),
            Self::Timeout { program, limit } => format!(
                "fz did not finish within {}s and was killed: `{program}`",
                limit.as_secs()
            ),
        }
    }
}

/// The real [`FzRunner`]: spawns the configured program as a child and
/// waits, with a deadline when one is configured.
#[derive(Debug, Clone)]
pub struct ProcessRunner {
    cwd: Option<PathBuf>,
    command: Vec<String>,
    /// How long the child may live; `None` — `FZ_MCP_TIMEOUT_SECS=0` —
    /// means no limit, wait as long as it takes.
    timeout: Option<Duration>,
}

impl ProcessRunner {
    /// `command` is the full command line — program first; the `args`
    /// of [`FzRunner::run`] are appended after its leading arguments.
    /// `timeout` is how long the child may live before it is killed:
    /// `None` waits forever.
    #[must_use]
    pub fn new(cwd: Option<PathBuf>, command: Vec<String>, timeout: Option<Duration>) -> Self {
        Self {
            cwd,
            command,
            timeout,
        }
    }
}

/// How often the wait polls the child. Small enough that the deadline
/// is met to within a poll of when it should be; cheap enough that a
/// six-hundred-second deploy pays nothing for it.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Reads one piped stream to EOF on a fresh thread, yielding everything
/// it carried, lossily UTF-8. Each stream gets its own thread so both
/// drain concurrently — the one property `Command::output` provided that
/// the polling wait below cannot do without: a child that fills a pipe
/// buffer must never block on its own writes, or it would hang with the
/// server hanging on the child, each on the other.
#[must_use]
fn drain_stream(pipe: impl Read + Send + 'static) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut pipe = pipe;
        // A mid-read error keeps whatever arrived: the child's partial
        // output is worth more here than a clean failure.
        let _ = pipe.read_to_end(&mut buffer);
        String::from_utf8_lossy(&buffer).into_owned()
    })
}

impl FzRunner for ProcessRunner {
    fn run(&self, args: &[String]) -> Result<FzOutput, FzFailure> {
        let Some((program, leading)) = self.command.split_first() else {
            return Err(FzFailure::Unavailable(
                "the configured fz command is empty".to_owned(),
            ));
        };
        let mut command = Command::new(program);
        command.args(leading).args(args);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        // The child's stdin is /dev/null, never ours: an `fz` that tried
        // to prompt (the six agent verbs never do, by construction)
        // would otherwise eat MCP messages off our stdin and
        // desynchronise the protocol. stdout and stderr are piped
        // because a child that inherited our stdout would inject raw
        // bytes into the MCP stream — precisely what this wrapper exists
        // to make impossible. The environment is inherited untouched.
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            FzFailure::Unavailable(format!("could not run `{program}`: {error}"))
        })?;

        // Hand both pipes to their reader threads before waiting, so
        // the child can always write: the deadlock a `try_wait` loop
        // with no readers dies of needs a full pipe to bite, and a full
        // pipe needs an undrained one.
        let stdout = child.stdout.take().map(drain_stream);
        let stderr = child.stderr.take().map(drain_stream);

        // Poll instead of blocking on `wait`, so the deadline is ours
        // to enforce rather than the child's to outlive.
        let deadline = self.timeout.map(|limit| Instant::now() + limit);
        let mut expired = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        expired = true;
                        break None;
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(error) => {
                    return Err(FzFailure::Unavailable(format!(
                        "could not run `{program}`: {error}"
                    )));
                }
            }
        };
        if expired {
            // Kill, then reap: the kill is what bounds the child, the
            // wait is what leaves no zombie behind. Both are
            // best-effort — a child that exits inside the race window
            // makes kill fail, and whichever way it exited, the answer
            // is the timeout.
            let _ = child.kill();
            let _ = child.wait();
            // Detach the reader threads instead of joining them. A pipe
            // reaches EOF only when *every* write end is closed, and
            // the kill closed only the child's: grandchildren that
            // inherited the pipes — a shell stub's `sleep`, the `rustc`
            // behind the documented `cargo run -q --bin fz --` — keep
            // them open after the child is dead, so a join here would
            // block until they exit and the limit would stop bounding
            // `run` at all, wedging a serial server despite the
            // timeout. The output is not used on this path — the
            // answer is the timeout whatever the child printed — so
            // the handles drop as we return and the threads are left
            // to finish on their own. The trade-off is deliberate: a
            // timed-out call can leave a reader thread alive until the
            // last write end closes. Such a thread is bounded and
            // harmless (it reads to EOF, ignores read errors, and its
            // result is discarded once nothing will join it, so it can
            // neither panic nor block anything); a server stuck past
            // its own deadline is not.
            return Err(FzFailure::Timeout {
                program: self.command.join(" "),
                limit: self.timeout.expect("expired implies a limit"),
            });
        }
        // The child exited on its own, so the output is complete once
        // the pipes drain: EOF is the signal that it is, and the
        // output is what this path exists to hand back.
        let stdout = stdout
            .map(|handle| handle.join().expect("the pipe reader cannot panic"))
            .unwrap_or_default();
        let stderr = stderr
            .map(|handle| handle.join().expect("the pipe reader cannot panic"))
            .unwrap_or_default();
        Ok(FzOutput {
            status: status.and_then(|status| status.code()),
            stdout,
            stderr,
        })
    }
}

/// Which `fz` to run, where, and for how long: the configuration
/// `fz-mcp` resolves from its flags and their environment fallbacks.
#[derive(Debug, Clone)]
pub struct FzConfig {
    /// The directory the child runs in, when one is configured.
    pub cwd: Option<PathBuf>,
    /// The full command line, program first. Default `["fz"]`.
    pub command: Vec<String>,
    /// How long a child may run before it is killed; `None` —
    /// `FZ_MCP_TIMEOUT_SECS=0` — waits as long as it takes.
    /// Default [`DEFAULT_TIMEOUT_SECS`].
    pub timeout: Option<Duration>,
}

impl FzConfig {
    /// Resolves the configuration: each flag wins over its environment
    /// fallback (`FZ_MCP_CWD`, `FZ_MCP_COMMAND`), the command defaults
    /// to plain `fz`, and the time limit comes from `FZ_MCP_TIMEOUT_SECS`
    /// ([`timeout_from_env`]). `FZ_MCP_COMMAND` is split on ASCII
    /// whitespace with **no shell interpretation** — a value like
    /// `cargo run -q --bin fz --` is five arguments, and a quoted or
    /// globbed value would silently do something else than the operator
    /// typed. An empty `FZ_MCP_CWD` counts as unset; the flag form is
    /// refused instead, at parse time.
    ///
    /// # Errors
    ///
    /// A non-UTF-8 `FZ_MCP_CWD`, `FZ_MCP_COMMAND` or
    /// `FZ_MCP_TIMEOUT_SECS` is refused, as is a non-numeric timeout:
    /// this configuration becomes the child's argv, its working
    /// directory and its leash, and a lossy reading would run something
    /// other than what the operator configured. `main` prints the
    /// message with the usage and exits 2.
    pub fn resolve(
        cwd_flag: Option<PathBuf>,
        command_flag: Option<Vec<String>>,
    ) -> Result<Self, String> {
        let cwd = cwd_flag
            .map_or_else(
                || match std::env::var("FZ_MCP_CWD") {
                    Ok(text) if text.is_empty() => Ok(None),
                    Ok(text) => Ok(Some(PathBuf::from(text))),
                    Err(std::env::VarError::NotPresent) => Ok(None),
                    Err(std::env::VarError::NotUnicode(_)) => Err(
                        "FZ_MCP_CWD is set but is not valid UTF-8; refusing rather than running somewhere the operator did not configure".to_owned(),
                    ),
                },
                |cwd| Ok(Some(cwd)),
            )?;
        let command = command_flag
            .map_or_else(
                || match std::env::var("FZ_MCP_COMMAND") {
                    Ok(text) => Ok(text
                        .split_ascii_whitespace()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()),
                    Err(std::env::VarError::NotPresent) => Ok(vec!["fz".to_owned()]),
                    Err(std::env::VarError::NotUnicode(_)) => Err(
                        "FZ_MCP_COMMAND is set but is not valid UTF-8; refusing rather than running something other than the operator configured".to_owned(),
                    ),
                },
                Ok,
            )?;
        let timeout = timeout_from_env()?;
        Ok(Self {
            cwd,
            command,
            timeout,
        })
    }

    /// The runner this configuration describes.
    #[must_use]
    pub fn runner(&self) -> ProcessRunner {
        ProcessRunner::new(self.cwd.clone(), self.command.clone(), self.timeout)
    }
}

/// Turns one `fz` run into the envelope the tool result carries.
///
/// The rule is `fz`'s own discipline read back: stdout, trailing
/// whitespace trimmed, is the answer if — and only if — its last
/// non-empty line parses as a JSON *object* (an array or a bare literal
/// is not an envelope). The envelope's text is then that line, byte for
/// byte — the wrapper re-serialises nothing the agent will read. That
/// text is not length-capped: whatever one line out of `fz` weighs, the
/// MCP reply weighs, so a child emitting a huge single line produces a
/// same-size reply. (The failure path is bounded — its stderr excerpt
/// stops at `EXCERPT_CAP` — precisely because the success path is
/// `fz`'s own bytes, not this crate's to trim.)
/// Anything else — a clap usage error with exit 2, a standalone-binary
/// refusal, a crash — lands on [`crate::codes::FZ_NO_JSON`], whose
/// message carries the exit status and a bounded excerpt of stderr
/// (stdout when stderr is empty), so the agent sees why without the
/// wrapper inventing a second output format.
#[must_use]
pub fn envelope_from_output(output: &FzOutput) -> Envelope {
    if let Some(line) = pick_stdout_line(&output.stdout)
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
        && value.is_object()
    {
        return Envelope {
            text: line.to_owned(),
            value,
        };
    }
    let (stream, name) = if output.stderr.trim().is_empty() {
        (output.stdout.as_str(), "stdout")
    } else {
        (output.stderr.as_str(), "stderr")
    };
    failure_envelope(
        &crate::codes::FZ_NO_JSON,
        format!(
            "fz produced no JSON object on stdout ({}); {} excerpt: {}",
            status_phrase(output.status),
            name,
            excerpt(stream),
        ),
    )
}

/// The last non-empty line of `fz`'s stdout, trailing whitespace
/// trimmed: `fz --json` prints exactly one object, and trailing
/// newlines or a blank line after it must not blind the wrapper when
/// the object itself parses. Leading characters are kept byte for byte.
fn pick_stdout_line(stdout: &str) -> Option<&str> {
    stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(str::trim_end)
}

fn status_phrase(status: Option<i32>) -> String {
    match status {
        Some(code) => format!("exit code {code}"),
        None => "no exit code; terminated by a signal".to_owned(),
    }
}

/// Bounds a diagnostic excerpt at `EXCERPT_CAP` characters: a
/// traceback `fz` dumped should reach the agent, but a ten-thousand-line
/// one must not ride inside every failed tool call forever.
const EXCERPT_CAP: usize = 500;

fn excerpt(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= EXCERPT_CAP {
        return trimmed.to_owned();
    }
    let mut bounded: String = trimmed.chars().take(EXCERPT_CAP).collect();
    bounded.push('…');
    bounded
}
