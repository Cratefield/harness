//! `fz push` (issue #184): the operator half of the push transports — a
//! VAPID key pair, one test send, and a subscription check.
//!
//! Three commands, each answering a question that otherwise only gets
//! answered at send time, in production, silently:
//!
//! - [`vapid_keygen`] makes the P-256 key pair a venture generates once and
//!   keeps forever, and prints the public half in the exact encoding a
//!   browser wants.
//! - [`send`] builds the venture's adapters from its environment and sends
//!   one notification, printing the outcome and — when nothing was sent —
//!   why. This is the tool the `needs-human` live proofs (issue #186) are
//!   run with.
//! - [`inspect_subscription`] validates a Web Push subscription and prints
//!   the `aud` the adapter will sign, because a wrong `aud` is the
//!   commonest cause of a VAPID `401`.
//!
//! # This module reads no push environment variable
//!
//! It calls [`cratefield_push_wiring::build_push`] — the same function
//! `serve()` calls on both runtimes and `fz doctor` calls through
//! `inspect_push` — so `fz push send` and the deployment it is diagnosing
//! cannot disagree about which variables a transport reads. Where a name has
//! to appear in prose it comes from [`PushKey::name`], not from a string
//! literal, and `crates/cli-acceptance/tests/push_env_guard.rs` fails the
//! build if that rule is broken here.
//!
//! # Nothing printed here came out of the environment
//!
//! An adapter's error is free to quote what it was handed, and issue #218's
//! review found the case that costs: `VAPID_SUBJECT` and `VAPID_PRIVATE_KEY`
//! pasted the wrong way round put the private key into a log, because the
//! subject is validated first and its error quotes the value. So the wiring
//! report carries only variable names and fixed phrases, and this module
//! prints the report — never a value it read. The same rule covers what the
//! operator supplies: a device token, a subscription `endpoint` and its
//! `auth` secret are all credential material, so a send prints the
//! [`Recipient`]'s fingerprinting `Debug` and a subscription check prints
//! the endpoint's origin without its path.
//!
//! **The failure path is where that promise was broken.** A `FAILED` report
//! printed the [`PushError`] verbatim, and a transport failure carries the
//! HTTP client's own message — which for `reqwest` ends
//! ` for url (<the whole URL>)`, the APNs device path and the Web Push
//! bearer endpoint included. The fix is in two places, and the first is the
//! important one: `cratefield-runtime-native`'s HTTP port no longer
//! stringifies a `reqwest::Error` whole, so the leak is closed for
//! `tracing::error!` and every persisted error too, not just for this
//! command. [`SendReport`] then redacts its own recipient out of whatever
//! reaches it anyway — this process is the one place that knows exactly
//! which string is the capability, so it can be precise where a general
//! rule has to be blunt. `the_failure_path_never_prints_the_recipient`
//! holds the `Sent(Err)` arm the `plan()`-only test could not see.

use std::fmt;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cratefield_adapter_webpush::ece::{AUTH_SECRET_LEN, PUBLIC_KEY_LEN, SubscriptionKeys};
use cratefield_adapter_webpush::vapid::origin_of;
use cratefield_core::{
    Clock, Config, HttpClient, Notification, Platform, Priority, PushError, PushOutcome, Recipient,
};
use cratefield_push_auth::Es256Signer;
use cratefield_push_wiring::{
    PushKey, PushVar, TransportWiring, build_push, inspect_push, transport_key, transport_name,
    vars_for,
};
use serde::Deserialize;
use zeroize::Zeroizing;

/// How many draws a random P-256 scalar is given before the platform's
/// randomness is declared broken. See [`generate_key`].
const SCALAR_ATTEMPTS: usize = 8;

/// The transport a `fz push send` is aimed at. The CLI's spelling of
/// [`Platform`], which is core's and carries no `clap` derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Transport {
    /// Apple Push Notification service; the recipient is a device token.
    Apns,
    /// Firebase Cloud Messaging; the recipient is a registration token.
    Fcm,
    /// Web Push (RFC 8030) — a browser subscription or a UnifiedPush
    /// endpoint; the recipient is the subscription JSON.
    WebPush,
}

impl Transport {
    /// The core [`Platform`] this transport carries.
    pub fn platform(self) -> Platform {
        match self {
            Transport::Apns => Platform::Ios,
            Transport::Fcm => Platform::Android,
            Transport::WebPush => Platform::Web,
        }
    }
}

/// [`Priority`] as a command-line value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum PriorityArg {
    /// Deliver immediately (APNs `10`, FCM `HIGH`, Web Push `Urgency: high`).
    #[default]
    Immediate,
    /// Deliver when convenient, to conserve the device's power.
    Conserve,
}

impl PriorityArg {
    fn priority(self) -> Priority {
        match self {
            PriorityArg::Immediate => Priority::Immediate,
            PriorityArg::Conserve => Priority::Conserve,
        }
    }
}

// ---------------------------------------------------------------------------
// `fz push vapid keygen`

/// Where a generated VAPID private key is allowed to go.
///
/// One of the two has to be chosen, and [`vapid_keygen`] refuses when
/// neither is: the public key is derived from the private one, so a run that
/// keeps neither produces a key nobody can ever configure.
pub struct KeygenOptions<'a> {
    /// Write the private key here, readable by its owner only.
    pub file: Option<&'a Path>,
    /// Overwrite `file` if it already exists — a **rotation**, which
    /// invalidates every existing browser subscription.
    pub force: bool,
    /// Print the private key to stdout as well.
    pub print_private: bool,
}

/// A generated VAPID key pair.
///
/// [`render`](Self::render) never contains the private key: printing it is a
/// separate call ([`private_key_disclosure`](Self::private_key_disclosure)),
/// so the default path cannot leak it by getting a boolean the wrong way
/// round.
pub struct VapidKeygen {
    public_key: String,
    private_key: Zeroizing<String>,
    written_to: Option<PathBuf>,
    rotated: bool,
}

impl fmt::Debug for VapidKeygen {
    /// Never prints the private key — the same rule `VapidKeys`,
    /// `Es256Signer` and `Recipient` follow.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VapidKeygen")
            .field("public_key", &self.public_key)
            .field("private_key", &"[redacted]")
            .field("written_to", &self.written_to)
            .field("rotated", &self.rotated)
            .finish()
    }
}

impl VapidKeygen {
    /// The `applicationServerKey` a browser passes to
    /// `pushManager.subscribe()`: base64url, no padding, of the 65-byte
    /// uncompressed P-256 point.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Whether an existing key was overwritten — a rotation, whose cost is
    /// every existing subscription.
    pub fn rotated(&self) -> bool {
        self.rotated
    }

    /// The warning a rotation earns, or `None` when nothing was replaced.
    ///
    /// Separate from [`render`](Self::render) because it belongs on
    /// **stderr**: stdout is what the README's own recipe reads the public
    /// key off, and a diagnostic in that stream is a diagnostic in
    /// somebody's `applicationServerKey`.
    pub fn warning(&self) -> Option<String> {
        self.rotated.then(rotation_warning)
    }

    /// What `fz push vapid keygen` prints on stdout. **Never** the private
    /// key, and never the rotation warning — see [`warning`](Self::warning).
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("VAPID key pair generated.\n\n");
        let _ = writeln!(
            out,
            "  public key (base64url, the 65-byte uncompressed P-256 point a browser\n  \
             passes to pushManager.subscribe() as applicationServerKey):\n\n    {}\n",
            self.public_key
        );
        if let Some(path) = &self.written_to {
            let _ = writeln!(
                out,
                "  private key written to {} (owner-readable only)\n",
                path.display()
            );
        }
        let private = PushKey::VapidPrivateKey.name();
        let subject = PushKey::VapidSubject.name();
        let _ = write!(
            out,
            "Next steps:\n  \
             1. Configure the private key as {private} and a `mailto:` or `https:` contact\n     \
             URI as {subject} (docs/PUSH-ENV.md). On Workers:\n\n       \
             wrangler secret put {private}\n\n  \
             2. Run `fz doctor` — it reports whether this venture routes Web Push, and\n     \
             fails a production deploy that half-wires it.\n  \
             3. Do not write the public key down anywhere it is configured: it is derived\n     \
             from the private key on every boot, so the two cannot drift.\n"
        );
        out
    }

    /// The private key, for `--print-private` only. A separate call so that
    /// no default path can print it.
    ///
    /// Cleared on drop, like the field it copies from: a plain `String`
    /// here would put the key back in an uncleared heap buffer and undo
    /// the [`Zeroizing`] the field is deliberately stored in.
    pub fn private_key_disclosure(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "  private key (base64url, the 32-byte P-256 scalar) — this is a secret;\n  \
             it is on your screen and in this shell's scrollback:\n\n    {}\n",
            self.private_key.as_str()
        ))
    }
}

/// Generates a VAPID key pair and keeps the private half where
/// `options` says.
///
/// # Errors
///
/// When neither `file` nor `print_private` is given (the key would be
/// discarded), when `file` exists and `force` was not given (a rotation, and
/// the message says what it costs), when the file cannot be written, or when
/// the platform will not produce random bytes.
pub fn vapid_keygen(options: &KeygenOptions<'_>) -> Result<VapidKeygen, String> {
    if options.file.is_none() && !options.print_private {
        return Err(format!(
            "nothing would keep the private key. Pass --file <PATH> to write it \
             (owner-readable only), or --print-private to print it. The public key alone is \
             useless: it is derived from the private one, and a {} nobody has cannot be \
             configured.",
            PushKey::VapidPrivateKey.name()
        ));
    }
    let (signer, scalar) = generate_key()?;
    // The scalar is encoded straight into the cleared-on-drop wrapper: the
    // `String` the encoder returns is moved, never copied, so no second
    // buffer holding the key is left behind for the allocator.
    let private_key = Zeroizing::new(URL_SAFE_NO_PAD.encode(scalar.as_slice()));
    let public_key = URL_SAFE_NO_PAD.encode(signer.public_key_uncompressed());
    let rotated = match options.file {
        Some(path) => write_private_key(path, &private_key, options.force)?,
        None => false,
    };
    Ok(VapidKeygen {
        public_key,
        private_key,
        written_to: options.file.map(Path::to_path_buf),
        rotated,
    })
}

/// A uniformly random P-256 key, cleared on drop, with the signer already
/// built from it.
///
/// Drawn as 32 raw octets and offered to the signer, which rejects zero and
/// anything at or above the curve order; both are astronomically unlikely
/// (about 2^-32 for the order), so the retry is bookkeeping rather than a
/// hot path — but retrying is the only correct answer, since clamping or
/// reducing the value would bias the key. The same shape
/// `cratefield_adapter_webpush::ece` uses for its per-message key, and the
/// randomness comes through `getrandom`, whose backend this workspace
/// selects in the final crate.
fn generate_key() -> Result<(Es256Signer, Zeroizing<[u8; 32]>), String> {
    let mut scalar = Zeroizing::new([0u8; 32]);
    for _ in 0..SCALAR_ATTEMPTS {
        getrandom::fill(scalar.as_mut_slice())
            .map_err(|err| format!("could not draw random bytes for a VAPID key: {err}"))?;
        if let Ok(signer) = Es256Signer::from_scalar(&scalar) {
            return Ok((signer, scalar));
        }
    }
    Err(format!(
        "no valid P-256 scalar in {SCALAR_ATTEMPTS} draws — this platform's randomness is broken"
    ))
}

/// Writes the private key, refusing to overwrite without `force`. Returns
/// whether a key was actually replaced.
///
/// # The key is never truncated in place
///
/// A `--force` rotation replaces the only copy of a key whose loss, by this
/// command's own warning, costs every existing browser subscription — and
/// no server can recreate one. Opening the destination with
/// `create(true).truncate(true)` destroys it the moment `open` returns, so
/// a write that then fails (a full disk, an I/O error, a killed process)
/// leaves an **empty file** where the venture's key used to be, and the
/// operator's next `fz doctor` reports Web Push half-wired with nothing to
/// restore.
///
/// So the new key is written to a temporary file beside the destination,
/// `fsync`ed, and only then `rename`d over it. `rename` within a directory
/// is atomic: every reader sees the old key or the new one, never a
/// half-written one and never nothing. The temporary file is a sibling
/// because a rename is only atomic within one filesystem.
///
/// The cost is that this needs to create a file in the destination's
/// directory, so a rotation into a directory the process cannot write is
/// now refused rather than done in place. That is the trade an atomic
/// replacement always makes, and it fails loudly with the key intact.
fn write_private_key(path: &Path, key: &str, force: bool) -> Result<bool, String> {
    let existed = path.exists();
    if existed && !force {
        return Err(rotation_refusal(path));
    }
    let temp = temp_sibling(path);
    write_new_key_file(&temp, key).map_err(|err| {
        let _ = std::fs::remove_file(&temp);
        format!(
            "cannot write the private key beside {}: {err}. The existing key, if any, is \
             untouched.",
            path.display()
        )
    })?;

    if !existed {
        // Not `create(true)`: `create_new` is the same refusal as the check
        // above, taken atomically, so a file that appears between the two
        // is still not overwritten. It is claimed empty and replaced by the
        // rename below, so this destroys nothing either way.
        if let Err(err) = new_file_options().open(path) {
            let _ = std::fs::remove_file(&temp);
            return Err(if err.kind() == std::io::ErrorKind::AlreadyExists {
                rotation_refusal(path)
            } else {
                format!("cannot write the private key to {}: {err}", path.display())
            });
        }
    }
    std::fs::rename(&temp, path).map_err(|err| {
        let _ = std::fs::remove_file(&temp);
        format!(
            "cannot move the new private key into {}: {err}. The existing key, if any, is \
             untouched.",
            path.display()
        )
    })?;
    // The rename itself is only durable once the *directory* is synced —
    // best effort, because a filesystem that will not open a directory
    // (Windows) has still had the file's own contents synced above.
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(existed)
}

/// A path beside `path` for the new key to be written to first. Same
/// directory, because `rename` is only atomic within one filesystem, and
/// dot-prefixed so a half-written key does not look like a key.
fn temp_sibling(path: &Path) -> PathBuf {
    let name = path.file_name().map_or_else(
        || "vapid.key".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    path.with_file_name(format!(".{name}.{}.{unique}.tmp", std::process::id()))
}

/// How every file this command creates is opened: new, and owner-readable
/// only from the moment it exists — never widened afterwards, which would
/// leave a window in which the key is world-readable.
fn new_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
}

/// Writes `key` to a file that must not already exist, and `fsync`s it:
/// without the sync the rename can land while the contents are still in
/// the page cache, which is the same empty-file outcome by another route.
fn write_new_key_file(path: &Path, key: &str) -> std::io::Result<()> {
    let mut file = new_file_options().open(path)?;
    writeln!(file, "{key}")?;
    file.sync_all()
}

/// Why an existing key file is not overwritten.
fn rotation_refusal(path: &Path) -> String {
    format!(
        "{} already exists, and overwriting it would rotate this venture's VAPID key. {} Pass \
         --force if that is what you mean, or write the new key somewhere else.",
        path.display(),
        ROTATION_COST
    )
}

/// The banner a rotation prints, after the fact.
fn rotation_warning() -> String {
    format!("warning: the VAPID key was rotated. {ROTATION_COST}\n")
}

/// What rotating a VAPID key costs, said once so the refusal and the warning
/// cannot drift apart.
const ROTATION_COST: &str = "A subscription is bound to the application server key it was \
                             created with, so rotating invalidates every existing browser \
                             subscription — and no server can recreate one: each browser has to \
                             call pushManager.subscribe() again, which needs the user back on \
                             the site with notification permission still granted.";

// ---------------------------------------------------------------------------
// `fz push send`

/// The command line of `fz push send`, before anything is parsed.
pub struct SendArgs {
    /// Which transport to send over; also how `recipient` is read.
    pub transport: Transport,
    /// An APNs device token, an FCM registration token, or a Web Push
    /// subscription JSON.
    pub recipient: String,
    /// The notification's title.
    pub title: String,
    /// The notification's body.
    pub body: String,
    /// Custom JSON payload the app reads.
    pub data: Option<String>,
    /// Where a tap should take the user.
    pub url: Option<String>,
    /// How long the push service may hold the notification, in seconds.
    pub ttl: Option<u64>,
    /// Delivery priority.
    pub priority: PriorityArg,
    /// A data-only notification: nothing is shown, the app is woken.
    pub silent: bool,
}

/// One parsed send: a recipient and the notification for it.
pub struct SendRequest {
    recipient: Recipient,
    notification: Notification,
}

impl SendRequest {
    /// Parses the command line into a recipient and a notification, without
    /// touching the environment or the network.
    ///
    /// # Errors
    ///
    /// When the recipient does not parse for the named transport, or
    /// `--data` is not a JSON **object**.
    pub fn from_args(args: &SendArgs) -> Result<Self, String> {
        let recipient = parse_recipient(args.transport, &args.recipient)?;
        let data = match &args.data {
            Some(raw) => {
                let value: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|err| format!("--data is not JSON: {err}. Pass a JSON object."))?;
                // An object, not merely JSON. `--data '["a"]'` parses, and
                // then means three different things: APNs and FCM drop a
                // non-object payload silently (each merges its members into
                // a JSON object it is building), while Web Push forwards
                // the array to the service worker. One flag cannot mean
                // "delivered", "dropped" and "delivered differently"
                // depending on the transport — and the message already
                // promised an object.
                if !value.is_object() {
                    return Err(format!(
                        "--data is {}, not a JSON object. Pass an object — \
                         `--data '{{\"key\":\"value\"}}'` — because a payload that is not one is \
                         silently dropped by APNs and FCM and forwarded by Web Push, so the same \
                         flag would mean three things.",
                        json_kind(&value)
                    ));
                }
                value
            }
            None => serde_json::Value::Null,
        };
        let notification = Notification {
            data,
            url: args.url.clone(),
            ttl: args.ttl.map(Duration::from_secs),
            priority: args.priority.priority(),
            silent: args.silent,
            ..Notification::new(args.title.clone(), args.body.clone())
        };
        Ok(Self {
            recipient,
            notification,
        })
    }

    /// The transport this send is routed over — the recipient's, so the
    /// adapter that takes it and the verdict that is reported are about the
    /// same transport by construction.
    pub fn transport(&self) -> Platform {
        self.recipient.platform()
    }
}

/// Sends one notification through the adapters this venture's environment
/// configures.
///
/// The adapters come from [`build_push`] — the construction `serve()` uses,
/// not a second wiring — so a transport this reaches is a transport the
/// deployment reaches, and one it reports unrouted is one every production
/// send would answer `NotConfigured` for.
pub async fn send(
    config: &dyn Config,
    http: &Arc<dyn HttpClient>,
    clock: &Arc<dyn Clock>,
    request: &SendRequest,
) -> SendReport {
    let (push, wiring) = build_push(config, http, clock);
    let transport = request.transport();
    let verdict = wiring.get(transport).clone();
    if !verdict.is_routed() {
        return SendReport::new(request, verdict, SendOutcome::Unrouted);
    }
    let outcome = push.send(&request.recipient, &request.notification).await;
    SendReport::new(request, verdict, SendOutcome::Sent(outcome))
}

/// What [`send`] would do, without sending: the same wiring verdict for the
/// same transport, from [`inspect_push`], which has no HTTP client at all —
/// so a `--dry-run` cannot reach the network however it is wired.
pub fn plan(config: &dyn Config, request: &SendRequest) -> SendReport {
    let wiring = inspect_push(config);
    let verdict = wiring.get(request.transport()).clone();
    SendReport::new(request, verdict, SendOutcome::Planned)
}

/// [`send`], over the network, from a synchronous CLI.
///
/// The client is the native runtime's own — reqwest behind the outbound
/// policy, wrapped in the port's bounds — and not one of this crate's
/// invention: a live proof against a real push service that goes through a
/// client we wrote for the occasion proves the client, not the protocol
/// (the same reasoning `crates/adapter-webpush`'s ntfy leg gives).
///
/// That client is tokio's and reqwest's, which is why it is behind the
/// `push-send` feature: `fz` is built once and installed, and everything
/// else it does is free of both. Without the feature every other `fz push`
/// command still works, `--dry-run` included, and this one says what to
/// rebuild — a missing send is loud, unlike a doctor check that would
/// silently stop checking (issue #191's rule, and the reason the doctor's
/// push rules are *not* optional).
///
/// # Errors
///
/// Without the `push-send` feature, always. With it, when the async runtime
/// the client needs cannot be started.
#[cfg(feature = "push-send")]
pub fn send_now(config: &dyn Config, request: &SendRequest) -> Result<SendReport, String> {
    let (http, clock) = send_stack();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the async runtime this send needs: {err}"))?;
    Ok(runtime.block_on(send(config, &http, &clock, request)))
}

/// The client and clock [`send_now`] sends through: the native runtime's
/// own, wired the way `serve()` wires them.
///
/// The clock is [`cratefield_runtime_native::TokioClock`] and **not**
/// core's `SystemClock`, which matters more than a name: the deadline the
/// port advertises is enforced by [`BoundedHttpClient`] *through the
/// clock*, and `SystemClock::timeout_any` is the documented test-only
/// default that runs the future to completion. Passing it wraps the client
/// in a bound that cannot fire — the send would still be bounded, but only
/// by the timeout `ReqwestClient` happens to set on itself, which is not
/// what the wrapper is there for.
///
/// [`BoundedHttpClient`]: cratefield_core::BoundedHttpClient
#[cfg(feature = "push-send")]
fn send_stack() -> (Arc<dyn HttpClient>, Arc<dyn Clock>) {
    let clock: Arc<dyn Clock> = Arc::new(cratefield_runtime_native::TokioClock);
    let http: Arc<dyn HttpClient> = Arc::new(cratefield_core::BoundedHttpClient::new(
        Arc::new(cratefield_runtime_native::ReqwestClient::new()),
        Arc::clone(&clock),
    ));
    (http, clock)
}

/// The same, in an `fz` built without the `push-send` feature: there is no
/// HTTP client, so there is no send. See the other half's documentation.
///
/// # Errors
///
/// Always.
#[cfg(not(feature = "push-send"))]
pub fn send_now(_config: &dyn Config, _request: &SendRequest) -> Result<SendReport, String> {
    Err(
        // Deliberately `cargo install`, and never "add the feature to your
        // venture's dependency": `push-send` pulls
        // `cratefield-runtime-native`, which `compile_error!`s on wasm32,
        // and a generated venture depends on `cratefield-cli` beside a wasm
        // `cdylib` — so flipping the feature there breaks the Worker build
        // the venture actually deploys. The send-capable `fz` is a
        // separately installed binary.
        "this `fz` was built without the `push-send` feature, so it has no HTTP client and \
         cannot send. Install one that has it — `cargo install cratefield-cli --features \
         push-send` — and run that binary (it needs no compiled-in harness); do not add the \
         feature to the venture's own `cratefield-cli` dependency, which would pull the native \
         runtime into its wasm build. Or run `fz push send --dry-run`, which reports the \
         transport's wiring without sending."
            .to_owned(),
    )
}

/// How far a send got.
enum SendOutcome {
    /// `--dry-run`: nothing was sent, deliberately.
    Planned,
    /// The transport is not routed, so nothing was sent.
    Unrouted,
    /// An adapter took the send and the provider answered.
    Sent(Result<PushOutcome, PushError>),
}

/// The result of a `fz push send`, as the operator sees it.
pub struct SendReport {
    transport: Platform,
    /// The recipient's fingerprinting `Debug`, taken once. Never the
    /// recipient itself: a device token addresses a device, and a Web Push
    /// `endpoint` is a bearer capability.
    recipient: String,
    /// Exactly the strings that make up this send's recipient, longest
    /// first — see [`credential_parts`] and [`SendReport::redacted`].
    credentials: Vec<String>,
    wiring: TransportWiring,
    outcome: SendOutcome,
}

impl SendReport {
    fn new(request: &SendRequest, wiring: TransportWiring, outcome: SendOutcome) -> Self {
        Self {
            transport: request.transport(),
            recipient: format!("{:?}", request.recipient),
            credentials: credential_parts(&request.recipient),
            wiring,
            outcome,
        }
    }

    /// `text` with this send's own recipient taken out of it.
    ///
    /// The second line of defence behind the HTTP port's own redaction,
    /// and a deliberately different kind: the port has to guess what is
    /// credential material in an arbitrary URL, while this process
    /// *knows* — the operator handed it the token or the subscription on
    /// the command line. So the match here is exact, and it costs no
    /// diagnostic detail at all: everything that is not the recipient
    /// survives verbatim.
    fn redacted(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for part in &self.credentials {
            if out.contains(part.as_str()) {
                out = out.replace(part.as_str(), REDACTED);
            }
        }
        out
    }

    /// Whether the command succeeded: a delivery, or a `--dry-run` whose
    /// transport would actually have carried the send. Nothing sent is not a
    /// success — the operator asked for a notification.
    pub fn ok(&self) -> bool {
        match &self.outcome {
            SendOutcome::Planned => self.wiring.is_routed(),
            SendOutcome::Sent(Ok(PushOutcome::Delivered { .. })) => true,
            // `NotConfigured` included: the operator asked for a
            // notification and did not get one.
            SendOutcome::Unrouted | SendOutcome::Sent(_) => false,
        }
    }

    /// The whole report: what was attempted, over which transport, and what
    /// came back — with the reason spelled out whenever nothing was sent.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "transport: {} ({})",
            transport_key(self.transport),
            transport_name(self.transport)
        );
        let _ = writeln!(out, "recipient: {}", self.recipient);
        let _ = writeln!(out, "wiring:    {}", self.wiring.verdict());
        out.push('\n');
        out.push_str(&self.result());
        out
    }

    fn result(&self) -> String {
        match &self.outcome {
            SendOutcome::Planned if self.wiring.is_routed() => format!(
                "result: NOT SENT (--dry-run)\n  {} is configured and would have carried this \
                 notification. Drop --dry-run to send it.\n",
                transport_name(self.transport)
            ),
            SendOutcome::Sent(Ok(PushOutcome::Delivered { id })) => match id {
                Some(id) => format!("result: DELIVERED\n  the push service accepted it: {id}\n"),
                None => "result: DELIVERED\n  the push service accepted it (it named no id)\n"
                    .to_owned(),
            },
            // Redacted, not printed: an adapter's error carries whatever
            // the HTTP client said, and a client that names the URL it
            // failed on names the device path or the subscription. The
            // runtime's own client no longer does (see the module note),
            // and this is the belt to that pair of braces — a `PushError`
            // reaching here came from *somewhere*, and the report cannot
            // know which client built it.
            SendOutcome::Sent(Err(err)) => format!(
                "result: FAILED\n  {}\n  {}\n",
                self.redacted(&err.to_string()),
                advice(err)
            ),
            // Everything else is "nothing was sent", and the reason is the
            // transport's wiring verdict. `NotConfigured` belongs here too:
            // the router answers it for a transport it does not carry, and
            // an adapter for one built unconfigured — either way nothing
            // left this process and the verdict above says which.
            SendOutcome::Planned
            | SendOutcome::Unrouted
            | SendOutcome::Sent(Ok(PushOutcome::NotConfigured)) => {
                format!("result: NOT SENT\n  {}\n", self.unrouted_reason())
            }
        }
    }

    /// Why nothing was sent, from the transport's verdict — names and fixed
    /// phrases only, never a value out of the environment.
    fn unrouted_reason(&self) -> String {
        let name = transport_name(self.transport);
        match &self.wiring {
            TransportWiring::Absent => format!(
                "not one of {name}'s variables is set here ({}), so this venture does not wire \
                 {name} at all and nothing was sent. Set them (docs/PUSH-ENV.md), or send over a \
                 transport this venture configures.",
                variable_names(self.transport)
            ),
            TransportWiring::Partial { present, missing } => format!(
                "{name} is half-wired — {} set, {} not — so it is left unrouted and nothing was \
                 sent. `fz doctor` reports the same thing, and fails a production deploy on it.",
                present.join(", "),
                missing.join(", ")
            ),
            TransportWiring::Invalid { reason } => format!(
                "{name}'s credentials were refused: {reason}. It is left unrouted, so nothing was \
                 sent and every deployed send would answer NotConfigured too."
            ),
            // Unreachable through `send` and `plan`, which only report a
            // reason for a transport that is not routed — but a report is
            // not the place to panic about it.
            TransportWiring::Configured => format!(
                "{name} is configured, but no adapter took the send. This is a \
                 cratefield-push-wiring bug: please file it."
            ),
        }
    }
}

/// What a redacted credential is replaced by. The word the Web Push
/// adapter and the native HTTP port both use, so one grep finds all three.
const REDACTED: &str = "[redacted]";

/// Below this length a "credential" is too short to redact by substring:
/// replacing every occurrence of a two-character `auth` would scribble
/// over the message instead of protecting anything. Every real one is far
/// longer — a device token is 64 hex characters, a `p256dh` 87, an `auth`
/// 22 — so this only ever skips a value that was never going to be
/// accepted by the adapter anyway.
const MIN_REDACTABLE: usize = 12;

/// Every string that makes up `recipient`, longest first.
///
/// Longest first because the parts nest: a Web Push endpoint contains its
/// own path, and redacting the path first would leave the origin and a
/// `[redacted]` where the whole endpoint could have gone in one piece.
fn credential_parts(recipient: &Recipient) -> Vec<String> {
    let mut parts = match recipient {
        Recipient::Apns { device_token } => vec![device_token.clone()],
        Recipient::Fcm { registration_token } => vec![registration_token.clone()],
        Recipient::WebPush {
            endpoint,
            p256dh,
            auth,
        } => {
            let mut parts = vec![endpoint.clone(), p256dh.clone(), auth.clone()];
            // The request target on its own: an intermediary that echoes
            // what it was asked for quotes the path without the scheme
            // and host, and that path is the whole capability.
            if let Some(rest) = endpoint.split_once("://").map(|(_, rest)| rest)
                && let Some(index) = rest.find('/')
            {
                parts.push(rest[index..].to_owned());
            }
            parts
        }
    };
    parts.retain(|part| part.len() >= MIN_REDACTABLE);
    parts.sort_by_key(|part| std::cmp::Reverse(part.len()));
    parts
}

/// What the operator should do about a failed send. The error's own message
/// says what happened; this says what it means.
fn advice(err: &PushError) -> &'static str {
    match err {
        // The one error in the port that is an instruction, and the one it
        // is most expensive to act on wrongly for Web Push.
        PushError::Unregistered => {
            "this recipient is gone: delete it from the venture's registry. A Web Push \
             subscription cannot be recreated server-side — only the browser can, by \
             subscribing again."
        }
        PushError::Rejected(_) => {
            "the provider refused the request; it will refuse it again unchanged. Check the \
             recipient and this transport's credentials (`fz doctor`)."
        }
        PushError::Transient { .. } => {
            "retryable: the provider was unavailable or asked for a pause. Nothing about the \
             recipient or the credentials is proven wrong by this."
        }
    }
}

/// What a JSON value is, for the `--data` refusal. Never the value: a
/// payload is the operator's, and this module prints no value it was given.
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// The environment variables one transport **needs**, listed for the "set
/// them" hint.
///
/// Required only. The hint is an instruction, and `APNS_HOST` is optional
/// with a documented default (`sandbox`) whose only wrong value is a hard
/// failure — telling an operator to set it invites them to guess
/// `production` for a development build's token, which fails every send.
/// An optional variable is described in `docs/PUSH-ENV.md`, not prescribed
/// here.
fn variable_names(transport: Platform) -> String {
    vars_for(transport)
        .filter(|var| var.required)
        .map(PushVar::name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The recipient for one transport, from what the operator passed.
fn parse_recipient(transport: Transport, value: &str) -> Result<Recipient, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("--recipient is empty".to_owned());
    }
    match transport {
        Transport::WebPush => parse_subscription(value).map(Subscription::into_recipient),
        Transport::Apns | Transport::Fcm if value.starts_with('{') => Err(format!(
            "--recipient looks like a JSON subscription, but --transport is {}, which takes the \
             bare token the device registered with. A subscription JSON goes with --transport \
             web-push.",
            transport_key(transport.platform())
        )),
        Transport::Apns => Ok(Recipient::apns(value)),
        Transport::Fcm => Ok(Recipient::fcm(value)),
    }
}

// ---------------------------------------------------------------------------
// `fz push inspect-subscription`

/// A Web Push subscription as the browser hands it over.
struct Subscription {
    endpoint: String,
    p256dh: String,
    auth: String,
}

impl Subscription {
    fn into_recipient(self) -> Recipient {
        Recipient::web_push(self.endpoint, self.p256dh, self.auth)
    }
}

/// Both shapes a subscription arrives in: the browser's own
/// `{endpoint, keys: {p256dh, auth}}`, and the flattened form a venture that
/// stores the three parts separately tends to write.
#[derive(Deserialize)]
struct SubscriptionJson {
    endpoint: Option<String>,
    keys: Option<SubscriptionKeysJson>,
    p256dh: Option<String>,
    auth: Option<String>,
}

#[derive(Deserialize)]
struct SubscriptionKeysJson {
    p256dh: Option<String>,
    auth: Option<String>,
}

fn parse_subscription(json: &str) -> Result<Subscription, String> {
    let parsed: SubscriptionJson = serde_json::from_str(json)
        .map_err(|err| format!("the subscription is not JSON: {err}. {SUBSCRIPTION_SHAPE}"))?;
    let endpoint = parsed.endpoint.ok_or_else(|| missing_field("endpoint"))?;
    let (p256dh, auth) = match parsed.keys {
        Some(keys) => (
            keys.p256dh.ok_or_else(|| missing_field("keys.p256dh"))?,
            keys.auth.ok_or_else(|| missing_field("keys.auth"))?,
        ),
        None => (
            parsed.p256dh.ok_or_else(|| missing_field("p256dh"))?,
            parsed.auth.ok_or_else(|| missing_field("auth"))?,
        ),
    };
    Ok(Subscription {
        endpoint,
        p256dh,
        auth,
    })
}

fn missing_field(field: &str) -> String {
    format!("the subscription JSON has no `{field}`. {SUBSCRIPTION_SHAPE}")
}

const SUBSCRIPTION_SHAPE: &str = "Pass what the browser hands over — \
                                  JSON.stringify(await registration.pushManager.getSubscription()) \
                                  — which is {\"endpoint\":\"…\",\"keys\":{\"p256dh\":\"…\",\
                                  \"auth\":\"…\"}}. The flattened \
                                  {\"endpoint\":…,\"p256dh\":…,\"auth\":…} is accepted too.";

/// A subscription that passed every check the adapter makes.
///
/// It holds the push service's origin and nothing else: not the endpoint's
/// path, which is the subscription's bearer capability, and neither key.
#[derive(Debug)]
pub struct SubscriptionReport {
    /// The push service's origin: what the adapter signs as the VAPID `aud`.
    aud: String,
}

impl SubscriptionReport {
    /// The `aud` the Web Push adapter will sign for this subscription.
    pub fn aud(&self) -> &str {
        &self.aud
    }

    /// What `fz push inspect-subscription` prints.
    pub fn render(&self) -> String {
        format!(
            "subscription: valid\n\n  \
             aud: {aud}\n    \
             the audience the adapter signs into its VAPID token for this subscription:\n    \
             the push service's origin, and never the subscription's path. A path-bearing\n    \
             aud is the commonest cause of a VAPID 401; this one has none.\n  \
             endpoint: {aud}/…\n    \
             the path is withheld here: it is a bearer capability — whoever holds it\n    \
             can push to this browser until the subscription dies.\n  \
             p256dh: {PUBLIC_KEY_LEN} bytes, an uncompressed P-256 point on the curve\n  \
             auth: {AUTH_SECRET_LEN} bytes\n",
            aud = self.aud
        )
    }
}

/// Validates a Web Push subscription and works out the `aud` the adapter
/// will use for it.
///
/// Every check is the adapter's own — `origin_of` for the audience,
/// `SubscriptionKeys::parse` for the two keys — so a subscription this
/// accepts is one the adapter accepts, and a reason this gives is the reason
/// a send would have failed with.
///
/// # Errors
///
/// When the JSON is not a subscription, the endpoint has no usable origin,
/// or either key is the wrong length or encoding.
pub fn inspect_subscription(json: &str) -> Result<SubscriptionReport, String> {
    let subscription = parse_subscription(json)?;
    let aud = origin_of(&subscription.endpoint).map_err(|err| {
        format!(
            "{err} — a Web Push endpoint is the absolute http(s) URL the browser put in \
             `subscription.endpoint`, and its origin is what the VAPID token claims."
        )
    })?;
    SubscriptionKeys::parse(&subscription.p256dh, &subscription.auth)
        .map_err(|err| format!("{err} — this subscription cannot be encrypted to as it stands."))?;
    Ok(SubscriptionReport { aud })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;
    use cratefield_core::SystemClock;
    use cratefield_testing::vectors::{
        RFC8291_AUTH_SECRET as AUTH, RFC8291_UA_PUBLIC as P256DH, TEST_P256_PEM,
        TEST_VAPID_SUBJECT, WEB_PUSH_ENDPOINT as ENDPOINT, WEB_PUSH_ENDPOINT_CAPABILITY,
        web_push_subscription_json,
    };
    use cratefield_testing::{FakeHttpClient, TempDir};

    fn subscription_json() -> String {
        web_push_subscription_json()
    }

    fn send_args(transport: Transport, recipient: &str) -> SendArgs {
        SendArgs {
            transport,
            recipient: recipient.to_owned(),
            title: "title".to_owned(),
            body: "body".to_owned(),
            data: None,
            url: None,
            ttl: None,
            priority: PriorityArg::Immediate,
            silent: false,
        }
    }

    #[test]
    fn a_generated_key_is_a_usable_p256_key_and_the_public_half_is_65_bytes() {
        // `TempDir`, not a cleanup on the last line: an assertion that
        // fires below would otherwise leave a `0600` private key in
        // `/tmp` on exactly the runs somebody then has to go and read.
        let dir = TempDir::new("fz-push-keygen-usable");
        let path = dir.join("vapid.key");
        let generated = vapid_keygen(&KeygenOptions {
            file: Some(&path),
            force: false,
            print_private: false,
        })
        .expect("generates");

        let public = URL_SAFE_NO_PAD
            .decode(generated.public_key())
            .expect("base64url");
        assert_eq!(public.len(), PUBLIC_KEY_LEN, "uncompressed P-256 point");
        assert_eq!(public[0], 0x04, "uncompressed point form");

        // Two runs are two keys: a keygen that returned a constant would
        // pass every other assertion here.
        let second = vapid_keygen(&KeygenOptions {
            file: Some(&dir.join("second.key")),
            force: false,
            print_private: false,
        })
        .expect("generates");
        assert_ne!(generated.public_key(), second.public_key());
    }

    #[test]
    fn the_private_key_is_never_in_the_report_unless_it_is_asked_for() {
        let generated = vapid_keygen(&KeygenOptions {
            file: None,
            force: false,
            print_private: true,
        })
        .expect("generates");
        let private = generated.private_key.as_str().to_owned();

        assert!(
            !generated.render().contains(&private),
            "the report must not carry the private key"
        );
        assert!(
            !format!("{generated:?}").contains(&private),
            "nor must Debug"
        );
        // The type is the assertion: a disclosure that came back as a
        // plain `String` would drop uncleared and undo the `Zeroizing`
        // the field is stored in. This line stops compiling if it does.
        let disclosure: Zeroizing<String> = generated.private_key_disclosure();
        assert!(
            disclosure.contains(&private),
            "--print-private asks for it explicitly"
        );
    }

    #[test]
    fn a_keygen_that_would_discard_the_private_key_is_refused() {
        let error = vapid_keygen(&KeygenOptions {
            file: None,
            force: false,
            print_private: false,
        })
        .expect_err("nothing would keep the key");
        assert!(error.contains("--file"), "{error}");
        assert!(error.contains("--print-private"), "{error}");
        // The variable is named, and named through the table.
        assert!(error.contains(PushKey::VapidPrivateKey.name()), "{error}");
    }

    #[test]
    fn an_existing_key_is_not_overwritten_without_force_and_the_warning_says_why() {
        let dir = TempDir::new("fz-push-keygen-force");
        let path = dir.join("vapid.key");
        let first = vapid_keygen(&KeygenOptions {
            file: Some(&path),
            force: false,
            print_private: false,
        })
        .expect("generates");
        let kept = std::fs::read_to_string(&path).expect("written");

        let error = vapid_keygen(&KeygenOptions {
            file: Some(&path),
            force: false,
            print_private: false,
        })
        .expect_err("refuses to rotate");
        assert!(error.contains("--force"), "{error}");
        assert!(
            error.contains("invalidates every existing browser subscription"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("still there"),
            kept,
            "the refused run left the key alone"
        );

        let rotated = vapid_keygen(&KeygenOptions {
            file: Some(&path),
            force: true,
            print_private: false,
        })
        .expect("rotates with --force");
        assert!(rotated.rotated());
        // The warning is a diagnostic and belongs on stderr, so it is not
        // in what stdout gets: the README's own recipe reads the public
        // key off that stream.
        let warning = rotated.warning().expect("a rotation warns");
        assert!(warning.contains("rotated"), "{warning}");
        assert!(
            warning.contains("invalidates every existing browser subscription"),
            "{warning}"
        );
        assert!(
            !rotated.render().contains("warning"),
            "the warning is stderr's, not stdout's: {}",
            rotated.render()
        );
        assert_ne!(rotated.public_key(), first.public_key());
        assert_ne!(std::fs::read_to_string(&path).expect("rewritten"), kept);
    }

    /// The cost of getting this wrong is stated by the command itself: a
    /// rotation invalidates every existing browser subscription, and none
    /// of them can be recreated server-side. A `--force` that truncated
    /// the destination first would leave an **empty file** whenever the
    /// write that follows fails — which is that same loss, unasked for.
    ///
    /// Staged with a directory the process cannot create a file in: the
    /// write cannot complete, and the question is what is left behind.
    #[test]
    #[cfg(unix)]
    fn a_force_rotation_that_cannot_complete_leaves_the_old_key_intact() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new("fz-push-keygen-torn");
        let path = dir.join("vapid.key");
        vapid_keygen(&KeygenOptions {
            file: Some(&path),
            force: false,
            print_private: false,
        })
        .expect("the venture's key");
        let kept = std::fs::read_to_string(&path).expect("written");

        // Read and execute, no write: the existing key file is still
        // writable through its own mode, so this is precisely the shape
        // where truncate-in-place succeeds at destroying it and an
        // atomic replacement refuses.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("makes the directory read-only");
        // Root ignores the mode, and then the scenario cannot be staged
        // at all — skip rather than assert something else.
        let staged = std::fs::write(dir.join("probe"), "x").is_err();
        let outcome = if staged {
            Some(vapid_keygen(&KeygenOptions {
                file: Some(&path),
                force: true,
                print_private: false,
            }))
        } else {
            None
        };
        // Restored before any assertion, so a failure here does not also
        // defeat the directory's own removal on drop.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restores the directory");

        let Some(outcome) = outcome else {
            eprintln!("skipped: this process writes into a read-only directory (root?)");
            return;
        };
        let Err(error) = outcome else {
            panic!("the rotation could not be completed, so it must have refused");
        };
        assert!(
            error.contains("untouched"),
            "the refusal says the key survived: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("the old key is still there"),
            kept,
            "a rotation that could not be completed destroyed the venture's only key"
        );
    }

    #[test]
    fn a_subscription_is_read_in_both_shapes_and_its_aud_is_the_origin() {
        let nested = inspect_subscription(&subscription_json()).expect("valid");
        let flat = inspect_subscription(&format!(
            "{{\"endpoint\":\"{ENDPOINT}\",\"p256dh\":\"{P256DH}\",\"auth\":\"{AUTH}\"}}"
        ))
        .expect("valid");
        assert_eq!(nested.aud(), flat.aud());
        assert_eq!(nested.aud(), "https://updates.push.services.mozilla.com");
        // The path is the subscription's bearer capability: an `aud` that
        // carries it earns a 401 from the services that check it strictly.
        assert!(
            !nested.render().contains(WEB_PUSH_ENDPOINT_CAPABILITY),
            "{}",
            nested.render()
        );
    }

    #[test]
    fn a_subscription_with_a_wrong_length_key_is_refused_by_name() {
        // One byte short of a P-256 point, and an auth secret that is not 16
        // bytes: the two mistakes a hand-assembled subscription makes.
        let short_p256dh = &P256DH[..P256DH.len() - 2];
        let error = inspect_subscription(&format!(
            "{{\"endpoint\":\"{ENDPOINT}\",\"keys\":{{\"p256dh\":\"{short_p256dh}\",\"auth\":\"{AUTH}\"}}}}"
        ))
        .expect_err("wrong length");
        assert!(error.contains("p256dh"), "{error}");

        let error = inspect_subscription(&format!(
            "{{\"endpoint\":\"{ENDPOINT}\",\"keys\":{{\"p256dh\":\"{P256DH}\",\"auth\":\"c2hvcnQ\"}}}}"
        ))
        .expect_err("wrong length");
        assert!(error.contains("auth"), "{error}");
    }

    #[test]
    fn an_endpoint_that_is_not_an_absolute_http_url_is_refused() {
        for endpoint in ["/relative/path", "ftp://push.example/x"] {
            let error = inspect_subscription(&format!(
                "{{\"endpoint\":\"{endpoint}\",\"keys\":{{\"p256dh\":\"{P256DH}\",\"auth\":\"{AUTH}\"}}}}"
            ))
            .expect_err("no origin");
            assert!(error.contains("endpoint"), "{endpoint}: {error}");
        }
    }

    #[test]
    fn a_bare_token_and_a_subscription_are_not_interchangeable() {
        let Err(error) = SendRequest::from_args(&send_args(Transport::Apns, &subscription_json()))
        else {
            panic!("a subscription is not a device token");
        };
        assert!(error.contains("web-push"), "{error}");

        let request = SendRequest::from_args(&send_args(Transport::Apns, "  DEVICE-TOKEN  "))
            .expect("a device token");
        assert_eq!(request.transport(), Platform::Ios);

        let request = SendRequest::from_args(&send_args(Transport::WebPush, &subscription_json()))
            .expect("a subscription");
        assert_eq!(request.transport(), Platform::Web);
    }

    #[test]
    fn an_unrouted_transport_reports_why_nothing_was_sent() {
        // Nothing configured at all: absent is a choice, and the report says
        // which variables would have wired it.
        let request = SendRequest::from_args(&send_args(Transport::WebPush, &subscription_json()))
            .expect("parses");
        let report = plan(
            &MapConfig::from_pairs(Vec::<(String, String)>::new()),
            &request,
        );
        assert!(!report.ok());
        let rendered = report.render();
        assert!(rendered.contains("NOT SENT"), "{rendered}");
        assert!(
            rendered.contains(PushKey::VapidPrivateKey.name()),
            "{rendered}"
        );
        assert!(
            rendered.contains(PushKey::VapidSubject.name()),
            "{rendered}"
        );

        // Half-wired: the report names what is set and what is not.
        let half = MapConfig::from_pairs([(
            PushKey::VapidSubject.name().to_owned(),
            "mailto:ops@example.test".to_owned(),
        )]);
        let rendered = plan(&half, &request).render();
        assert!(rendered.contains("half-wired"), "{rendered}");
        assert!(
            rendered.contains(PushKey::VapidPrivateKey.name()),
            "{rendered}"
        );
    }

    #[test]
    fn a_dry_run_of_a_configured_transport_says_it_would_have_sent() {
        let request = SendRequest::from_args(&send_args(Transport::WebPush, &subscription_json()))
            .expect("parses");
        let report = plan(&web_push_config(), &request);
        assert!(report.ok(), "{}", report.render());
        assert!(report.render().contains("--dry-run"), "{}", report.render());
    }

    #[test]
    fn a_configured_transport_sends_and_reports_the_outcome() {
        let request = SendRequest::from_args(&send_args(Transport::WebPush, &subscription_json()))
            .expect("parses");
        let http: Arc<dyn HttpClient> = Arc::new(FakeHttpClient::ok_json(""));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let report = pollster::block_on(send(&web_push_config(), &http, &clock, &request));
        assert!(report.ok(), "{}", report.render());
        assert!(report.render().contains("DELIVERED"), "{}", report.render());
    }

    #[test]
    fn the_report_never_prints_a_value_out_of_the_environment() {
        // The trap issue #218's review found: an adapter error quotes what
        // it was handed, and a swapped subject/private key then puts the key
        // in the output. Every variable in the table gets a distinctive
        // value here — including the swap itself — and none of them may
        // appear in what the operator sees.
        let sentinel = |var: &PushVar| format!("SENTINEL-{}-VALUE", var.name());
        let config = MapConfig::from_pairs(
            cratefield_push_wiring::PUSH_ENV
                .iter()
                .map(|var| (var.name().to_owned(), sentinel(var))),
        );
        let request = SendRequest::from_args(&send_args(Transport::WebPush, &subscription_json()))
            .expect("parses");
        let rendered = plan(&config, &request).render();
        for var in cratefield_push_wiring::PUSH_ENV {
            assert!(
                !rendered.contains(&sentinel(var)),
                "{} leaked into the report:\n{rendered}",
                var.name()
            );
        }
        // And the credentials the operator supplied are not echoed either.
        assert!(
            !rendered.contains(AUTH),
            "the auth secret leaked:\n{rendered}"
        );
        assert!(
            !rendered.contains(WEB_PUSH_ENDPOINT_CAPABILITY),
            "the endpoint leaked:\n{rendered}"
        );
    }

    /// The arm the test above never reaches, and the one that leaked.
    ///
    /// `plan()` cannot fail a send, so a report of a *failed* send was
    /// never exercised — while the failure is exactly where a transport's
    /// error message arrives, and reqwest's message ends
    /// ` for url (<the whole URL>)`. For Web Push that URL is the
    /// subscription: a bearer capability anyone who reads the output can
    /// push with, printed two lines under the fingerprint that was
    /// supposed to withhold it.
    ///
    /// The client here says what the native runtime's used to say, so
    /// this holds the CLI to its own promise even if a caller ever hands
    /// it a client that has not been fixed.
    #[test]
    fn the_failure_path_never_prints_the_recipient() {
        // APNs addresses a device by *path*, so the whole token is in the
        // URL a client reports.
        const DEVICE_TOKEN: &str =
            "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff";

        let leaky = |target: &str| {
            let http: Arc<dyn HttpClient> = Arc::new(FakeHttpClient::scripted(vec![Err(
                cratefield_core::HttpError::Transport(format!(
                    "error sending request for url ({target})"
                )),
            )]));
            http
        };
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

        let request = SendRequest::from_args(&send_args(Transport::WebPush, &subscription_json()))
            .expect("parses");
        let report =
            pollster::block_on(send(&web_push_config(), &leaky(ENDPOINT), &clock, &request));
        let rendered = report.render();
        assert!(!report.ok(), "{rendered}");
        assert!(rendered.contains("FAILED"), "{rendered}");
        assert!(
            !rendered.contains(WEB_PUSH_ENDPOINT_CAPABILITY),
            "the subscription's bearer capability leaked through the failure:\n{rendered}"
        );
        assert!(
            !rendered.contains(ENDPOINT),
            "the endpoint leaked through the failure:\n{rendered}"
        );
        // Still diagnosable: what failed, and what to do about it.
        assert!(rendered.contains("retryable"), "{rendered}");

        let request = SendRequest::from_args(&send_args(Transport::Apns, DEVICE_TOKEN))
            .expect("a device token");
        let report = pollster::block_on(send(
            &apns_config(),
            &leaky(&format!(
                "https://api.push.apple.com/3/device/{DEVICE_TOKEN}"
            )),
            &clock,
            &request,
        ));
        let rendered = report.render();
        assert!(rendered.contains("FAILED"), "{rendered}");
        assert!(
            !rendered.contains(DEVICE_TOKEN),
            "the device token leaked through the failure:\n{rendered}"
        );
    }

    #[test]
    fn data_has_to_be_a_json_object() {
        // Each of these parses as JSON and then means three different
        // things: APNs and FCM merge only an object's members and drop
        // the rest, Web Push forwards whatever it is.
        for raw in ["[1,2]", "\"a string\"", "42", "null", "true"] {
            let mut args = send_args(Transport::WebPush, &subscription_json());
            args.data = Some(raw.to_owned());
            let Err(error) = SendRequest::from_args(&args) else {
                panic!("{raw} is not a JSON object");
            };
            assert!(error.contains("JSON object"), "{raw}: {error}");
        }

        let mut args = send_args(Transport::WebPush, &subscription_json());
        args.data = Some("{\"order\":\"A-17\"}".to_owned());
        SendRequest::from_args(&args).expect("an object is what the flag is for");

        // Not JSON at all keeps its own message.
        let mut args = send_args(Transport::WebPush, &subscription_json());
        args.data = Some("{oops".to_owned());
        let Err(error) = SendRequest::from_args(&args) else {
            panic!("`{{oops` is not JSON");
        };
        assert!(error.contains("not JSON"), "{error}");
    }

    #[test]
    fn the_set_them_hint_names_only_variables_that_have_to_be_set() {
        // APNs is the transport with an optional variable: `APNS_HOST`
        // has a documented default, and its only wrong value — a
        // development token sent to `production` — fails every send. An
        // instruction to "set them" must not include it.
        let request = SendRequest::from_args(&send_args(Transport::Apns, "  DEVICE-TOKEN  "))
            .expect("a device token");
        let rendered = plan(
            &MapConfig::from_pairs(Vec::<(String, String)>::new()),
            &request,
        )
        .render();
        assert!(rendered.contains("Set them"), "{rendered}");
        for var in vars_for(Platform::Ios) {
            assert_eq!(
                rendered.contains(var.name()),
                var.required,
                "{} is required={} but {} in the hint:\n{rendered}",
                var.name(),
                var.required,
                if var.required {
                    "missing from"
                } else {
                    "named in"
                }
            );
        }
    }

    /// The refusal is the only thing an `fz` without the feature says
    /// about sending, so it is the only place an operator is told how to
    /// get one that can — and telling them to add the feature to the
    /// venture's own dependency breaks the venture's wasm build, because
    /// `cratefield-runtime-native` `compile_error!`s on wasm32 and a
    /// generated venture depends on this crate beside a `cdylib`.
    #[test]
    #[cfg(not(feature = "push-send"))]
    fn the_refusal_points_at_an_installed_binary_not_at_a_venture_dependency() {
        let request = SendRequest::from_args(&send_args(Transport::WebPush, &subscription_json()))
            .expect("parses");
        let Err(error) = send_now(&web_push_config(), &request) else {
            panic!("no client, no send");
        };
        assert!(
            error.contains("cargo install cratefield-cli --features push-send"),
            "{error}"
        );
        assert!(
            !error.contains("cratefield-cli = {"),
            "the refusal must not hand out a dependency recipe: {error}"
        );
        assert!(error.contains("--dry-run"), "{error}");
    }

    /// The bound the port advertises has to be one that can fire. The
    /// clock is how `BoundedHttpClient` enforces it, and core's
    /// `SystemClock` has the documented test-only `timeout_any` that runs
    /// the future to completion — so wiring that clock advertises a
    /// deadline and enforces none.
    #[test]
    #[cfg(feature = "push-send")]
    fn the_send_stack_is_built_on_a_clock_that_can_actually_time_out() {
        let (_http, clock) = send_stack();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let outcome = runtime.block_on(async move {
            cratefield_core::timeout(
                &*clock,
                async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    "the upstream answered eventually"
                },
                Duration::from_millis(10),
            )
            .await
        });
        assert!(
            outcome.is_none(),
            "the deadline did not fire: this clock runs the future to completion, so every \
             bound `BoundedHttpClient` puts on a send is decoration"
        );
    }

    /// A validly configured Web Push environment, named through the table.
    fn web_push_config() -> MapConfig {
        MapConfig::from_pairs([
            (
                PushKey::VapidPrivateKey.name().to_owned(),
                TEST_P256_PEM.to_owned(),
            ),
            (
                PushKey::VapidSubject.name().to_owned(),
                TEST_VAPID_SUBJECT.to_owned(),
            ),
        ])
    }

    /// The same for APNs: the throwaway key, and values of the shape each
    /// remaining variable is checked for.
    fn apns_config() -> MapConfig {
        MapConfig::from_pairs([
            (
                PushKey::ApnsKeyP8.name().to_owned(),
                TEST_P256_PEM.to_owned(),
            ),
            (
                PushKey::ApnsKeyId.name().to_owned(),
                "ABCDE12345".to_owned(),
            ),
            (
                PushKey::ApnsTeamId.name().to_owned(),
                "TEAM123456".to_owned(),
            ),
            (
                PushKey::ApnsTopic.name().to_owned(),
                "ventures.factory0.example".to_owned(),
            ),
        ])
    }
}
