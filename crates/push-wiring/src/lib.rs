//! `cratefield-push-wiring` (issue #191): the one place that turns a
//! venture's environment into the [`Push`] port.
//!
//! Three adapters serve three transports — `cratefield-adapter-apns`,
//! `cratefield-adapter-fcm` and `cratefield-adapter-webpush` — and each is
//! built from a handful of environment variables. Read those names in
//! `serve()`, again in `fz push send` and a third time in `fz doctor` and
//! they drift; the drift shows up in production as a notification that
//! silently never sends. So the names live in exactly one table
//! ([`PUSH_ENV`]), one function assembles the adapters from it
//! ([`build_push`]), and everything else calls that function.
//!
//! # The partial case is the point
//!
//! A venture that meant to enable FCM and mistyped one variable must not
//! boot into a state where every Android send answers
//! [`PushOutcome::NotConfigured`](cratefield_core::PushOutcome) and nothing
//! says why. [`build_push`] therefore returns a [`PushWiring`] report
//! alongside the router, and the report distinguishes:
//!
//! - **Configured** — every variable the transport needs is set and the
//!   adapter accepted them.
//! - **Absent** — not one of its variables is set. The venture did not wire
//!   that transport, which is a choice, not a defect.
//! - **Partial** — some but not all. Somebody meant to wire it.
//! - **Invalid** — all of them are set and the adapter refused them (a `.p8`
//!   that is not a PKCS#8 key, an `APNS_HOST` that is neither host).
//!
//! Partial and Invalid are an **error in production** and a **warning
//! everywhere else** ([`PushWiring::severity`]): a developer wiring APNs one
//! variable at a time must still be able to boot.
//!
//! # Nothing that came out of the environment goes into the report
//!
//! The report is logged whole at cold start, so a single value copied into
//! it reaches Workers Logs. An adapter's error is free to quote what it was
//! handed — `VapidError::Subject` does — and `Vapid::new` validates the
//! subject *before* the key, so `VAPID_SUBJECT` and `VAPID_PRIVATE_KEY`
//! pasted the wrong way round (the mistake `VapidKeys`' own doc warns about)
//! would have put the private key in the log. So an adapter's error string
//! is never copied into [`TransportWiring::Invalid`]: every `reason` is a
//! fixed phrase naming the variable and what was expected, and
//! `the_report_never_prints_any_variables_value` holds every variable in the
//! table to it.
//!
//! # Degraded, never broken
//!
//! A transport that is not configured is simply not routed: the
//! [`RoutingPush`] answers `NotConfigured` for its recipients, which is the
//! same contract each adapter's `not_configured()` constructor gives. With
//! nothing configured at all the router is empty, every send is
//! `NotConfigured`, and the Worker still boots.
//!
//! # Call sites
//!
//! - `serve()` on both runtimes, through `Cloudflare::push_from_env()` /
//!   `Native::push_from_env()`, which build the router once per isolate or
//!   process and log the report once at cold start.
//! - `fz doctor`, through [`inspect_push`] — the same function with an
//!   offline HTTP client, because the doctor never sends.
//! - `fz push send` and `fz push doctor`, when the CLI lands (issue #184):
//!   they call [`build_push`] and must not read any of these names
//!   themselves. `crates/cli-acceptance/tests/push_env_guard.rs` fails the
//!   build if they do.
//!
//! # The table is the documentation
//!
//! `docs/PUSH-ENV.md` is generated from [`PUSH_ENV`] by
//! `cargo run -p cratefield-push-wiring --example push-env-doc`, and CI
//! fails on drift — so the doc cannot describe variables the reader does not
//! read.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use cratefield_adapter_apns::{Apns, ApnsConfigError, ApnsCredentials, ApnsHost};
use cratefield_adapter_fcm::{Fcm, FcmConfigError};
use cratefield_adapter_webpush::vapid::{VapidError, VapidKeys};
use cratefield_adapter_webpush::{WebPush, WebPushConfigError};
use cratefield_core::{
    Clock, Config, HttpClient, HttpError, Platform, Push, RoutingPush, SystemClock, VentureEnv,
};

/// One push environment variable, as a **type**.
///
/// The table entry carries one of these and so does every lookup, so no
/// variable is ever named a second time as a bare string literal: the name
/// is spelled once, in [`PushKey::name`], and a lookup for a key the table
/// does not carry does not compile.
///
/// That is the difference between a rename being a compile error and being a
/// production incident. With a name-keyed lookup and an `unwrap_or_default`,
/// renaming a table entry left the transport still reporting `Complete`
/// while the credential handed to the adapter was `""` — which for
/// `APNS_HOST` is a silent sandbox default in production and
/// `BadDeviceToken` on every send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PushKey {
    /// The `.p8` provider key, whole.
    ApnsKeyP8,
    /// The `.p8` key's 10-character id.
    ApnsKeyId,
    /// The Apple team id.
    ApnsTeamId,
    /// The app's bundle id.
    ApnsTopic,
    /// `production` or `sandbox`.
    ApnsHost,
    /// The Google service-account JSON, whole.
    FcmServiceAccountJson,
    /// The VAPID private key.
    VapidPrivateKey,
    /// The VAPID contact URI.
    VapidSubject,
}

impl PushKey {
    /// The `SCREAMING_SNAKE` name, read through [`Config`] so a Workers
    /// secret and a native environment variable are the same thing.
    ///
    /// The one place in the workspace a push variable is spelled out: this
    /// match is exhaustive, so a new key without a name does not compile.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            PushKey::ApnsKeyP8 => "APNS_KEY_P8",
            PushKey::ApnsKeyId => "APNS_KEY_ID",
            PushKey::ApnsTeamId => "APNS_TEAM_ID",
            PushKey::ApnsTopic => "APNS_TOPIC",
            PushKey::ApnsHost => "APNS_HOST",
            PushKey::FcmServiceAccountJson => "FCM_SERVICE_ACCOUNT_JSON",
            PushKey::VapidPrivateKey => "VAPID_PRIVATE_KEY",
            PushKey::VapidSubject => "VAPID_SUBJECT",
        }
    }
}

/// One environment variable a push transport reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushVar {
    /// Which variable this is. Its [`name`](PushKey::name) is what is read
    /// from the environment; nothing looks a variable up by that string.
    pub key: PushKey,
    /// The transport it belongs to.
    pub transport: Platform,
    /// Whether the transport cannot be built without it.
    pub required: bool,
    /// Whether the value is credential material. A `true` here means the
    /// value must never reach a log — only this name and a verdict.
    pub secret: bool,
    /// What it is, for `docs/PUSH-ENV.md`.
    pub purpose: &'static str,
}

impl PushVar {
    /// The variable's name in the environment.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.key.name()
    }
}

/// Every environment variable the push adapters read, in one table.
///
/// This is the single source of truth the acceptance test in
/// `cli-acceptance` enforces: no other Rust source may name one of these
/// keys in a string literal.
pub const PUSH_ENV: &[PushVar] = &[
    PushVar {
        key: PushKey::ApnsKeyP8,
        transport: Platform::Ios,
        required: true,
        secret: true,
        purpose: "The `.p8` provider key from the Apple developer portal, PKCS#8 PEM, whole.",
    },
    PushVar {
        key: PushKey::ApnsKeyId,
        transport: Platform::Ios,
        required: true,
        secret: false,
        purpose: "The key's 10-character id (the `.p8` filename suffix).",
    },
    PushVar {
        key: PushKey::ApnsTeamId,
        transport: Platform::Ios,
        required: true,
        secret: false,
        purpose: "The 10-character Apple team id; the provider JWT's issuer.",
    },
    PushVar {
        key: PushKey::ApnsTopic,
        transport: Platform::Ios,
        required: true,
        secret: false,
        purpose: "The app's bundle id, sent as `apns-topic`.",
    },
    PushVar {
        key: PushKey::ApnsHost,
        transport: Platform::Ios,
        required: false,
        secret: false,
        purpose: "`production` or `sandbox`. Optional; defaults to `sandbox`, because a \
                  development build's token is a sandbox token and sending it to production \
                  fails every time.",
    },
    PushVar {
        key: PushKey::FcmServiceAccountJson,
        transport: Platform::Android,
        required: true,
        secret: true,
        purpose: "The Google service-account JSON Firebase hands over, whole. `client_email`, \
                  `private_key`, `project_id` and `token_uri` are read out of it, so there is \
                  no second variable to keep in step.",
    },
    PushVar {
        key: PushKey::VapidPrivateKey,
        transport: Platform::Web,
        required: true,
        secret: true,
        purpose: "The VAPID private key: a PKCS#8 PEM, or the bare 32-byte P-256 scalar \
                  base64url. The public key is derived, never configured.",
    },
    PushVar {
        key: PushKey::VapidSubject,
        transport: Platform::Web,
        required: true,
        secret: false,
        purpose: "RFC 8292 §2.1 `sub`: a `mailto:` or `https:` contact URI a push service can \
                  reach the operator at.",
    },
];

/// The transports, in report order.
pub const TRANSPORTS: [Platform; 3] = [Platform::Ios, Platform::Android, Platform::Web];

/// The [`RoutingPush`] builder name for a transport — `apns`, `fcm`,
/// `web_push` — which is what a report line and a log say.
#[must_use]
pub fn transport_key(transport: Platform) -> &'static str {
    match transport {
        Platform::Ios => "apns",
        Platform::Android => "fcm",
        Platform::Web => "web_push",
    }
}

/// The transport's name in prose (`APNs`, `FCM`, `Web Push`).
#[must_use]
pub fn transport_name(transport: Platform) -> &'static str {
    match transport {
        Platform::Ios => "APNs",
        Platform::Android => "FCM",
        Platform::Web => "Web Push",
    }
}

/// The variables one transport reads.
pub fn vars_for(transport: Platform) -> impl Iterator<Item = &'static PushVar> {
    PUSH_ENV
        .iter()
        .filter(move |var| var.transport == transport)
}

/// How one transport was configured.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TransportWiring {
    /// Not one of the transport's variables is set: the venture did not
    /// wire it. Its recipients answer `NotConfigured`, which is the
    /// documented outcome, not a fault.
    #[default]
    Absent,
    /// Every required variable is set and the adapter accepted them.
    Configured,
    /// Some of the transport's variables are set and some are not. The
    /// transport is **not** routed — every send would answer
    /// `NotConfigured` — and somebody clearly meant it to work.
    Partial {
        /// The variables that are set, in table order.
        present: Vec<&'static str>,
        /// The required variables that are not, in table order.
        missing: Vec<&'static str>,
    },
    /// Every variable is set and the adapter refused them.
    Invalid {
        /// Why the adapter refused the credentials: a fixed phrase naming
        /// the variable and what was expected of it.
        ///
        /// Never the adapter's own error string, and so never a value out
        /// of the environment — the whole report is logged at cold start
        /// (see the crate documentation).
        reason: String,
    },
}

impl TransportWiring {
    /// `configured`, `absent`, `partial` or `invalid` — the word a log line
    /// and `docs/PUSH-ENV.md` use.
    #[must_use]
    pub fn verdict(&self) -> &'static str {
        match self {
            TransportWiring::Absent => "absent",
            TransportWiring::Configured => "configured",
            TransportWiring::Partial { .. } => "partial",
            TransportWiring::Invalid { .. } => "invalid",
        }
    }

    /// Whether this transport is routed. `false` for everything but
    /// [`Configured`](TransportWiring::Configured), so an `Invalid`
    /// transport degrades to `NotConfigured` rather than to a broken
    /// adapter that fails on every send.
    #[must_use]
    pub fn is_routed(&self) -> bool {
        matches!(self, TransportWiring::Configured)
    }

    /// Whether this is a misconfiguration rather than a decision.
    #[must_use]
    pub fn is_problem(&self) -> bool {
        matches!(
            self,
            TransportWiring::Partial { .. } | TransportWiring::Invalid { .. }
        )
    }
}

/// How loudly a [`PushWiring`] report should be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WiringSeverity {
    /// Every transport is either configured or deliberately absent.
    Ok,
    /// Something is half-wired, but this is not production: log it and
    /// carry on, because wiring a transport one variable at a time is what
    /// development looks like.
    Warning,
    /// Something is half-wired in production, where it means a whole
    /// platform's notifications silently never send.
    Error,
}

/// Which push transports a venture's environment configured, which it did
/// not, and which it half did.
///
/// Never holds a value — only variable names and verdicts — so the whole
/// report is safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PushWiring {
    apns: TransportWiring,
    fcm: TransportWiring,
    web_push: TransportWiring,
}

impl PushWiring {
    /// The verdict for one transport.
    #[must_use]
    pub fn get(&self, transport: Platform) -> &TransportWiring {
        match transport {
            Platform::Ios => &self.apns,
            Platform::Android => &self.fcm,
            Platform::Web => &self.web_push,
        }
    }

    /// Every transport and its verdict, in report order.
    pub fn iter(&self) -> impl Iterator<Item = (Platform, &TransportWiring)> {
        TRANSPORTS
            .into_iter()
            .map(move |transport| (transport, self.get(transport)))
    }

    /// The one line logged at cold start: every transport, its verdict, and
    /// — where it is half-wired — which variable names are set and which are
    /// not. Names and verdicts only; never a value.
    #[must_use]
    pub fn summary(&self) -> String {
        use fmt::Write as _;
        let mut out = String::from("push wiring:");
        for (transport, wiring) in self.iter() {
            let _ = write!(out, " {}={}", transport_key(transport), wiring.verdict());
            match wiring {
                TransportWiring::Partial { present, missing } => {
                    let _ = write!(
                        out,
                        " (set: {}; unset: {})",
                        present.join(", "),
                        missing.join(", ")
                    );
                }
                TransportWiring::Invalid { reason } => {
                    let _ = write!(out, " ({reason})");
                }
                TransportWiring::Absent | TransportWiring::Configured => {}
            }
        }
        out
    }

    /// One message per misconfigured transport, each naming what is set,
    /// what is not, and what it costs.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for (transport, wiring) in self.iter() {
            let name = transport_name(transport);
            match wiring {
                TransportWiring::Partial { present, missing } => problems.push(format!(
                    "{name} is partially configured: {} {} set; {} {} not. \
                     {name} is left unrouted, so every {name} send reports NotConfigured and \
                     nothing is delivered. Set the missing variables, or unset the rest to \
                     say this transport is deliberately off.",
                    present.join(", "),
                    is_are(present.len()),
                    missing.join(", "),
                    is_are(missing.len()),
                )),
                TransportWiring::Invalid { reason } => problems.push(format!(
                    "{name} is configured but its credentials were refused: {reason}. \
                     {name} is left unrouted, so every {name} send reports NotConfigured."
                )),
                TransportWiring::Absent | TransportWiring::Configured => {}
            }
        }
        problems
    }

    /// Whether any transport is actually routed — the question `fz doctor`
    /// asks of a venture whose modules require the [`Push`] port: with
    /// nothing routed every send answers `NotConfigured`.
    #[must_use]
    pub fn any_routed(&self) -> bool {
        self.iter().any(|(_, wiring)| wiring.is_routed())
    }

    /// How loudly to report this. Partial and invalid configurations are an
    /// error in production and a warning everywhere else.
    // Asks each transport rather than building `problems()`: this runs on
    // every cold start, and formatting three paragraphs to find out whether
    // there are any is three allocations to answer a `bool`.
    #[must_use]
    pub fn severity(&self, env: VentureEnv) -> WiringSeverity {
        if !self.iter().any(|(_, wiring)| wiring.is_problem()) {
            WiringSeverity::Ok
        } else if env == VentureEnv::Production {
            WiringSeverity::Error
        } else {
            WiringSeverity::Warning
        }
    }

    /// The report as a `Result`, for `fz doctor` and anything else that
    /// fails a command rather than logging.
    ///
    /// # Errors
    ///
    /// Every problem, joined, when [`severity`](Self::severity) is
    /// [`WiringSeverity::Error`] — that is, when something is half-wired in
    /// production.
    pub fn check(&self, env: VentureEnv) -> Result<(), String> {
        match self.severity(env) {
            WiringSeverity::Error => Err(self.problems().join("\n")),
            WiringSeverity::Ok | WiringSeverity::Warning => Ok(()),
        }
    }
}

impl fmt::Display for PushWiring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

/// `is` for one variable name, `are` for a list of them. A message an
/// operator reads at 3am should not also make them parse the grammar.
fn is_are(count: usize) -> &'static str {
    if count == 1 { "is" } else { "are" }
}

/// What one transport's variables looked like in the environment.
enum Survey {
    Absent,
    Partial {
        present: Vec<&'static str>,
        missing: Vec<&'static str>,
    },
    Complete(Values),
}

/// The values one transport's variables held, keyed by [`PushKey`] and not
/// by name: the survey that read them and the builder that hands them to an
/// adapter cannot disagree about which variable a value came from.
struct Values(Vec<(PushKey, String)>);

impl Values {
    /// The value read for `key`, or `None` when the variable was unset —
    /// which is only ever the case for a variable the table marks optional.
    fn get(&self, key: PushKey) -> Option<&str> {
        self.0
            .iter()
            .find(|(found, _)| *found == key)
            .map(|(_, value)| value.as_str())
    }
}

/// A value the survey reported present.
///
/// [`Survey::Complete`] means every required variable of the transport was
/// read, so `None` cannot happen; it is still reported rather than defaulted
/// to `""`, because handing an adapter an empty credential is the silent
/// 403 this crate exists to prevent.
fn required(values: &Values, key: PushKey) -> Result<String, TransportWiring> {
    values.get(key).map(ToOwned::to_owned).ok_or_else(|| {
        invalid(format!(
            "{} was read from the environment and then lost (a cratefield-push-wiring bug)",
            key.name()
        ))
    })
}

/// A value that is set and not blank, **trimmed**.
///
/// A variable present but empty is treated as unset: an empty Workers secret
/// and an unset one mean the same thing to an operator, and treating `""` as
/// configured would hand the adapter a credential it must then refuse.
///
/// The trim is not only for that test. A newline or a leading space picked
/// up pasting a value into `wrangler secret put` is invisible, and an
/// untrimmed `APNS_KEY_ID` reports `configured`, goes into the provider
/// JWT's `kid`, and earns a 403 on every send — exactly the silent failure
/// this crate exists to prevent. What is handed on is what was tested.
fn value_of(config: &dyn Config, key: PushKey) -> Option<String> {
    config
        .get(key.name())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn survey(config: &dyn Config, transport: Platform) -> Survey {
    let mut present = Vec::new();
    let mut missing = Vec::new();
    let mut values = Vec::new();
    for var in vars_for(transport) {
        match value_of(config, var.key) {
            Some(value) => {
                present.push(var.name());
                values.push((var.key, value));
            }
            None if var.required => missing.push(var.name()),
            None => {}
        }
    }
    if present.is_empty() {
        Survey::Absent
    } else if missing.is_empty() {
        Survey::Complete(Values(values))
    } else {
        Survey::Partial { present, missing }
    }
}

/// Assembles the [`Push`] port from a venture's environment, and reports
/// what it found.
///
/// The returned `Arc<dyn Push>` is always usable: a [`RoutingPush`] holding
/// exactly the transports that are fully and validly configured. Everything
/// else — absent, partial, invalid — is left unrouted, so its recipients get
/// [`PushOutcome::NotConfigured`](cratefield_core::PushOutcome) and no send
/// ever panics or reaches the network.
///
/// The [`PushWiring`] is the report to log once at cold start
/// ([`PushWiring::summary`]) and to fail production on
/// ([`PushWiring::check`]).
///
/// `http` and `clock` are the runtime's ports; the adapters speak HTTP
/// through them and mint their provider tokens against them. Nothing here
/// touches the network — the adapters are constructed, not used.
#[must_use]
pub fn build_push(
    config: &dyn Config,
    http: &Arc<dyn HttpClient>,
    clock: &Arc<dyn Clock>,
) -> (Arc<dyn Push>, PushWiring) {
    let (apns_adapter, apns) = build_apns(config, http, clock);
    let (fcm_adapter, fcm) = build_fcm(config, http, clock);
    let (web_push_adapter, web_push) = build_web_push(config, http, clock);

    let mut router = RoutingPush::new();
    if let Some(adapter) = apns_adapter {
        router = router.apns(adapter);
    }
    if let Some(adapter) = fcm_adapter {
        router = router.fcm(adapter);
    }
    if let Some(adapter) = web_push_adapter {
        router = router.web_push(adapter);
    }

    (
        Arc::new(router),
        PushWiring {
            apns,
            fcm,
            web_push,
        },
    )
}

/// A transport that is not fully and validly configured contributes no
/// adapter: `RoutingPush` then answers `NotConfigured` for its recipients,
/// which is what an unrouted transport must do.
type Built = (Option<Arc<dyn Push>>, TransportWiring);

/// An [`TransportWiring::Invalid`] verdict.
///
/// Every caller passes a fixed phrase. Nothing that came out of the
/// environment, and no adapter error string that might quote it, reaches a
/// `reason` — the report is logged whole at cold start.
fn invalid(reason: String) -> TransportWiring {
    TransportWiring::Invalid { reason }
}

/// Why the APNs adapter refused the credentials, said without repeating any
/// of them.
fn apns_refusal(err: &ApnsConfigError) -> TransportWiring {
    match err {
        ApnsConfigError::Key(_) => invalid(format!(
            "{} is not a PKCS#8 PEM P-256 private key — paste the `.p8` file whole, \
             `-----BEGIN PRIVATE KEY-----` line included",
            PushKey::ApnsKeyP8.name()
        )),
    }
}

/// The same for FCM. Each variant names the field of the service-account
/// JSON at fault; the JSON itself is a secret and none of it is repeated.
fn fcm_refusal(err: &FcmConfigError) -> TransportWiring {
    let name = PushKey::FcmServiceAccountJson.name();
    invalid(match err {
        FcmConfigError::ServiceAccount(_) => format!(
            "{name} is not the service-account JSON Firebase issues — it must parse as JSON \
             and carry `project_id`, `private_key`, `client_email` and `token_uri`"
        ),
        FcmConfigError::Key(_) => {
            format!("{name} carries a `private_key` that is not an RSA private key in PEM form")
        }
        FcmConfigError::ProjectId(_) => {
            format!("{name} carries a `project_id` that is not a bare Firebase project id")
        }
        FcmConfigError::TokenUri(_) => {
            format!("{name} carries a `token_uri` that is not an https URL")
        }
    })
}

/// The same for Web Push — and the one that matters most.
///
/// [`VapidError::Subject`]'s own `Display` quotes the subject it was given,
/// and [`Vapid::new`](cratefield_adapter_webpush::vapid::Vapid::new)
/// validates the subject *before* the key. A deployment that pasted
/// `VAPID_SUBJECT` and `VAPID_PRIVATE_KEY` the wrong way round would
/// therefore have put the private key into the report, and from there into
/// the logs.
fn web_push_refusal(err: &WebPushConfigError) -> TransportWiring {
    invalid(match err {
        WebPushConfigError::Vapid(VapidError::Key(_)) => format!(
            "{} is neither a PKCS#8 PEM nor a base64url-encoded 32-byte P-256 scalar",
            PushKey::VapidPrivateKey.name()
        ),
        WebPushConfigError::Vapid(VapidError::Subject(_)) => format!(
            "{} is not a `mailto:` or `https:` contact URI (RFC 8292 §2.1). If it holds a \
             key, it was swapped with {}",
            PushKey::VapidSubject.name(),
            PushKey::VapidPrivateKey.name()
        ),
        // Neither reaches `WebPush::new`: an endpoint belongs to a send and
        // the record size is the adapter's own default. Named, not echoed.
        WebPushConfigError::Vapid(VapidError::Endpoint(_)) | WebPushConfigError::Ece(_) => format!(
            "the Web Push adapter refused the configuration built from {} and {}",
            PushKey::VapidPrivateKey.name(),
            PushKey::VapidSubject.name()
        ),
    })
}

fn build_apns(config: &dyn Config, http: &Arc<dyn HttpClient>, clock: &Arc<dyn Clock>) -> Built {
    let values = match survey(config, Platform::Ios) {
        Survey::Absent => return (None, TransportWiring::Absent),
        Survey::Partial { present, missing } => {
            return (None, TransportWiring::Partial { present, missing });
        }
        Survey::Complete(values) => values,
    };

    // Unset is the sandbox, deliberately: a development build's device token
    // is a sandbox token, and the adapter's own README documents the same
    // default. A value that is set and unparseable is a typo, not a default.
    let host = match values.get(PushKey::ApnsHost) {
        None => ApnsHost::Sandbox,
        Some(raw) => match ApnsHost::parse(raw) {
            Some(host) => host,
            None => {
                // The value is not echoed even though the table marks this
                // variable non-secret: `secret: false` describes what the
                // variable is for, not what an operator actually pasted into
                // it, and a `.p8` body put in the wrong secret would land in
                // the logs.
                return (
                    None,
                    invalid(format!(
                        "{} is neither `production` nor `sandbox`",
                        PushKey::ApnsHost.name()
                    )),
                );
            }
        },
    };

    let creds = match apns_credentials(&values, host) {
        Ok(creds) => creds,
        Err(wiring) => return (None, wiring),
    };
    match Apns::new(Arc::clone(http), Arc::clone(clock), creds) {
        Ok(apns) => (Some(Arc::new(apns)), TransportWiring::Configured),
        Err(err) => (None, apns_refusal(&err)),
    }
}

fn apns_credentials(values: &Values, host: ApnsHost) -> Result<ApnsCredentials, TransportWiring> {
    Ok(ApnsCredentials {
        key_p8_pem: required(values, PushKey::ApnsKeyP8)?,
        key_id: required(values, PushKey::ApnsKeyId)?,
        team_id: required(values, PushKey::ApnsTeamId)?,
        topic: required(values, PushKey::ApnsTopic)?,
        host,
    })
}

fn build_fcm(config: &dyn Config, http: &Arc<dyn HttpClient>, clock: &Arc<dyn Clock>) -> Built {
    let values = match survey(config, Platform::Android) {
        Survey::Absent => return (None, TransportWiring::Absent),
        Survey::Partial { present, missing } => {
            return (None, TransportWiring::Partial { present, missing });
        }
        Survey::Complete(values) => values,
    };

    let json = match required(&values, PushKey::FcmServiceAccountJson) {
        Ok(json) => json,
        Err(wiring) => return (None, wiring),
    };
    match Fcm::from_service_account_json(Arc::clone(http), Arc::clone(clock), &json) {
        Ok(fcm) => (Some(Arc::new(fcm)), TransportWiring::Configured),
        Err(err) => (None, fcm_refusal(&err)),
    }
}

fn build_web_push(
    config: &dyn Config,
    http: &Arc<dyn HttpClient>,
    clock: &Arc<dyn Clock>,
) -> Built {
    let values = match survey(config, Platform::Web) {
        Survey::Absent => return (None, TransportWiring::Absent),
        Survey::Partial { present, missing } => {
            return (None, TransportWiring::Partial { present, missing });
        }
        Survey::Complete(values) => values,
    };

    let keys = match vapid_keys(&values) {
        Ok(keys) => keys,
        Err(wiring) => return (None, wiring),
    };
    match WebPush::new(Arc::clone(http), Arc::clone(clock), keys) {
        Ok(web_push) => (Some(Arc::new(web_push)), TransportWiring::Configured),
        Err(err) => (None, web_push_refusal(&err)),
    }
}

fn vapid_keys(values: &Values) -> Result<VapidKeys, TransportWiring> {
    Ok(VapidKeys {
        private_key: required(values, PushKey::VapidPrivateKey)?,
        subject: required(values, PushKey::VapidSubject)?,
    })
}

/// The same verdicts as [`build_push`], for a caller that has no HTTP
/// client and needs none — `fz doctor`, which reports on an environment
/// rather than sending through it.
///
/// It really is [`build_push`]: the adapters are constructed against an
/// offline client that refuses every send, and then dropped with the
/// router. Constructing them is what surfaces
/// [`TransportWiring::Invalid`] — a `.p8` that is not a key is only
/// discovered by parsing it — so the doctor sees exactly what the runtime
/// will see, which is the whole point of there being one function.
#[must_use]
pub fn inspect_push(config: &dyn Config) -> PushWiring {
    let http: Arc<dyn HttpClient> = Arc::new(OfflineHttpClient);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let (_router, report) = build_push(config, &http, &clock);
    report
}

/// The `applicationServerKey` a browser must pass to
/// `pushManager.subscribe()`, base64url — or `None` when this venture has
/// not configured Web Push (issue #183).
///
/// It lives here for the same reason [`build_push`] does: the VAPID
/// variables have one reader. The **public** half is derived from the
/// private key rather than configured, so a venture that serves this
/// cannot serve a key that has drifted from the one its sends are signed
/// with — which would be invisible until every browser subscription
/// silently stopped working.
///
/// The key is public by definition: it is handed to every browser that
/// subscribes. Nothing else from the environment comes back out.
#[must_use]
pub fn vapid_public_key(config: &dyn Config) -> Option<String> {
    let Survey::Complete(values) = survey(config, Platform::Web) else {
        return None;
    };
    let keys = vapid_keys(&values).ok()?;
    let http: Arc<dyn HttpClient> = Arc::new(OfflineHttpClient);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    WebPush::new(http, clock, keys)
        .ok()?
        .public_key()
        .map(str::to_owned)
}

/// An [`HttpClient`] that refuses every send, for [`inspect_push`]. The
/// adapters store it and never call it; if one ever did, this is a loud
/// refusal rather than a surprise network call from a diagnostic command.
struct OfflineHttpClient;

#[async_trait::async_trait]
impl HttpClient for OfflineHttpClient {
    async fn send(
        &self,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        Err(HttpError::Transport(
            "this push adapter was built for inspection only and cannot send".to_owned(),
        ))
    }
}

/// `docs/PUSH-ENV.md`, generated from [`PUSH_ENV`] so the document
/// cannot describe variables the reader does not read. Written and
/// drift-checked by `cargo run -p cratefield-push-wiring --example
/// push-env-doc`.
#[must_use]
pub fn notifications_doc() -> String {
    use fmt::Write as _;

    let mut out = String::new();
    out.push_str("# The push environment\n\n");
    out.push_str(
        "*Generated reference. The hand-written notifications guide (push, in-app, \
email and languages, with the per-platform client sections) is \
`docs/NOTIFICATIONS.md`, issue #185, which links here rather than repeating this \
table.*\n\n",
    );
    out.push_str(
        "Every environment variable the push adapters read, generated from\n\
         `cratefield-push-wiring`'s `PUSH_ENV` table by `cargo run -p\n\
         cratefield-push-wiring --example push-env-doc` and checked in CI for\n\
         drift (issue #191).\n\n\
         One function reads these names — `build_push` — so no two callers can\n\
         drift apart on a variable name. `serve()` reaches it through\n\
         `push_from_env()` on either runtime, and `fz doctor` through\n\
         `inspect_push`; `fz push` (issue #184) calls it directly when it lands.\n\
         `crates/cli-acceptance/tests/push_env_guard.rs` fails the build if any\n\
         other Rust source names one of them.\n\n\
         Keys are read through the `Config` port, so on Workers a secret and a\n\
         `[vars]` entry both work (a secret wins), and natively they are process\n\
         environment variables. A variable set to the empty string counts as unset.\n\n",
    );

    for transport in TRANSPORTS {
        let _ = writeln!(
            out,
            "## {} (`{}`)\n",
            transport_name(transport),
            transport_key(transport)
        );
        out.push_str("| Variable | Required | Secret | Purpose |\n");
        out.push_str("|---|---|---|---|\n");
        for var in vars_for(transport) {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} |",
                var.name(),
                if var.required { "yes" } else { "no" },
                if var.secret { "yes" } else { "no" },
                var.purpose,
            );
        }
        out.push('\n');
    }

    out.push_str(
        "## Verdicts\n\n\
         `build_push` returns a `PushWiring` report next to the router, and each\n\
         runtime logs it once at cold start. Per transport:\n\n\
         | Verdict | When | Consequence |\n\
         |---|---|---|\n\
         | `configured` | every required variable is set and the adapter accepted \
         them | the transport is routed |\n\
         | `absent` | not one of its variables is set | the transport is not routed; \
         its recipients answer `NotConfigured`. A choice, not a defect |\n\
         | `partial` | some of its variables are set and some are not | the transport \
         is **not** routed. An error in production, a warning elsewhere |\n\
         | `invalid` | all are set and the adapter refused them | the transport is \
         **not** routed. An error in production, a warning elsewhere |\n\n\
         Partial is the case this exists for: a venture that meant to enable FCM and\n\
         mistyped one variable must not boot into a state where every Android send\n\
         silently answers `NotConfigured`. In production that fails `fz doctor` and\n\
         is logged at error; in development and staging it is a warning, because\n\
         wiring a transport one variable at a time is what development looks like.\n\n\
         The report holds variable **names** and verdicts only, never a value, so it\n\
         is safe to log whole.\n",
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    #[test]
    fn every_variable_belongs_to_exactly_one_transport_and_is_unique() {
        let mut names: Vec<&str> = PUSH_ENV.iter().map(PushVar::name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "a variable is listed twice");
    }

    #[test]
    fn every_key_appears_in_the_table_exactly_once() {
        // The typed lookup is only infallible if the table carries every
        // key: a key the table does not hold could be asked for and never
        // found. `PushKey::name` is exhaustive, so this pairs the two
        // directions — and a key added to the enum but not to the table
        // fails here rather than in production as an empty credential.
        let keys: Vec<PushKey> = PUSH_ENV.iter().map(|var| var.key).collect();
        for key in [
            PushKey::ApnsKeyP8,
            PushKey::ApnsKeyId,
            PushKey::ApnsTeamId,
            PushKey::ApnsTopic,
            PushKey::ApnsHost,
            PushKey::FcmServiceAccountJson,
            PushKey::VapidPrivateKey,
            PushKey::VapidSubject,
        ] {
            assert_eq!(
                keys.iter().filter(|found| **found == key).count(),
                1,
                "{} is not in PUSH_ENV exactly once",
                key.name()
            );
        }
        assert_eq!(
            keys.len(),
            8,
            "a key was added to the table, not to this test"
        );
    }

    #[test]
    fn a_value_is_trimmed_before_it_reaches_an_adapter() {
        // A newline or a leading space picked up in a paste is invisible.
        // Untrimmed, `APNS_KEY_ID` reports `configured`, goes into the
        // provider JWT's `kid` and earns a 403 on every send.
        let config = MapConfig::from_pairs([(
            PushKey::ApnsKeyId.name().to_owned(),
            " ABCDE12345\n".to_owned(),
        )]);
        assert_eq!(
            value_of(&config, PushKey::ApnsKeyId).as_deref(),
            Some("ABCDE12345")
        );
    }

    #[test]
    fn a_blank_value_is_unset() {
        // An empty Workers secret and an unset one mean the same thing to
        // an operator — and a value that is only whitespace is empty.
        let config =
            MapConfig::from_pairs([(PushKey::ApnsKeyId.name().to_owned(), "   \n".to_owned())]);
        assert_eq!(value_of(&config, PushKey::ApnsKeyId), None);
    }

    #[test]
    fn every_transport_has_at_least_one_required_variable() {
        // Without one, `survey` could never report `Absent` for it and the
        // router would try to build an adapter out of nothing.
        for transport in TRANSPORTS {
            assert!(
                vars_for(transport).any(|var| var.required),
                "{} has no required variable",
                transport_key(transport)
            );
        }
    }

    #[test]
    fn severity_does_not_format_the_problems_to_find_out_whether_there_are_any() {
        // A cheap assertion of a cheap implementation: `severity` runs on
        // every cold start and must not allocate three paragraphs to answer
        // a bool. Kept honest by agreeing with `problems()` either way.
        for config in [
            MapConfig::from_pairs(Vec::<(String, String)>::new()),
            MapConfig::from_pairs([(
                PushKey::VapidSubject.name().to_owned(),
                "mailto:ops@example.test".to_owned(),
            )]),
        ] {
            let wiring = inspect_push(&config);
            assert_eq!(
                wiring.severity(VentureEnv::Production) == WiringSeverity::Ok,
                wiring.problems().is_empty(),
                "{}",
                wiring.summary()
            );
        }
    }
}
