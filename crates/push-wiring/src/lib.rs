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
//! `docs/NOTIFICATIONS.md` is generated from [`PUSH_ENV`] by
//! `cargo run -p cratefield-push-wiring --example notifications-doc`, and CI
//! fails on drift — so the doc cannot describe variables the reader does not
//! read.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use cratefield_adapter_apns::{Apns, ApnsCredentials, ApnsHost};
use cratefield_adapter_fcm::Fcm;
use cratefield_adapter_webpush::WebPush;
use cratefield_adapter_webpush::vapid::VapidKeys;
use cratefield_core::{
    Clock, Config, HttpClient, HttpError, Platform, Push, RoutingPush, SystemClock, VentureEnv,
};

/// One environment variable a push transport reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushVar {
    /// The `SCREAMING_SNAKE` key, read through [`Config`] so a Workers
    /// secret and a native environment variable are the same thing.
    pub name: &'static str,
    /// The transport it belongs to.
    pub transport: Platform,
    /// Whether the transport cannot be built without it.
    pub required: bool,
    /// Whether the value is credential material. A `true` here means the
    /// value must never reach a log — only this name and a verdict.
    pub secret: bool,
    /// What it is, for `docs/NOTIFICATIONS.md`.
    pub purpose: &'static str,
}

/// Every environment variable the push adapters read, in one table.
///
/// This is the single source of truth the acceptance test in
/// `cli-acceptance` enforces: no other Rust source may name one of these
/// keys in a string literal.
pub const PUSH_ENV: &[PushVar] = &[
    PushVar {
        name: "APNS_KEY_P8",
        transport: Platform::Ios,
        required: true,
        secret: true,
        purpose: "The `.p8` provider key from the Apple developer portal, PKCS#8 PEM, whole.",
    },
    PushVar {
        name: "APNS_KEY_ID",
        transport: Platform::Ios,
        required: true,
        secret: false,
        purpose: "The key's 10-character id (the `.p8` filename suffix).",
    },
    PushVar {
        name: "APNS_TEAM_ID",
        transport: Platform::Ios,
        required: true,
        secret: false,
        purpose: "The 10-character Apple team id; the provider JWT's issuer.",
    },
    PushVar {
        name: "APNS_TOPIC",
        transport: Platform::Ios,
        required: true,
        secret: false,
        purpose: "The app's bundle id, sent as `apns-topic`.",
    },
    PushVar {
        name: "APNS_HOST",
        transport: Platform::Ios,
        required: false,
        secret: false,
        purpose: "`production` or `sandbox`. Optional; defaults to `sandbox`, because a \
                  development build's token is a sandbox token and sending it to production \
                  fails every time.",
    },
    PushVar {
        name: "FCM_SERVICE_ACCOUNT_JSON",
        transport: Platform::Android,
        required: true,
        secret: true,
        purpose: "The Google service-account JSON Firebase hands over, whole. `client_email`, \
                  `private_key`, `project_id` and `token_uri` are read out of it, so there is \
                  no second variable to keep in step.",
    },
    PushVar {
        name: "VAPID_PRIVATE_KEY",
        transport: Platform::Web,
        required: true,
        secret: true,
        purpose: "The VAPID private key: a PKCS#8 PEM, or the bare 32-byte P-256 scalar \
                  base64url. The public key is derived, never configured.",
    },
    PushVar {
        name: "VAPID_SUBJECT",
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
    /// Every variable is set and the adapter refused them. The reason is
    /// the adapter's own message, which names the defect and never the
    /// credential.
    Invalid {
        /// Why the adapter refused the credentials.
        reason: String,
    },
}

impl TransportWiring {
    /// `configured`, `absent`, `partial` or `invalid` — the word a log line
    /// and `docs/NOTIFICATIONS.md` use.
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

    /// How loudly to report this. Partial and invalid configurations are an
    /// error in production and a warning everywhere else.
    #[must_use]
    pub fn severity(&self, env: VentureEnv) -> WiringSeverity {
        if self.problems().is_empty() {
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
    Complete(Vec<(&'static str, String)>),
}

impl Survey {
    /// The value of `name`; only ever called for a variable this survey
    /// found, so the `unwrap_or_default` is unreachable in practice and
    /// still cannot panic.
    fn value(values: &[(&'static str, String)], name: &str) -> String {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }
}

/// A value that is set and not blank. A variable present but empty is
/// treated as unset: an empty Workers secret and an unset one mean the same
/// thing to an operator, and treating `""` as configured would hand the
/// adapter a credential it must then refuse.
fn value_of(config: &dyn Config, name: &str) -> Option<String> {
    config.get(name).filter(|value| !value.trim().is_empty())
}

fn survey(config: &dyn Config, transport: Platform) -> Survey {
    let mut present = Vec::new();
    let mut missing = Vec::new();
    let mut values = Vec::new();
    for var in vars_for(transport) {
        match value_of(config, var.name) {
            Some(value) => {
                present.push(var.name);
                values.push((var.name, value));
            }
            None if var.required => missing.push(var.name),
            None => {}
        }
    }
    if present.is_empty() {
        Survey::Absent
    } else if missing.is_empty() {
        Survey::Complete(values)
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

fn build_apns(config: &dyn Config, http: &Arc<dyn HttpClient>, clock: &Arc<dyn Clock>) -> Built {
    let values = match survey(config, Platform::Ios) {
        Survey::Absent => return (None, TransportWiring::Absent),
        Survey::Partial { present, missing } => {
            return (None, TransportWiring::Partial { present, missing });
        }
        Survey::Complete(values) => values,
    };

    let raw_host = Survey::value(&values, "APNS_HOST");
    // Unset is the sandbox, deliberately: a development build's device token
    // is a sandbox token, and the adapter's own README documents the same
    // default. A value that is set and unparseable is a typo, not a default.
    let host = if raw_host.is_empty() {
        Some(ApnsHost::Sandbox)
    } else {
        ApnsHost::parse(&raw_host)
    };
    let Some(host) = host else {
        // `APNS_HOST` is not a secret (the table says so), so echoing the
        // value is what makes the typo findable.
        return (
            None,
            TransportWiring::Invalid {
                reason: format!("APNS_HOST is {raw_host:?}; expected `production` or `sandbox`"),
            },
        );
    };

    let creds = ApnsCredentials {
        key_p8_pem: Survey::value(&values, "APNS_KEY_P8"),
        key_id: Survey::value(&values, "APNS_KEY_ID"),
        team_id: Survey::value(&values, "APNS_TEAM_ID"),
        topic: Survey::value(&values, "APNS_TOPIC"),
        host,
    };
    match Apns::new(Arc::clone(http), Arc::clone(clock), creds) {
        Ok(apns) => (Some(Arc::new(apns)), TransportWiring::Configured),
        Err(err) => (
            None,
            TransportWiring::Invalid {
                reason: err.to_string(),
            },
        ),
    }
}

fn build_fcm(config: &dyn Config, http: &Arc<dyn HttpClient>, clock: &Arc<dyn Clock>) -> Built {
    let values = match survey(config, Platform::Android) {
        Survey::Absent => return (None, TransportWiring::Absent),
        Survey::Partial { present, missing } => {
            return (None, TransportWiring::Partial { present, missing });
        }
        Survey::Complete(values) => values,
    };

    let json = Survey::value(&values, "FCM_SERVICE_ACCOUNT_JSON");
    match Fcm::from_service_account_json(Arc::clone(http), Arc::clone(clock), &json) {
        Ok(fcm) => (Some(Arc::new(fcm)), TransportWiring::Configured),
        Err(err) => (
            None,
            TransportWiring::Invalid {
                reason: err.to_string(),
            },
        ),
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

    let keys = VapidKeys {
        private_key: Survey::value(&values, "VAPID_PRIVATE_KEY"),
        subject: Survey::value(&values, "VAPID_SUBJECT"),
    };
    match WebPush::new(Arc::clone(http), Arc::clone(clock), keys) {
        Ok(web_push) => (Some(Arc::new(web_push)), TransportWiring::Configured),
        Err(err) => (
            None,
            TransportWiring::Invalid {
                reason: err.to_string(),
            },
        ),
    }
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

/// `docs/NOTIFICATIONS.md`, generated from [`PUSH_ENV`] so the document
/// cannot describe variables the reader does not read. Written and
/// drift-checked by `cargo run -p cratefield-push-wiring --example
/// notifications-doc`.
#[must_use]
pub fn notifications_doc() -> String {
    use fmt::Write as _;

    let mut out = String::new();
    out.push_str("# Notifications: the push environment\n\n");
    out.push_str(
        "Every environment variable the push adapters read, generated from\n\
         `cratefield-push-wiring`'s `PUSH_ENV` table by `cargo run -p\n\
         cratefield-push-wiring --example notifications-doc` and checked in CI for\n\
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
                var.name,
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

    #[test]
    fn every_variable_belongs_to_exactly_one_transport_and_is_unique() {
        let mut names: Vec<&str> = PUSH_ENV.iter().map(|var| var.name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "a variable is listed twice");
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
}
