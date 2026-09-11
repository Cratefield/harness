//! `fz doctor` (issue #8): harness validity, lockfile consistency and the
//! portable-SQL lint. It re-asserts the contract-version rule (issue #17)
//! and the production abuse-port rules (issues #13/#102/#133) — the same
//! checks `Harness::build` enforces at initialization, kept visible here
//! for operator tooling.
//!
//! Output comes in two disciplines (harness #140). Without `--json` the
//! doctor is prose: warnings on stderr, every failure joined into one
//! message, byte-for-byte as it has always been. With `--json` it prints
//! exactly one JSON object to stdout — `schema`, `ok` and the failures,
//! each with its stable code from [`crate::codes`] — and nothing else,
//! so an agent can parse the verdict without screen-scraping.

use crate::EnvVars;
use crate::codes::{CODES, DoctorCodeDef};
use crate::collect::{LockedMigrationError, verify_locked};
use crate::lint::banned_tokens;
use crate::lock::{Lock, read_lock};
use cratefield_core::lint_card_data;
use cratefield_core::{
    HARNESS_API, HARNESS_SIDECARS, Harness, Port, SIDECAR_GATEWAY_SECRET, VentureEnv, deployed_env,
    env_disagreement, harness_api_mismatch,
};
use cratefield_push_wiring::PushWiring;
use std::path::Path;
use std::process::ExitCode;

/// The `schema` field of the `fz doctor --json` object (harness #140):
/// consumers branch on it, so it only ever grows.
pub const REPORT_SCHEMA: u32 = 1;

/// One failed doctor check: its stable code from the catalogue
/// ([`crate::codes`]) plus the human message, which is byte-identical to
/// the prose path's.
#[derive(Debug)]
pub struct DoctorFailure {
    /// The catalogue definition this failure is classified under.
    pub code: &'static DoctorCodeDef,
    /// The failure message, exactly as the prose path prints it.
    pub message: String,
}

/// The outcome of a doctor run: every failed check, in check order.
#[derive(Debug)]
pub struct DoctorReport {
    /// Empty when every check passed.
    pub failures: Vec<DoctorFailure>,
}

impl DoctorReport {
    /// `true` when every check passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }

    /// The exact stdout payload of `fz doctor --json`: one object, one
    /// line, no trailing newline.
    ///
    /// # Errors
    ///
    /// Only if `serde_json` cannot serialize the report — a struct of
    /// strings and numbers cannot hit that, but the Result keeps every
    /// caller total instead of panicking.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        #[derive(serde::Serialize)]
        struct Report<'a> {
            schema: u32,
            ok: bool,
            failures: Vec<Failure<'a>>,
        }
        #[derive(serde::Serialize)]
        struct Failure<'a> {
            code: &'a str,
            message: &'a str,
        }
        serde_json::to_string(&Report {
            schema: REPORT_SCHEMA,
            ok: self.ok(),
            failures: self
                .failures
                .iter()
                .map(|failure| Failure {
                    code: failure.code.code,
                    message: &failure.message,
                })
                .collect(),
        })
    }
}

/// Which output discipline the doctor runs under.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Output {
    /// Prose: operator warnings on stderr, failures joined into one
    /// message by [`doctor`].
    Human,
    /// `--json`: exactly one object on stdout, operator warnings
    /// suppressed so nothing but the JSON reaches a consumer.
    Json,
}

/// Runs every doctor check. `allow_no_captcha` downgrades the
/// production-captcha failure to a printed warning for the stated
/// reason (issue #13).
///
/// # Errors
///
/// One message listing every failed check — the same bytes `fz doctor`
/// has always produced.
pub fn doctor(
    harness: &Harness,
    migrations_dir: &Path,
    allow_no_captcha: Option<&str>,
    sidecars: Option<&str>,
) -> Result<(), String> {
    let report = run_checks(
        harness,
        migrations_dir,
        allow_no_captcha,
        sidecars,
        Output::Human,
    );
    if report.ok() {
        return Ok(());
    }
    let messages: Vec<String> = report
        .failures
        .into_iter()
        .map(|failure| failure.message)
        .collect();
    Err(messages.join("\n  - "))
}

/// Runs every doctor check under `--json` discipline (harness #140):
/// prints exactly one JSON object to stdout — `schema`, `ok`, `failures`
/// with their stable codes — and nothing else, then reports the verdict
/// as the exit code.
#[must_use = "call process::exit with the returned ExitCode"]
pub fn doctor_json(
    harness: &Harness,
    migrations_dir: &Path,
    allow_no_captcha: Option<&str>,
    sidecars: Option<&str>,
) -> ExitCode {
    let report = run_checks(
        harness,
        migrations_dir,
        allow_no_captcha,
        sidecars,
        Output::Json,
    );
    match report.render_json() {
        Ok(payload) => println!("{payload}"),
        Err(err) => {
            eprintln!("fz: cannot serialize the doctor report: {err}");
            return ExitCode::FAILURE;
        }
    }
    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The doctor's checks under `--json` discipline, without printing —
/// the exact report [`doctor_json`] serializes, for tests and future
/// consumers. Operator warnings are suppressed, as `--json` promises.
#[must_use]
pub fn doctor_report_json(
    harness: &Harness,
    migrations_dir: &Path,
    allow_no_captcha: Option<&str>,
    sidecars: Option<&str>,
) -> DoctorReport {
    run_checks(
        harness,
        migrations_dir,
        allow_no_captcha,
        sidecars,
        Output::Json,
    )
}

fn run_checks(
    harness: &Harness,
    migrations_dir: &Path,
    allow_no_captcha: Option<&str>,
    sidecars: Option<&str>,
    output: Output,
) -> DoctorReport {
    let mut failures: Vec<DoctorFailure> = Vec::new();

    contract_failures(harness, &mut failures);
    self_check_failures(harness, &mut failures);

    // Harness::build already succeeded by construction; the production-only
    // port rules (captcha, payments webhook) are checked against the runtime's
    // provided ports.
    //
    // The environment is the deployment's, not only the compiled one
    // (issue #143): the doctor runs where `ENV` is set, and a venture that
    // never called `.env()` still ships to production.
    let env = deployed_env(harness.venture().env, &EnvVars);
    if let Some(note) = env_disagreement(harness.venture().env, env)
        && output == Output::Human
    {
        eprintln!("fz: warning: {note}");
    }
    if env == VentureEnv::Production {
        production_port_checks(harness, allow_no_captcha, output, &mut failures);
    }

    push_checks(harness, env, output, &mut failures);
    lockfile_failures(harness, migrations_dir, &mut failures);
    sidecar_failures(harness, sidecars, output, &mut failures);
    lint_failures(harness, &mut failures);

    DoctorReport { failures }
}

/// The contract-version re-check (issue #17). `Harness::build` already
/// refuses a mismatched module, so a harness that reaches the doctor is
/// coherent; the re-check keeps the rule visible here as well, and reports
/// the module, its version and the core crate if it ever fires.
fn contract_failures(harness: &Harness, failures: &mut Vec<DoctorFailure>) {
    for module in harness.modules() {
        if module.harness_api() != HARNESS_API {
            failures.push(DoctorFailure {
                code: &CODES.harness_api_mismatch,
                message: harness_api_mismatch(module.as_ref()),
            });
        }
    }
}

/// What each module says about its own embedded data
/// ([`Module::self_check`](cratefield_core::Module::self_check)).
///
/// The doctor has no deploy config, so it cannot run a module's
/// `validate_config` — those values live on the runtime `Env` and exist
/// only per request. It *can* ask whether what the module compiled in is
/// coherent, and that question has the same answer everywhere: the
/// notifications module answers it with every translation its catalog is
/// missing for a message the venture declared (issue #190).
///
/// Unconditional, not production-only. A missing translation is a person
/// reading `booking-confirmed.title` on a lock screen in every
/// environment, and finding it on staging is the point.
fn self_check_failures(harness: &Harness, failures: &mut Vec<DoctorFailure>) {
    for module in harness.modules() {
        for message in module.self_check() {
            failures.push(DoctorFailure {
                code: &CODES.module_self_check,
                message,
            });
        }
    }
}

/// Lockfile consistency: every module migration locked, every locked
/// file present and byte-identical.
fn lockfile_failures(harness: &Harness, migrations_dir: &Path, failures: &mut Vec<DoctorFailure>) {
    let lock = match read_lock(migrations_dir) {
        Ok(lock) => lock,
        Err(err) => {
            failures.push(DoctorFailure {
                code: &CODES.lockfile_unreadable,
                message: err,
            });
            Lock::default()
        }
    };
    for module in harness.modules() {
        for migration in module.migrations().sqlite {
            let key = format!("{}/{}", module.name(), migration.id);
            match lock.get(&key) {
                Some(entry) => {
                    if let Err(err) = verify_locked(migrations_dir, &key, entry) {
                        let code = match &err {
                            LockedMigrationError::Missing { .. } => &CODES.locked_migration_missing,
                            LockedMigrationError::Edited { .. } => &CODES.locked_migration_edited,
                        };
                        failures.push(DoctorFailure {
                            code,
                            message: err.to_string(),
                        });
                    }
                }
                None => failures.push(DoctorFailure {
                    code: &CODES.migration_not_collected,
                    message: format!(
                        "migration {key} is not collected yet — run `fz migrations collect`"
                    ),
                }),
            }
        }
    }
}

/// Sidecars (issue #66). The doctor sees only compiled-in modules, so
/// it says plainly what it cannot check rather than reporting a clean
/// bill for half the venture. A mount that shadows a compiled-in
/// module is a real misconfiguration: the runtime ignores it and
/// keeps the compiled-in module, so someone believes a sidecar is
/// serving a prefix that it is not.
fn sidecar_failures(
    harness: &Harness,
    sidecars: Option<&str>,
    output: Output,
    failures: &mut Vec<DoctorFailure>,
) {
    match crate::sidecars::parse(sidecars) {
        Ok(mounts) if !mounts.is_empty() => {
            for mount in crate::sidecars::shadowing(harness, &mounts) {
                failures.push(DoctorFailure {
                    code: &CODES.sidecar_shadows_module,
                    message: format!(
                        "sidecar mount `{}` names a module compiled into this venture; the runtime \
                         ignores the mount and serves the compiled-in module. Remove it from \
                         {HARNESS_SIDECARS} or remove the module from the composition",
                        mount.name
                    ),
                });
            }
            if output == Output::Human {
                eprintln!(
                    "fz: warning: {} is sidecar-mounted, so its tables, migrations and SQL are not \
                     checked here — they live in its own repository (docs/MOUNTING.md)",
                    crate::sidecars::listed(&mounts)
                );
                // Gateway advisory (issue #131): without the shared secret the
                // host stamps no token, so a sidecar that requires one refuses
                // every forwarded request and a sidecar that does not cannot
                // tell the host from the open internet.
                if std::env::var(SIDECAR_GATEWAY_SECRET)
                    .ok()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    eprintln!(
                        "fz: warning: {SIDECAR_GATEWAY_SECRET} is unset — the host stamps no \
                         gateway token, so a sidecar that requires one (SIDECAR_REQUIRE_GATEWAY) \
                         refuses every forwarded request (issue #131)"
                    );
                }
            }
        }
        Ok(_) => {}
        Err(errors) => failures.extend(errors.into_iter().map(|message| DoctorFailure {
            code: &CODES.sidecar_mount_invalid,
            message,
        })),
    }
}

/// The SQL lints: the portable-SQL check and the card-data check (#44).
/// The portable lint skips a module that ships a `postgres` set — it has
/// declared where its SQL differs, the same rule
/// `cratefield_adapter_postgres::select_set` applies when it chooses a set,
/// and the doctor should not disagree with the runner. The card-data lint
/// never skips: no dialect stores a card number, verification code or full
/// expiry, unlike the portable lint above.
fn lint_failures(harness: &Harness, failures: &mut Vec<DoctorFailure>) {
    for module in harness.modules() {
        if !module.migrations().postgres.is_empty() {
            continue;
        }
        for migration in module.migrations().sqlite {
            for (token, why) in banned_tokens(migration.sql) {
                failures.push(DoctorFailure {
                    code: &CODES.non_portable_sql,
                    message: format!(
                        "module `{}` migration {}: banned token `{token}` — {why}",
                        module.name(),
                        migration.id
                    ),
                });
            }
        }
    }

    for module in harness.modules() {
        let migrations = module.migrations();
        for migration in migrations.sqlite.iter().chain(migrations.postgres.iter()) {
            for (fragment, why) in lint_card_data(migration.sql) {
                failures.push(DoctorFailure {
                    code: &CODES.card_data_in_migration,
                    message: format!(
                        "module `{}` migration {}: `{fragment}` {why}",
                        module.name(),
                        migration.id
                    ),
                });
            }
        }
    }
}

/// The push-wiring section (issue #191). The doctor does not read the push
/// environment itself: it calls the same `build_push` `serve()` and `fz push`
/// call, through `inspect_push`, so the three cannot check different variable
/// names.
///
/// Gated on what the harness declares, like every other production-only rule
/// here: the process environment is shared, and a venture that mounts no push
/// module at all must not fail its deploy because the env file it inherits
/// exports someone else's `VAPID_SUBJECT`.
fn push_checks(
    harness: &Harness,
    env: VentureEnv,
    output: Output,
    failures: &mut Vec<DoctorFailure>,
) {
    let declaration = PushDeclaration::of(harness.modules());
    if !declaration.declared {
        return;
    }
    push_wiring_checks(
        &cratefield_push_wiring::inspect_push(&EnvVars),
        env,
        declaration,
        output,
        failures,
    );
}

/// What this venture says about push, so the doctor's push rules key on the
/// harness rather than on whatever the process environment happens to
/// export (issue #191).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PushDeclaration {
    /// A module lists [`Port::Push`] in `requires()` or `optional()`. Only
    /// then is the push environment this venture's business.
    declared: bool,
    /// A module lists it in `requires()`: this venture does not work
    /// without a transport that can actually send.
    required: bool,
}

impl PushDeclaration {
    fn of(modules: &[std::sync::Arc<dyn cratefield_core::Module>]) -> Self {
        Self::from_ports(
            modules
                .iter()
                .map(|module| (module.requires(), module.optional())),
        )
    }

    /// The rule itself, over nothing but the port lists — so it is unit
    /// tested without composing a harness, which for a module that
    /// *requires* a port would mean a runtime that provides it too.
    fn from_ports<'a>(modules: impl Iterator<Item = (&'a [Port], &'a [Port])>) -> Self {
        let mut declaration = Self {
            declared: false,
            required: false,
        };
        for (requires, optional) in modules {
            if requires.contains(&Port::Push) {
                declaration.declared = true;
                declaration.required = true;
            } else if optional.contains(&Port::Push) {
                declaration.declared = true;
            }
        }
        declaration
    }
}

/// Turns a push wiring report into doctor output: failures in production,
/// warnings below it (issue #191). Split out so the rules are unit tested
/// without a process environment.
///
/// The severity rule itself is [`PushWiring::check`]'s, called rather than
/// restated — the same rule encoded twice is the drift this crate exists to
/// prevent, one copy short of a test.
///
/// The second rule is the build-time gate `push_from_env()` cannot keep. A
/// runtime that assembles the port from the environment provides `Port::Push`
/// whatever that environment holds — on Workers the `Env` does not exist
/// until the first fetch, so `Harness::build` cannot know — and a module that
/// requires push then compiles, deploys, and answers `NotConfigured` for
/// every send. The doctor is where the deployment's environment *is* known,
/// so the refusal lives here: in production, a venture whose modules require
/// push and whose environment routes no transport at all fails.
fn push_wiring_checks(
    wiring: &PushWiring,
    env: VentureEnv,
    declaration: PushDeclaration,
    output: Output,
    failures: &mut Vec<DoctorFailure>,
) {
    match wiring.check(env) {
        // Half-wired and refused-credentials are one code, not two: the
        // message already names which transport and which variables, and
        // `check` reports every misconfigured transport in one string, so a
        // venture with one of each has a single failure to classify. The
        // operator action is the same either way — finish or correct that
        // transport's variables, or unset them to say it is deliberately off.
        Err(problems) => failures.push(DoctorFailure {
            code: &CODES.push_transport_misconfigured,
            message: problems,
        }),
        // Below production the same problems are a warning: wiring a
        // transport one variable at a time is what development looks like.
        Ok(()) => {
            if output == Output::Human {
                for problem in wiring.problems() {
                    eprintln!("fz: warning: {problem}");
                }
            }
        }
    }

    if declaration.required && env == VentureEnv::Production && !wiring.any_routed() {
        failures.push(DoctorFailure {
            code: &CODES.push_required_but_unrouted,
            message: "production venture has modules that require the Push port but no push \
                      transport is configured — every send would answer NotConfigured. Set one \
                      transport's variables (docs/PUSH-ENV.md), or drop the modules that require \
                      push. If this venture provides Push from an adapter of its own rather than \
                      from the environment, that adapter is not visible here (issue #191)"
                .to_owned(),
        });
    }
}

/// The production-only port rules, gathered so `doctor` stays a flat list of
/// checks: the captcha rule (with its override) and the payments webhook rule.
fn production_port_checks(
    harness: &Harness,
    allow_no_captcha: Option<&str>,
    output: Output,
    failures: &mut Vec<DoctorFailure>,
) {
    let guards = cratefield_core::WriteGuards::collect(harness.modules());
    if let Some(message) = captcha_production_failure(
        &guards,
        cratefield_core::captcha_effective(harness.runtime()),
    ) {
        match allow_no_captcha {
            Some(reason) => {
                // An override of a production abuse control is a decision
                // someone has to answer for later, so it is recorded, not
                // just printed (issue #143). `tracing` is the audited sink
                // — scrubbed by #135 and shipped wherever the operator
                // sends logs — and fires in both disciplines, while the
                // stderr line keeps the operator running the command
                // informed.
                tracing::warn!(
                    control = "captcha",
                    reason,
                    modules = guards.captcha_modules.join(","),
                    "production abuse control overridden by an operator"
                );
                if output == Output::Human {
                    eprintln!("fz: warning: captcha override accepted ({reason}): {message}");
                    eprintln!(
                        "fz: note: this override is recorded; it is for previews only and must \
                         not stand in for a Captcha port in production"
                    );
                }
            }
            None => failures.push(DoctorFailure {
                code: &CODES.captcha_not_effective,
                message,
            }),
        }
    }

    let webhook_secret_present =
        std::env::var("STRIPE_WEBHOOK_SECRET").is_ok_and(|value| !value.trim().is_empty());
    if let Some(message) = payments_webhook_failure(guards.needs_payments(), webhook_secret_present)
    {
        failures.push(DoctorFailure {
            code: &CODES.payments_webhook_secret_missing,
            message,
        });
    }
}

/// The production captcha rule (issue #133): captcha-guarded writes need a
/// Captcha port that is *effectively* configured — provided **and** bound per
/// the adapter's report — not merely present. The builder already refuses
/// this composition (`Harness::build`); the doctor re-checks it so the rule
/// stays visible in operator tooling.
fn captcha_production_failure(
    guards: &cratefield_core::WriteGuards,
    captcha_effective: bool,
) -> Option<String> {
    if guards.needs_captcha() && !captcha_effective {
        Some(format!(
            "production venture has captcha-guarded public writes from [{}] but the Captcha port \
             is not effectively configured — provide Turnstile with its secret and expected \
             hostname (architecture section 11; issue #133)",
            guards.captcha_modules.join(", ")
        ))
    } else {
        None
    }
}

/// The production-payments rule: a production venture that declares
/// [`Signature`]-guarded routes without a webhook signing secret cannot
/// verify Stripe webhooks, so it would process forged events. Pure so the
/// truth table is unit-tested; the caller supplies the env-derived booleans.
///
/// [`Signature`]: cratefield_core::RoutePolicy::Signature
fn payments_webhook_failure(
    signature_routes_present: bool,
    webhook_secret_present: bool,
) -> Option<String> {
    if signature_routes_present && !webhook_secret_present {
        Some(
            "production venture has signature-guarded routes but STRIPE_WEBHOOK_SECRET is unset \
             — webhook signatures cannot be verified and forged events would be trusted \
             (issue #102)"
                .to_owned(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CODES, DoctorFailure, DoctorReport, Output, PushDeclaration, captcha_production_failure,
        payments_webhook_failure, push_wiring_checks,
    };
    use cratefield_core::{MapConfig, Port, VentureEnv, WriteGuards};
    use cratefield_push_wiring::{PUSH_ENV, PushKey, PushWiring, inspect_push};

    /// A venture whose modules only *may* use push: the wiring is checked,
    /// but nothing has to be routed.
    const OPTIONAL: PushDeclaration = PushDeclaration {
        declared: true,
        required: false,
    };

    /// A venture whose modules cannot work without a transport.
    const REQUIRED: PushDeclaration = PushDeclaration {
        declared: true,
        required: true,
    };

    fn guards(needs_captcha: bool) -> WriteGuards {
        WriteGuards {
            captcha_modules: if needs_captcha {
                vec!["writer".to_owned()]
            } else {
                Vec::new()
            },
            signature_modules: Vec::new(),
            signed_link_modules: Vec::new(),
        }
    }

    #[test]
    fn captcha_rule_keys_on_declared_policies_and_effectiveness() {
        // Guarded writes without an effective port fail — even if the port
        // is *present*, since effectiveness is what the gate measures.
        let failure = captcha_production_failure(&guards(true), false).expect("fails closed");
        assert!(failure.contains("writer"));
        assert!(failure.contains("effectively configured"));
        assert!(captcha_production_failure(&guards(true), true).is_none());
        assert!(captcha_production_failure(&guards(false), false).is_none());
    }

    #[test]
    fn payments_in_production_needs_a_webhook_secret() {
        assert!(payments_webhook_failure(true, false).is_some());
        assert!(payments_webhook_failure(true, true).is_none());
        assert!(payments_webhook_failure(false, false).is_none());
    }

    /// The `--json` wire contract (harness #140): field order, the schema
    /// number, and the code string straight from the catalogue.
    #[test]
    fn report_renders_the_json_contract() {
        let report = DoctorReport {
            failures: vec![
                DoctorFailure {
                    code: &CODES.captcha_not_effective,
                    message: "production venture has captcha-guarded writes".to_owned(),
                },
                DoctorFailure {
                    code: &CODES.payments_webhook_secret_missing,
                    message: "STRIPE_WEBHOOK_SECRET is unset".to_owned(),
                },
            ],
        };
        let payload = report.render_json().expect("serializes");
        assert_eq!(
            payload,
            "{\"schema\":1,\"ok\":false,\"failures\":[\
             {\"code\":\"captcha-not-effective\",\"message\":\"production venture has \
             captcha-guarded writes\"},\
             {\"code\":\"payments-webhook-secret-missing\",\"message\":\"STRIPE_WEBHOOK_SECRET \
             is unset\"}]}"
        );
        assert!(!report.ok());

        let clean = DoctorReport {
            failures: Vec::new(),
        };
        assert_eq!(
            clean.render_json().expect("serializes"),
            "{\"schema\":1,\"ok\":true,\"failures\":[]}"
        );
        assert!(clean.ok());
    }

    /// A half-wired push environment, built through the real reader so this
    /// test names no environment variable of its own — the property
    /// `cli-acceptance`'s guard enforces across the workspace.
    fn half_wired() -> PushWiring {
        let var = PUSH_ENV
            .iter()
            .find(|var| var.required)
            .expect("the table has a required variable");
        let wiring = inspect_push(&MapConfig::from_pairs([(
            var.name().to_owned(),
            "set-but-alone".to_owned(),
        )]));
        assert!(
            !wiring.problems().is_empty(),
            "one variable of a transport is a half-wired transport: {}",
            wiring.summary()
        );
        wiring
    }

    #[test]
    fn a_half_wired_transport_fails_the_doctor_in_production_only() {
        let wiring = half_wired();

        let mut failures = Vec::new();
        push_wiring_checks(
            &wiring,
            VentureEnv::Production,
            OPTIONAL,
            Output::Human,
            &mut failures,
        );
        assert_eq!(failures.len(), 1, "{failures:?}");
        for problem in wiring.problems() {
            assert!(failures[0].message.contains(&problem), "{failures:?}");
        }
        // The slug itself, written out: the catalogue's contract is that a
        // code is never renamed, and a test that reads it back off `CODES`
        // would rename with it.
        assert_eq!(failures[0].code.code, "push-transport-misconfigured");

        // Below production it is a printed warning, not a failure: wiring a
        // transport one variable at a time is what development looks like.
        for env in [VentureEnv::Development, VentureEnv::Staging] {
            let mut failures = Vec::new();
            push_wiring_checks(&wiring, env, OPTIONAL, Output::Human, &mut failures);
            assert!(failures.is_empty(), "{env:?}: {failures:?}");
        }
    }

    #[test]
    fn a_venture_that_wires_no_push_at_all_is_silent() {
        // Absent is a choice, not a defect — the doctor must not nag a
        // venture that sends no notifications, even in production.
        let wiring = inspect_push(&MapConfig::from_pairs(Vec::<(String, String)>::new()));
        let mut failures = Vec::new();
        push_wiring_checks(
            &wiring,
            VentureEnv::Production,
            OPTIONAL,
            Output::Human,
            &mut failures,
        );
        assert!(failures.is_empty(), "{failures:?}");
        assert!(wiring.problems().is_empty(), "{:?}", wiring.problems());
    }

    #[test]
    fn a_module_that_requires_push_needs_a_transport_that_can_send() {
        // The build-time gate `push_from_env()` cannot keep: on Workers the
        // `Env` does not exist when `Harness::build` runs, so a module
        // requiring Push compiles and deploys against an environment that
        // configures nothing and answers NotConfigured for every send. The
        // doctor runs where the environment is known, so it refuses.
        let nothing = inspect_push(&MapConfig::from_pairs(Vec::<(String, String)>::new()));
        assert!(!nothing.any_routed());

        let mut failures = Vec::new();
        push_wiring_checks(
            &nothing,
            VentureEnv::Production,
            REQUIRED,
            Output::Human,
            &mut failures,
        );
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].message.contains("require the Push port"),
            "{failures:?}"
        );
        // Its own code, not the half-wired one: nothing here is half-wired,
        // and the operator's move is to route a transport or to drop the
        // modules that require one.
        assert_eq!(failures[0].code.code, "push-required-but-unrouted");

        // Only in production, and only when a module actually requires it.
        for env in [VentureEnv::Development, VentureEnv::Staging] {
            let mut failures = Vec::new();
            push_wiring_checks(&nothing, env, REQUIRED, Output::Human, &mut failures);
            assert!(failures.is_empty(), "{env:?}: {failures:?}");
        }
        let mut failures = Vec::new();
        push_wiring_checks(
            &nothing,
            VentureEnv::Production,
            OPTIONAL,
            Output::Human,
            &mut failures,
        );
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn the_push_rules_are_gated_on_what_the_venture_declares() {
        // The process environment is shared. A venture that mounts no push
        // module at all must not fail its production doctor run because the
        // env file it inherits exports somebody else's VAPID_SUBJECT — every
        // other production-only rule here keys on the harness, and this one
        // did not.
        let none = PushDeclaration::from_ports([(&[Port::Db][..], &[][..])].into_iter());
        assert!(!none.declared);
        assert!(!none.required);

        let optional =
            PushDeclaration::from_ports([(&[Port::Db][..], &[Port::Push][..])].into_iter());
        assert!(optional.declared);
        assert!(
            !optional.required,
            "a module that only *may* use push does not make one mandatory"
        );

        let required = PushDeclaration::from_ports(
            [(&[Port::Db][..], &[][..]), (&[Port::Push][..], &[][..])].into_iter(),
        );
        assert!(required.declared);
        assert!(required.required);
    }

    #[test]
    fn a_configured_transport_satisfies_a_module_that_requires_push() {
        // The rule must pass on the deployment it is meant to allow, or it
        // is just a way to fail every production doctor run.
        //
        // The variables are named through `PushKey`, not written out: the
        // guard in `cli-acceptance` allows exactly one source in the
        // workspace to spell one of these names, and it is not this one.
        let key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\
                   cXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0\
                   uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n\
                   -----END PRIVATE KEY-----";
        let wiring = inspect_push(&MapConfig::from_pairs([
            (PushKey::VapidPrivateKey.name().to_owned(), key.to_owned()),
            (
                PushKey::VapidSubject.name().to_owned(),
                "mailto:ops@example.test".to_owned(),
            ),
        ]));
        assert!(wiring.any_routed(), "{}", wiring.summary());

        let mut failures = Vec::new();
        push_wiring_checks(
            &wiring,
            VentureEnv::Production,
            REQUIRED,
            Output::Human,
            &mut failures,
        );
        assert!(failures.is_empty(), "{failures:?}");
    }
}
