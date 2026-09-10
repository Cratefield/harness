//! `fz doctor` (issue #8): harness validity, lockfile consistency and the
//! portable-SQL lint. It re-asserts the contract-version rule (issue #17)
//! and the production abuse-port rules (issues #13/#102/#133) — the same
//! checks `Harness::build` enforces at initialization, kept visible here
//! for operator tooling.

use crate::collect::verify_locked;
use crate::lint::banned_tokens;
use crate::lock::{Lock, read_lock};
use cratefield_core::lint_card_data;
use cratefield_core::{
    Config, HARNESS_API, HARNESS_SIDECARS, Harness, SIDECAR_GATEWAY_SECRET, VentureEnv,
    deployed_env, env_disagreement, harness_api_mismatch,
};
use cratefield_push_wiring::{PushWiring, WiringSeverity};
use std::path::Path;

/// The process environment as a [`Config`], so the doctor reads `ENV` the
/// same way a deployed runtime does (issue #143).
struct EnvVars;

impl Config for EnvVars {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|value| !value.is_empty())
    }
}

/// Runs every doctor check. `allow_no_captcha` downgrades the
/// production-captcha failure to a printed warning for the stated
/// reason (issue #13).
///
/// # Errors
///
/// One message listing every failed check.
pub fn doctor(
    harness: &Harness,
    migrations_dir: &Path,
    allow_no_captcha: Option<&str>,
    sidecars: Option<&str>,
) -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();

    // Contract versions (issue #17). `Harness::build` already refuses a
    // mismatched module, so a harness that reaches the doctor is coherent;
    // the re-check keeps the rule visible here as well, and reports the
    // module, its version and the core crate if it ever fires.
    for module in harness.modules() {
        if module.harness_api() != HARNESS_API {
            failures.push(harness_api_mismatch(module.as_ref()));
        }
    }

    // Harness::build already succeeded by construction; the production-only
    // port rules (captcha, payments webhook) are checked against the runtime's
    // provided ports.
    //
    // The environment is the deployment's, not only the compiled one
    // (issue #143): the doctor runs where `ENV` is set, and a venture that
    // never called `.env()` still ships to production.
    let env = deployed_env(harness.venture().env, &EnvVars);
    if let Some(note) = env_disagreement(harness.venture().env, env) {
        eprintln!("fz: warning: {note}");
    }
    if env == VentureEnv::Production {
        production_port_checks(harness, allow_no_captcha, &mut failures);
    }

    // Push wiring (issue #191). The doctor does not read the push
    // environment itself: it calls the same `build_push` `serve()` and
    // `fz push` call, through `inspect_push`, so the three cannot check
    // different variable names. A half-wired transport is a failure in
    // production and a warning below it — nothing is reported at all when
    // every transport is either configured or deliberately absent.
    push_wiring_checks(
        &cratefield_push_wiring::inspect_push(&EnvVars),
        env,
        &mut failures,
    );

    // Lockfile consistency: every module migration locked, every locked
    // file present and byte-identical.
    let lock = match read_lock(migrations_dir) {
        Ok(lock) => lock,
        Err(err) => {
            failures.push(err);
            Lock::default()
        }
    };
    for module in harness.modules() {
        for migration in module.migrations().sqlite {
            let key = format!("{}/{}", module.name(), migration.id);
            match lock.get(&key) {
                Some(entry) => {
                    if let Err(err) = verify_locked(migrations_dir, &key, entry) {
                        failures.push(err);
                    }
                }
                None => failures.push(format!(
                    "migration {key} is not collected yet — run `fz migrations collect`"
                )),
            }
        }
    }

    // Sidecars (issue #66). The doctor sees only compiled-in modules, so
    // it says plainly what it cannot check rather than reporting a clean
    // bill for half the venture. A mount that shadows a compiled-in
    // module is a real misconfiguration: the runtime ignores it and
    // keeps the compiled-in module, so someone believes a sidecar is
    // serving a prefix that it is not.
    match crate::sidecars::parse(sidecars) {
        Ok(mounts) if !mounts.is_empty() => {
            for mount in crate::sidecars::shadowing(harness, &mounts) {
                failures.push(format!(
                    "sidecar mount `{}` names a module compiled into this venture; the runtime \
                     ignores the mount and serves the compiled-in module. Remove it from \
                     {HARNESS_SIDECARS} or remove the module from the composition",
                    mount.name
                ));
            }
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
                    "fz: warning: {SIDECAR_GATEWAY_SECRET} is unset — the host stamps no gateway \
                     token, so a sidecar that requires one (SIDECAR_REQUIRE_GATEWAY) refuses \
                     every forwarded request (issue #131)"
                );
            }
        }
        Ok(_) => {}
        Err(errors) => failures.extend(errors),
    }

    // Portable-SQL lint over every migration. A module that ships a
    // `postgres` set has declared where its SQL differs, so its sqlite
    // set is allowed to be sqlite-specific — the same rule
    // `cratefield_adapter_postgres::select_set` applies when it chooses a
    // set, and the doctor should not disagree with the runner.
    for module in harness.modules() {
        if !module.migrations().postgres.is_empty() {
            continue;
        }
        for migration in module.migrations().sqlite {
            for (token, why) in banned_tokens(migration.sql) {
                failures.push(format!(
                    "module `{}` migration {}: banned token `{token}` — {why}",
                    module.name(),
                    migration.id
                ));
            }
        }
    }

    // Card-data lint (#44): never a card number, verification code or full
    // expiry in a migration, on either dialect (a normal Stripe integration
    // stores none of them) — so, unlike the portable lint above, this does not
    // skip a module that ships a postgres override.
    for module in harness.modules() {
        let migrations = module.migrations();
        for migration in migrations.sqlite.iter().chain(migrations.postgres.iter()) {
            for (fragment, why) in lint_card_data(migration.sql) {
                failures.push(format!(
                    "module `{}` migration {}: `{fragment}` {why}",
                    module.name(),
                    migration.id
                ));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n  - "))
    }
}

/// Turns a push wiring report into doctor output: failures in production,
/// warnings below it (issue #191). Split out so the severity rule is unit
/// tested without a process environment.
fn push_wiring_checks(wiring: &PushWiring, env: VentureEnv, failures: &mut Vec<String>) {
    match wiring.severity(env) {
        WiringSeverity::Ok => {}
        WiringSeverity::Warning => {
            for problem in wiring.problems() {
                eprintln!("fz: warning: {problem}");
            }
        }
        WiringSeverity::Error => failures.extend(wiring.problems()),
    }
}

/// The production-only port rules, gathered so `doctor` stays a flat list of
/// checks: the captcha rule (with its override) and the payments webhook rule.
fn production_port_checks(
    harness: &Harness,
    allow_no_captcha: Option<&str>,
    failures: &mut Vec<String>,
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
                // sends logs — while the stderr line keeps the operator
                // running the command informed.
                tracing::warn!(
                    control = "captcha",
                    reason,
                    modules = guards.captcha_modules.join(","),
                    "production abuse control overridden by an operator"
                );
                eprintln!("fz: warning: captcha override accepted ({reason}): {message}");
                eprintln!(
                    "fz: note: this override is recorded; it is for previews only and must \
                     not stand in for a Captcha port in production"
                );
            }
            None => failures.push(message),
        }
    }

    let webhook_secret_present =
        std::env::var("STRIPE_WEBHOOK_SECRET").is_ok_and(|value| !value.trim().is_empty());
    if let Some(message) = payments_webhook_failure(guards.needs_payments(), webhook_secret_present)
    {
        failures.push(message);
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
    use super::{captcha_production_failure, payments_webhook_failure, push_wiring_checks};
    use cratefield_core::{MapConfig, VentureEnv, WriteGuards};
    use cratefield_push_wiring::{PUSH_ENV, PushWiring, inspect_push};

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

    /// A half-wired push environment, built through the real reader so this
    /// test names no environment variable of its own — the property
    /// `cli-acceptance`'s guard enforces across the workspace.
    fn half_wired() -> PushWiring {
        let var = PUSH_ENV
            .iter()
            .find(|var| var.required)
            .expect("the table has a required variable");
        let wiring = inspect_push(&MapConfig::from_pairs([(
            var.name.to_owned(),
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
        push_wiring_checks(&wiring, VentureEnv::Production, &mut failures);
        assert_eq!(failures.len(), wiring.problems().len(), "{failures:?}");

        // Below production it is a printed warning, not a failure: wiring a
        // transport one variable at a time is what development looks like.
        for env in [VentureEnv::Development, VentureEnv::Staging] {
            let mut failures = Vec::new();
            push_wiring_checks(&wiring, env, &mut failures);
            assert!(failures.is_empty(), "{env:?}: {failures:?}");
        }
    }

    #[test]
    fn a_venture_that_wires_no_push_at_all_is_silent() {
        // Absent is a choice, not a defect — the doctor must not nag a
        // venture that sends no notifications, even in production.
        let wiring = inspect_push(&MapConfig::from_pairs(Vec::<(String, String)>::new()));
        let mut failures = Vec::new();
        push_wiring_checks(&wiring, VentureEnv::Production, &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
        assert!(wiring.problems().is_empty(), "{:?}", wiring.problems());
    }
}
