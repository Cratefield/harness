//! `fz doctor` (issue #8): harness validity, the production-captcha rule,
//! lockfile consistency and the portable-SQL lint. Since issue #17 it
//! also re-asserts the contract-version rule.

use crate::collect::verify_locked;
use crate::lint::banned_tokens;
use crate::lock::{Lock, read_lock};
use cratefield_core::lint_card_data;
use cratefield_core::{HARNESS_API, HARNESS_SIDECARS, Harness, VentureEnv, harness_api_mismatch};
use std::path::Path;

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
    if harness.venture().env == VentureEnv::Production {
        production_port_checks(harness, allow_no_captcha, &mut failures);
    }

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

/// The production-only port rules, gathered so `doctor` stays a flat list of
/// checks: the captcha rule (with its override) and the payments webhook rule.
fn production_port_checks(
    harness: &Harness,
    allow_no_captcha: Option<&str>,
    failures: &mut Vec<String>,
) {
    let public_writers: Vec<&str> = harness
        .modules()
        .iter()
        .filter(|module| module.public_writes())
        .map(|module| module.name())
        .collect();
    if !public_writers.is_empty() && !captcha_provided(harness) {
        let message = format!(
            "production venture with public writes from [{}] but no Captcha port \
             — configure Turnstile (architecture section 11)",
            public_writers.join(", ")
        );
        match allow_no_captcha {
            Some(reason) => {
                eprintln!("fz: warning: captcha override accepted ({reason}): {message}");
            }
            None => failures.push(message),
        }
    }

    // A production venture that can take money must be able to verify webhook
    // signatures, or it will process forged events (issue #102). Doctor has no
    // venture config, but it runs natively where the operator can export the
    // secret, so the presence check reads the conventional env var.
    let webhook_secret_present =
        std::env::var("STRIPE_WEBHOOK_SECRET").is_ok_and(|value| !value.trim().is_empty());
    if let Some(message) =
        payments_webhook_failure(payments_provided(harness), webhook_secret_present)
    {
        failures.push(message);
    }
}

fn captcha_provided(harness: &Harness) -> bool {
    harness
        .runtime()
        .is_some_and(|runtime| runtime.provides().contains(&cratefield_core::Port::Captcha))
}

fn payments_provided(harness: &Harness) -> bool {
    harness.runtime().is_some_and(|runtime| {
        runtime
            .provides()
            .contains(&cratefield_core::Port::Payments)
    })
}

/// The production-payments rule: a production venture that provides the
/// `Payments` port without a webhook signing secret cannot verify Stripe
/// webhooks, so it would process forged events. Pure so the truth table is
/// unit-tested; the caller supplies the env-derived booleans.
fn payments_webhook_failure(
    payments_provided: bool,
    webhook_secret_present: bool,
) -> Option<String> {
    if payments_provided && !webhook_secret_present {
        Some(
            "production venture provides the Payments port but STRIPE_WEBHOOK_SECRET is unset \
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
    use super::payments_webhook_failure;

    #[test]
    fn payments_in_production_needs_a_webhook_secret() {
        assert!(payments_webhook_failure(true, false).is_some());
        assert!(payments_webhook_failure(true, true).is_none());
        assert!(payments_webhook_failure(false, false).is_none());
    }
}
