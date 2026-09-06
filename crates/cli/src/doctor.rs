//! `fz doctor` (issue #8): harness validity, the production-captcha rule,
//! lockfile consistency and the portable-SQL lint.

use crate::collect::verify_locked;
use crate::lint::banned_tokens;
use crate::lock::{Lock, read_lock};
use factory0_core::{Harness, VentureEnv};
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
) -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();

    // Harness::build already succeeded by construction; the venture
    // captcha rule is checked against the runtime's provided ports.
    if harness.venture().env == VentureEnv::Production {
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

    // Portable-SQL lint over every migration.
    for module in harness.modules() {
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

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n  - "))
    }
}

fn captcha_provided(harness: &Harness) -> bool {
    harness
        .runtime()
        .is_some_and(|runtime| runtime.provides().contains(&factory0_core::Port::Captcha))
}
