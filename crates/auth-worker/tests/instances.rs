//! Every instance the repository deploys (`instances/<app>/wrangler.toml`,
//! issue #777) must boot: its variables, in both environments, pass the
//! Worker's own validation and every module's, and its route, issuer,
//! passkey relying party and migrations agree with each other.
//!
//! A typo in an instance's `wrangler.toml` is caught here, in CI, instead
//! of as a 500 on the instance's first request.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cratefield_auth_worker::AuthWorkerConfig;
use cratefield_core::{MapConfig, Module};

fn instances_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../instances")
}

/// Every `instances/<app>/wrangler.toml`.
fn instances() -> Vec<(String, toml::Table)> {
    let mut found = Vec::new();
    for entry in fs::read_dir(instances_dir()).expect("instances/ is readable") {
        let dir = entry.expect("a directory entry").path();
        let file = dir.join("wrangler.toml");
        if file.is_file() {
            let text = fs::read_to_string(&file).expect("readable");
            let table: toml::Table = text
                .parse()
                .unwrap_or_else(|err| panic!("{} is not TOML: {err}", file.display()));
            let name = dir
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a utf-8 name")
                .to_owned();
            found.push((name, table));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// The two environments of one instance: the top level is staging,
/// `[env.production]` is production. Wrangler does not inherit tables into
/// an environment, so each is read on its own.
fn environments(table: &toml::Table) -> Vec<(&'static str, &toml::Table)> {
    let production = table
        .get("env")
        .and_then(|env| env.get("production"))
        .and_then(toml::Value::as_table)
        .expect("an [env.production] table");
    vec![("staging", table), ("production", production)]
}

fn vars(env: &toml::Table) -> BTreeMap<String, String> {
    env.get("vars")
        .and_then(toml::Value::as_table)
        .expect("a vars table")
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().expect("string vars").to_owned()))
        .collect()
}

/// The variables plus stand-ins for the secrets an operator puts, so the
/// check is about this file and not about a secret store.
fn config(vars: &BTreeMap<String, String>) -> MapConfig {
    let mut pairs: Vec<(String, String)> = vars.clone().into_iter().collect();
    pairs.push(("OWLPOST_API_KEY".to_owned(), "stand-in".to_owned()));
    pairs.push(("HARNESS_SECRET".to_owned(), "x".repeat(32)));
    MapConfig::from_pairs(pairs)
}

#[test]
fn the_known_instances_exist() {
    let names: Vec<String> = instances().into_iter().map(|(name, _)| name).collect();
    for expected in ["alphahunt", "cratefield"] {
        assert!(names.iter().any(|name| name == expected), "{names:?}");
    }
}

#[test]
fn every_instance_boots_in_both_environments() {
    for (name, table) in instances() {
        for (env_name, env) in environments(&table) {
            let vars = vars(env);
            let cfg = config(&vars);
            let parsed = AuthWorkerConfig::from_config(&cfg).unwrap_or_else(|err| {
                panic!("instances/{name} ({env_name}) is refused by the Worker: {err}")
            });
            let modules: Vec<Box<dyn Module>> = vec![
                Box::new(auth_core::AuthCore::new()),
                Box::new(auth_oidc::Oidc::new()),
                Box::new(auth_passkeys::Passkeys::new()),
                Box::new(auth_magic_link::MagicLink::new()),
                Box::new(auth_password::Password::new()),
                Box::new(auth_meta::Meta::new()),
            ];
            for module in modules {
                module.validate_config(&cfg).unwrap_or_else(|err| {
                    panic!(
                        "instances/{name} ({env_name}) is refused by {}: {err}",
                        module.name()
                    )
                });
            }

            // The route is the public URL's host, and the issuer is the
            // public URL: a token minted here names this instance.
            let host = parsed
                .public_url
                .strip_prefix("https://")
                .unwrap_or_else(|| panic!("instances/{name} ({env_name}) must use https"));
            let route = env
                .get("route")
                .and_then(|route| route.get("pattern"))
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("instances/{name} ({env_name}) has no route"));
            assert_eq!(route, host, "instances/{name} ({env_name})");
            assert_eq!(
                vars.get("AUTH_CORE_ISSUER"),
                Some(&parsed.public_url),
                "instances/{name} ({env_name})"
            );

            // A passkey's RP id must be the host or a registrable suffix of
            // it, or no browser runs the ceremony.
            let rp_id = vars
                .get("AUTH_PASSKEYS_RP_ID")
                .unwrap_or_else(|| panic!("instances/{name} ({env_name}) has no RP id"));
            assert!(
                host == rp_id || host.ends_with(&format!(".{rp_id}")),
                "instances/{name} ({env_name}): RP id {rp_id} does not cover {host}"
            );

            let d1 = env
                .get("d1_databases")
                .and_then(toml::Value::as_array)
                .and_then(|list| list.first())
                .unwrap_or_else(|| panic!("instances/{name} ({env_name}) has no D1"));
            let migrations = d1
                .get("migrations_dir")
                .and_then(toml::Value::as_str)
                .expect("a migrations_dir");
            assert!(
                instances_dir().join(&name).join(migrations).is_dir(),
                "instances/{name} ({env_name}): {migrations} does not exist"
            );
        }
    }
}

#[test]
fn production_is_production_and_names_its_own_app() {
    for (name, table) in instances() {
        let production = environments(&table)
            .into_iter()
            .find(|(env_name, _)| *env_name == "production")
            .map(|(_, env)| vars(env))
            .expect("production");
        assert_eq!(
            production.get("ENV").map(String::as_str),
            Some("production"),
            "instances/{name}"
        );
        // Two instances must never share an identity.
        assert!(
            production
                .get("AUTH_VENTURE_NAME")
                .is_some_and(|venture| venture.starts_with(&name)),
            "instances/{name}: AUTH_VENTURE_NAME should start with the instance's name"
        );
    }
}
