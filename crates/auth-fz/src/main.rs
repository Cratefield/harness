//! The auth venture's `fz` (auth#41). `fz migrations collect`, `doctor`, etc.
//! need to link the venture's *own* harness to see its modules — the
//! standalone `cratefield-cli` binary cannot. This composes the same modules
//! as the deployed Worker (a native `AllPorts` runtime, since `fz` only reads
//! module metadata, not live bindings) and hands them to the CLI.

use cratefield_core::{Harness, Port, Runtime, Venture};

/// A runtime that claims every port, so `Harness::build` succeeds for `fz`
/// without real adapters — `collect`/`doctor` read module migrations and
/// config, not live ports.
struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

/// The venture `fz` composes. Migrations and module metadata do not depend
/// on which app an instance belongs to (issue #777), so this names no app:
/// an operator who wants `doctor` to read as their instance exports that
/// instance's `AUTH_VENTURE_NAME` and `AUTH_PUBLIC_URL`, and otherwise a
/// neutral local placeholder is used.
fn venture() -> Venture {
    let name = std::env::var("AUTH_VENTURE_NAME").unwrap_or_else(|_| "auth-instance".to_owned());
    let public_url =
        std::env::var("AUTH_PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8788".to_owned());
    let host = public_url
        .split_once("://")
        .map_or(public_url.as_str(), |(_, rest)| rest)
        .split(['/', ':'])
        .next()
        .unwrap_or("localhost")
        .to_owned();
    Venture::new(name, host)
        .public_url(public_url.clone())
        .cors_origins([public_url])
}

/// The auth venture's harness — the same modules the Worker mounts.
fn harness() -> Harness {
    Harness::builder()
        .venture(venture())
        .templates(cratefield_auth_magic_link::default_templates())
        .templates(cratefield_auth_password::default_templates())
        .module(cratefield_auth_core::AuthCore::new())
        .module(cratefield_auth_oidc::Oidc::new())
        .module(cratefield_auth_passkeys::Passkeys::new())
        .module(cratefield_auth_magic_link::MagicLink::new())
        .module(cratefield_auth_password::Password::new())
        .module(cratefield_auth_meta::Meta::new())
        .runtime(AllPorts)
        .build()
        .expect("the auth venture is a valid harness")
}

fn main() {
    cratefield_cli::main_for(harness);
}
