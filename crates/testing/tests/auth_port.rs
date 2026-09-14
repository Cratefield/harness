//! The `Auth` port: who a request's credentials speak for (issue #153).
//!
//! The rule with teeth is that an unverified credential is not anonymity.
//! Folding the two together is a hole with no floor: an expired token
//! reading a `public-read` table would succeed, so nothing would tell its
//! holder the session had ended, and the first handler written to fall
//! back to anonymous on error would hand anonymous access to anybody
//! presenting a forged token.

use cratefield_core::{
    Auth, AuthError, Caller, Config, ConfigError, Migrations, Module, ModuleContext, Port, Ports,
};
use cratefield_testing::{AuthMode, FakeAuth};
use http::HeaderMap;

fn with_bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("a header value"),
    );
    headers
}

#[test]
fn a_request_with_no_credential_is_anonymous() {
    let auth = FakeAuth::subjects();
    let who = pollster::block_on(auth.identify(&HeaderMap::new())).expect("no credential is fine");
    assert_eq!(who, Caller::Anonymous);
    assert_eq!(who.id(), None);
}

#[test]
fn a_credential_that_does_not_verify_is_not_anonymity() {
    // The whole point of the port answering a `Result`.
    let auth = FakeAuth::new(AuthMode::NotVerified);
    assert_eq!(
        pollster::block_on(auth.identify(&with_bearer("forged"))),
        Err(AuthError::NotVerified)
    );
    // And the same verifier still calls a request with no header
    // anonymous, which is the distinction being kept.
    assert_eq!(
        pollster::block_on(auth.identify(&HeaderMap::new())),
        Ok(Caller::Anonymous)
    );
}

#[test]
fn a_verifier_that_cannot_answer_is_a_different_refusal() {
    // One is the caller's problem and one is the deployment's, so one is
    // a 401 and the other a 503. Telling a user to sign in again while
    // the auth service is down is advice they will follow and that will
    // not help.
    let auth = FakeAuth::new(AuthMode::Unavailable);
    let refusal = pollster::block_on(auth.identify(&with_bearer("fine")));
    assert!(
        matches!(refusal, Err(AuthError::Unavailable(_))),
        "{refusal:?}"
    );
    assert_ne!(refusal, Err(AuthError::NotVerified));
}

#[test]
fn an_unavailable_message_is_scrubbed_on_the_way_out() {
    // The detail is an adapter's, so it can carry a connection URL with
    // credentials in it. `DbError` scrubs for this reason (#135), and
    // "it never reaches a caller" is a promise about every call site
    // rather than about this type.
    let raw = "connect failed: https://svc:hunter2@auth.example/jwks for ada@example.com";
    let rendered = AuthError::Unavailable(raw.to_owned()).to_string();
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(!rendered.contains("ada@example.com"), "{rendered}");
    // And it still says what went wrong, or the scrub has eaten the
    // message instead of the secret.
    assert!(
        rendered.contains("the verifier could not answer"),
        "{rendered}"
    );
}

#[test]
fn a_verified_credential_carries_the_subject_a_table_matches_on() {
    let auth = FakeAuth::subjects();
    let who = pollster::block_on(auth.identify(&with_bearer("ada"))).expect("verifies");
    assert_eq!(who.id(), Some("ada"));
    assert_eq!(
        who.subject().map(|subject| subject.session.as_str()),
        Some("fake-session")
    );
}

/// A module that needs to know who is calling.
struct NeedsAuth;

impl Module for NeedsAuth {
    fn name(&self) -> &'static str {
        "needs-auth"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Auth]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

#[test]
fn a_module_that_declared_the_port_is_handed_it() {
    let mut ports = Ports::empty();
    ports.auth = Some(std::sync::Arc::new(FakeAuth::subjects()));
    let view = ports.view_for(&NeedsAuth);
    assert!(view.auth.is_some(), "a declared port is in the view");
}

#[test]
fn a_module_that_did_not_declare_the_port_cannot_reach_it() {
    // The same rule every other port follows: `view_for` hands a module
    // only what it asked for, so a module cannot quietly start
    // identifying callers without saying so in `requires()`.
    struct Quiet;
    impl Module for Quiet {
        fn name(&self) -> &'static str {
            "quiet"
        }
        fn version(&self) -> &'static str {
            "0.0.0"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn migrations(&self) -> Migrations {
            Migrations::default()
        }
        fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
            Ok(())
        }
        fn router(&self, _ctx: ModuleContext) -> axum::Router {
            axum::Router::new()
        }
    }
    let mut ports = Ports::empty();
    ports.auth = Some(std::sync::Arc::new(FakeAuth::subjects()));
    assert!(ports.view_for(&Quiet).auth.is_none());
}

#[test]
fn the_port_is_one_a_runtime_can_be_asked_for() {
    // It has to be in `ALL`, or `warn_undeclared_ports` never mentions it
    // and a composition check that iterates the ports skips it.
    assert!(Port::ALL.contains(&Port::Auth), "{:?}", Port::ALL);
    assert_eq!(Port::Auth.name(), "Auth");
}
