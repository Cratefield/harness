//! The verifier a deployment gets when it asked for one from the
//! environment and the environment did not have it.
//!
//! It has to fail in a way that cannot be mistaken for working. A public
//! table must still serve, and a caller presenting a credential must not
//! be told it did not verify — nothing here can tell, and saying so is a
//! claim this has not established.

use cratefield_core::{Auth, AuthError, Caller, Unconfigured};
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
fn a_request_with_no_credential_is_still_anonymous() {
    // So a venture whose tables are all public is unaffected by an auth
    // service it never configured and does not need.
    let auth = Unconfigured::new("AUTH_ISSUER is not set");
    assert_eq!(
        pollster::block_on(auth.identify(&HeaderMap::new())),
        Ok(Caller::Anonymous)
    );
}

#[test]
fn a_presented_credential_is_unavailable_and_never_unverified() {
    // The token may be perfectly good; nothing here can tell. Answering
    // `NotVerified` would send a signed-in user to sign in again, which
    // will not help, and would read in a log as a bad token rather than
    // as a deployment that cannot check one.
    let auth = Unconfigured::new("AUTH_ISSUER is not set");
    let refusal = pollster::block_on(auth.identify(&with_bearer("possibly-fine")));
    assert!(
        matches!(refusal, Err(AuthError::Unavailable(_))),
        "{refusal:?}"
    );
    assert_ne!(refusal, Err(AuthError::NotVerified));
}

#[test]
fn the_refusal_says_what_is_missing() {
    // An operator reading 503s needs the cause; this is the only place
    // that knows it.
    let auth = Unconfigured::new("AUTH_ISSUER and AUTH_CLIENT_ID are not set");
    let Err(AuthError::Unavailable(why)) = pollster::block_on(auth.identify(&with_bearer("x")))
    else {
        panic!("expected an unavailable refusal");
    };
    assert!(why.contains("AUTH_ISSUER"), "{why}");
    assert!(why.contains("AUTH_CLIENT_ID"), "{why}");
}
