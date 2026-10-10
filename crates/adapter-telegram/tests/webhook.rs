//! Webhook tests (issue #764): the secret header decides before anything
//! parses, a verified delivery parses, a verified non-update does not, and
//! `is_valid_secret` mirrors Telegram's alphabet exactly.

use cratefield_adapter_telegram::webhook::{
    SECRET_HEADER, WebhookError, is_valid_secret, parse_verified,
};
use cratefield_adapter_telegram::{UpdateKind, parse_update};
use http::HeaderMap;

// Obvious dummy value, never real. Within Telegram's alphabet on purpose.
const SECRET: &str = "cratefield-webhook-secret-1";
const UPDATE: &str = include_str!("fixtures/message.json");

fn headers(secret: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(secret) = secret {
        headers.insert(SECRET_HEADER, secret.parse().expect("a header value"));
    }
    headers
}

#[test]
fn the_right_secret_verifies_and_parses() {
    let update = parse_verified(SECRET, &headers(Some(SECRET)), UPDATE.as_bytes(), 0)
        .expect("the matching secret verifies");
    assert_eq!(update.update_id, 100);
    assert!(matches!(update.kind, UpdateKind::Message(_)));
}

#[test]
fn a_wrong_or_missing_secret_is_unverified_and_never_parsed() {
    // A bad JSON body on purpose: if anything parsed before it verified,
    // these would come back Malformed instead of Unverified.
    for secret in [None, Some("not-the-secret")] {
        let error =
            parse_verified(SECRET, &headers(secret), b"not json at all", 0).expect_err("refused");
        assert_eq!(error, WebhookError::Unverified, "secret {secret:?}");
    }
}

#[test]
fn an_empty_header_value_or_secret_refuses() {
    // The verifier fails closed on an empty token or an empty configured
    // secret — neither can match anything.
    assert_eq!(
        parse_verified(SECRET, &headers(Some("")), UPDATE.as_bytes(), 0),
        Err(WebhookError::Unverified)
    );
    assert_eq!(
        parse_verified("", &headers(Some("")), UPDATE.as_bytes(), 0),
        Err(WebhookError::Unverified)
    );
}

#[test]
fn a_verified_body_that_is_not_an_update_is_malformed() {
    for body in [
        &b"not json at all"[..],
        b"[]",
        br#"{"update_id": 1, "message": {"message_id": 1}}"#, // no chat
    ] {
        let error = parse_verified(SECRET, &headers(Some(SECRET)), body, 0)
            .expect_err("a verified non-update is malformed");
        assert_eq!(
            error,
            WebhookError::Malformed,
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn the_errors_display_and_the_helper_composes_with_parse_update() {
    assert_eq!(
        WebhookError::Unverified.to_string(),
        "telegram webhook secret did not verify"
    );
    assert_eq!(
        WebhookError::Malformed.to_string(),
        "malformed telegram webhook body"
    );
    // The same body the webhook accepts parses bare, because the webhook
    // delegates to parse_update.
    let update = parse_update(UPDATE.as_bytes()).expect("parses");
    assert_eq!(update.update_id, 100);
}

#[test]
fn is_valid_secret_mirrors_telegrams_alphabet() {
    assert!(is_valid_secret("a"), "one character is allowed");
    assert!(is_valid_secret("ABCdef123_X-y"));
    assert!(is_valid_secret(&"a".repeat(256)), "256 is the ceiling");
    assert!(!is_valid_secret(""), "empty is not a secret");
    assert!(
        !is_valid_secret(&"a".repeat(257)),
        "257 is over the ceiling"
    );
    assert!(!is_valid_secret("has space"));
    assert!(!is_valid_secret("has.dot"));
    assert!(!is_valid_secret("has:colon"));
    assert!(
        !is_valid_secret("has$s fund"),
        "a stray $ is outside the alphabet"
    );
    assert!(
        !is_valid_secret("sécret"),
        "non-ASCII is outside the alphabet"
    );
}
