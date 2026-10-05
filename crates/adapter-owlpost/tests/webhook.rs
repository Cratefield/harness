//! Owlpost's inbound webhooks: verify-then-parse, and every way a delivery is
//! refused (issue #668).

use cratefield_adapter_owlpost::webhook::{
    EVENT_ID_HEADER, Envelope, OwlpostEvent, SIGNATURE_HEADER, WebhookError, event_id,
    parse_verified, verifier,
};
use cratefield_testing::sign_stripe_style;
use http::{HeaderMap, HeaderValue};

const SECRET: &str = "whsec_test_dummy";
const NOW: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z, the fixtures' epoch
/// Core's ±300 s default tolerance.
const TOLERANCE: i64 = 300;

const FIXTURES: &str = include_str!("fixtures/webhook-events.json");

/// Signs `body` at `t` exactly as Owlpost would, with an event id header.
fn signed(body: &[u8], t: i64) -> HeaderMap {
    let mut headers = sign_stripe_style(SIGNATURE_HEADER, SECRET, t, body);
    headers.insert(EVENT_ID_HEADER, HeaderValue::from_static("evt_test"));
    headers
}

/// The fixture of type `event_type`, serialized — the bytes the signature covers.
fn fixture_bytes(event_type: &str) -> Vec<u8> {
    let envelope = serde_json::from_str::<Vec<serde_json::Value>>(FIXTURES)
        .expect("the fixture file is a JSON array")
        .into_iter()
        .find(|value| value["type"] == serde_json::json!(event_type))
        .unwrap_or_else(|| panic!("no fixture for {event_type}"));
    serde_json::to_vec(&envelope).expect("a fixture serializes")
}

/// Parses `body` as a good delivery signed at `NOW`.
fn parse_good(body: &[u8]) -> Result<Envelope, WebhookError> {
    parse_verified(&verifier(), SECRET, &signed(body, NOW), body, NOW)
}

/// Every fixture parses into the variant its `type` names. `event_type()` is
/// an exhaustive variant → wire match, so it equalling the fixture's type
/// does pin the variant: the wrong one names a different type.
#[test]
fn every_event_type_parses_into_its_variant() {
    let types = serde_json::from_str::<Vec<serde_json::Value>>(FIXTURES)
        .expect("the fixture file is a JSON array")
        .into_iter()
        .map(|value| {
            value["type"]
                .as_str()
                .expect("a fixture names its type")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(types.len(), 13, "one fixture per event type");
    for event_type in types {
        let envelope = parse_good(&fixture_bytes(&event_type))
            .unwrap_or_else(|error| panic!("{event_type} should parse, got {error}"));
        assert_eq!(envelope.event_type, event_type, "type kept verbatim");
        assert_eq!(envelope.data.event_type(), event_type);
        // `event_type()` and `event_type` agree by construction only if the
        // right variant was built; a typo in a match arm falls through to
        // `Unknown`, which would otherwise pass unnoticed.
        assert!(
            !matches!(envelope.data, OwlpostEvent::Unknown(_)),
            "{event_type} must not fall through to Unknown"
        );
        assert!(envelope.id.starts_with("evt_test"));
        assert!(envelope.created_at.ends_with('Z'), "RFC 3339 as sent");
    }
}

/// A few typed payloads carry fields worth pinning down.
#[test]
fn typed_fields_survive_the_parse() {
    let OwlpostEvent::EmailBounced(bounce) = parse_good(&fixture_bytes("email.bounced"))
        .expect("bounced parses")
        .data
    else {
        panic!("expected a bounce")
    };
    assert_eq!(bounce.code.as_deref(), Some("550"));
    assert_eq!(bounce.bounce_type.as_deref(), Some("hard"));
    assert_eq!(bounce.to, vec!["nobody@example.com".to_owned()]);

    let OwlpostEvent::EmailClicked(click) = parse_good(&fixture_bytes("email.clicked"))
        .expect("clicked parses")
        .data
    else {
        panic!("expected a click")
    };
    assert_eq!(click.url, "https://example.com/pricing");
    assert_eq!(click.user_agent.as_deref(), Some("Mozilla/5.0"));

    let OwlpostEvent::MessageReceived(inbound) = parse_good(&fixture_bytes("message.received"))
        .expect("received parses")
        .data
    else {
        panic!("expected inbound")
    };
    assert_eq!(inbound.from, "ada@example.com");
    assert_eq!(inbound.to, vec!["inbox@example.com".to_owned()]);
}

/// A tampered body, another endpoint's secret, a time outside the tolerance
/// and an unsigned delivery all refuse — while the signature stays perfect.
#[test]
fn a_refused_delivery_never_parses() {
    let body = fixture_bytes("email.sent");
    let headers = signed(&body, NOW);
    let tampered = [body.as_slice(), b" "].concat();
    // (headers, secret, body, now, why) — every row must refuse.
    let refusals: &[(&HeaderMap, &str, &[u8], i64, &str)] = &[
        (&headers, SECRET, &tampered, NOW, "tampered body"),
        (&headers, "whsec_another", &body, NOW, "wrong secret"),
        (&headers, SECRET, &body, NOW - TOLERANCE - 1, "301 s stale"),
        (&headers, SECRET, &body, NOW + TOLERANCE + 1, "301 s ahead"),
        (&HeaderMap::new(), SECRET, &body, NOW, "no signature header"),
    ];
    for (headers, secret, body, now, why) in refusals {
        assert_eq!(
            parse_verified(&verifier(), secret, headers, body, *now),
            Err(WebhookError::Signature),
            "{why} must refuse"
        );
    }
    // One second inside either edge still verifies.
    for fresh in [NOW - TOLERANCE + 1, NOW + TOLERANCE - 1] {
        assert!(parse_verified(&verifier(), SECRET, &headers, &body, fresh).is_ok());
    }
}

/// The tolerance is the caller's to set — why `parse_verified` takes the
/// verifier rather than building one.
#[test]
fn a_wider_tolerance_accepts_what_the_default_refuses() {
    let body = fixture_bytes("email.sent");
    let headers = signed(&body, NOW);
    let wide = NOW - TOLERANCE - 1;
    assert_eq!(
        parse_verified(&verifier(), SECRET, &headers, &body, wide),
        Err(WebhookError::Signature)
    );
    assert!(
        parse_verified(
            &verifier().tolerance_secs(600),
            SECRET,
            &headers,
            &body,
            wide
        )
        .is_ok()
    );
}

/// A *signed* body that is not a usable envelope is the only way to reach
/// `Malformed`; an unsigned non-JSON body is `Signature`, never a parse error.
#[test]
fn only_a_verified_body_is_ever_parsed() {
    let not_json = b"this is not json";
    let not_an_envelope = br#"{"id":"evt_x"}"#;
    let bad_data =
        br#"{"id":"evt_x","type":"email.bounced","created_at":"2026-01-01T00:00:00Z","data":7}"#;
    for body in [not_json.as_slice(), not_an_envelope, bad_data] {
        let error = parse_good(body).unwrap_err();
        assert!(
            matches!(error, WebhookError::Malformed(_)),
            "a signed bad body is Malformed, got {error:?}"
        );
    }
    // The unverified non-JSON body is refused before the parse is attempted.
    assert_eq!(
        parse_verified(
            &verifier(),
            "whsec_another",
            &signed(not_json, NOW),
            not_json,
            NOW
        ),
        Err(WebhookError::Signature),
        "an unverified non-JSON body must not report a parse failure"
    );
    // Neither answer leaks the secret.
    let error = parse_good(not_json).unwrap_err();
    let rendered = format!("{error:?} {error}");
    assert!(
        !rendered.contains(SECRET),
        "the secret never appears: {rendered}"
    );
}

/// An event type this crate does not know is carried, not refused.
#[test]
fn an_unknown_type_is_carried_verbatim() {
    let body = br#"{"id":"evt_x","type":"email.teleported","created_at":"2026-01-01T00:00:00Z","data":{}}"#;
    let envelope = parse_good(body).expect("not an error");
    assert_eq!(
        envelope.data,
        OwlpostEvent::Unknown("email.teleported".to_owned())
    );
    assert_eq!(envelope.data.event_type(), "email.teleported");
    assert_eq!(
        envelope.event_type, "email.teleported",
        "the id still reaches dedup"
    );
    assert_eq!(envelope.id, "evt_x");
}

/// The event id header is read when it is there, and ignored when it is not.
#[test]
fn the_event_id_header_is_read_when_present() {
    let mut headers = HeaderMap::new();
    assert_eq!(event_id(&headers), None);
    headers.insert(EVENT_ID_HEADER, HeaderValue::from_static("evt_test_sent"));
    assert_eq!(event_id(&headers), Some("evt_test_sent"));
    // Empty is no id, and the signature header is not mistaken for one.
    headers.insert(EVENT_ID_HEADER, HeaderValue::from_static(""));
    assert_eq!(event_id(&headers), None, "an empty id is no id");
    assert_eq!(
        event_id(&sign_stripe_style(SIGNATURE_HEADER, SECRET, NOW, b"{}")),
        None
    );
    assert_eq!(event_id(&signed(b"{}", NOW)), Some("evt_test"));
}
