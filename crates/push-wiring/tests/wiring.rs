//! The wiring contract (issue #191): which transports a venture's
//! environment configures, which it half-configures, and what the assembled
//! router then answers.
//!
//! The routing assertions all turn on one distinction: an unrouted transport
//! answers `Ok(PushOutcome::NotConfigured)` without touching anything, and a
//! routed one *attempts* the send. These tests hand the adapters an HTTP
//! client that refuses every request, so "attempted" surfaces as a
//! `PushError` — which is exactly the evidence that the transport was
//! routed.

use std::sync::Arc;

use bytes::Bytes;
use cratefield_core::{
    Clock, Config, HttpClient, HttpError, MapConfig, Notification, Platform, Push, PushOutcome,
    Recipient, SystemClock, VentureEnv,
};
use cratefield_push_wiring::{
    PUSH_ENV, PushWiring, TRANSPORTS, TransportWiring, WiringSeverity, build_push, inspect_push,
    notifications_doc, transport_key, vars_for,
};

// ---------------------------------------------------------------------------
// Fixtures

/// A throwaway P-256 key, generated for the adapter tests only — NOT an
/// Apple key. The same one `crates/adapter-apns/tests/apns.rs` uses.
const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n-----END PRIVATE KEY-----";

/// A throwaway RSA key, generated for the adapter tests only — NOT a Google
/// key. The same one `crates/adapter-fcm/tests/fcm.rs` uses.
const TEST_RSA: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCgQ/qAORkSKZjW
xMCbrhGXqbVCHpslcKpb3Ew/5qpRclIDXmJcaXehqY4swKuYdyqcQloRH5inZ/6U
DR/p72s+6Gu5ExAje64hw2AChozIdmKA/xZYxPjQ5AtFXLofTglg1VeudH+6/bDw
sXKGsaqRPWghb0lc1cai0ETHZDfP9frfJKjJRm2HlZqp8CKwwl1Jy6CQOGrjKlQX
ThV07JKPpRPTZFscZTMzjG9fIfYCcxWt7c7HcPN4G7QUrx4oEX/jkuJcA2zgQ0WL
0gJ4IKUc1BiNDP67UniFq8bxlcqePQc8MN3bBDrPKktX24u9ZJJZjx6otgBIWCaB
nIKyuyfzAgMBAAECggEAS0Af+tzUfMazUQSJO4/8Cq5QwX8Fcgr4srE5zDdOeXeo
MpS6spGC7pFihHjjGW+6viwZhjjDwLb/vhx7g6g7Pwp6qifdSAvms0u9ZPIwYF/V
2KPtpji2a77n2+WyLsjBdoo15WAmKXK9BgcLs1rwr8mZfzl1xPVLk18fLFBONIKY
ySiiGRQC2NZXfAEZF/pDMaBT5+my7hjZkw07XMrV//DnR71Gre2IPj0SNPWjS+Fd
qMQq5UvxaJxLP6dDswYqXNvoWC7YAlsnf9ySD3ykLThATh4yUCL6y97wvKEdU9yb
1mruLpOGNCnjCDqx+spY49qt+3uWBcj2BXjAPUlQoQKBgQDPOLZSz772jquTiyk0
4OiUkCofmhLdpKU/vJW6TWGjGWv3MSUvi1wA5q/AByljCtr+/lwzkj1c9/6Hzo0N
zv0kagaVRmb5INhTEu+1957lBP/WucHOvKPhiUvLjiH0YTqFSl+uB5ZbzbIxMOko
T86cq9/qFkOl3BhR8CFoRWwbbwKBgQDF/avnjCFOEVzluU+FnNepR36mZWlhQPNt
xT/wlavbPVQbIYbUJ4vKaU2OjIRE0fPJiC/XXEdD74LeX3gfoufau/M3hSmUDLoq
DZCng5zGKtOlPMLQkf0Q2xVesM5eCJ2dPWZDR8jgkoXaLRa1YIFUofl24AkeabqO
u56pgEwJvQKBgAaN+65o5dh0sNas6zPB/XldigeP3xLlt1hpxa6r7e+zySd7hXqY
hON+aIbBczyvxjeUoiP7dzdunL18+hc6ueUh+W1VWcJ9mHogOjbeS0dhPhpzq763
VtO2fRBGQaqyPKCktpwRn17uBbnqmyVsSNPJ1/5Wj/M6IAbPeq8Kqx2/AoGAPy6u
lxu+3RzpWl4CpI7iu6CXKB6gvGpvxI3305zP1Q0DNA1E65sbHyLvnxf0dcnSVHPj
YISQMXvTdYdd3Cqudr0X5pXWKOrO1fCyQuLbOtob5FU5jjmoWqKvdSJTGOsC8VTQ
t5PG5POdR3ywDH2ZiBqQc4EXJ99xq27wOQM6QLkCgYB9f9GrE+DQIYBzb7hf1SMz
ELvz+3ijy43njvIg4CihiUAzIuc0VJaVCKZcxIMZxLoDB6roeLoYBS+GhVrMoHUj
mbv4voW/HXdaIlZUbMa0y9q0cg3Q8oaw5bwSzrSZxEkadudn4+MFKbLRvmYFX7We
6OmL9MfIa/kocbiIIu0TSA==
-----END PRIVATE KEY-----";

fn service_account_json() -> String {
    format!(
        "{{\"type\":\"service_account\",\"project_id\":\"demo-project\",\
         \"private_key\":{},\"client_email\":\"pusher@demo-project.iam.gserviceaccount.com\",\
         \"token_uri\":\"https://oauth2.googleapis.com/token\"}}",
        serde_json_string(TEST_RSA)
    )
}

/// A JSON string literal, without pulling `serde_json` in as a dev
/// dependency for one call.
fn serde_json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn config(pairs: &[(&str, &str)]) -> MapConfig {
    MapConfig::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    )
}

fn full_apns() -> Vec<(&'static str, String)> {
    vec![
        ("APNS_KEY_P8", TEST_P8.to_owned()),
        ("APNS_KEY_ID", "ABCDE12345".to_owned()),
        ("APNS_TEAM_ID", "TEAM123456".to_owned()),
        ("APNS_TOPIC", "ventures.factory0.example".to_owned()),
        ("APNS_HOST", "production".to_owned()),
    ]
}

fn owned(pairs: Vec<(&'static str, String)>) -> MapConfig {
    MapConfig::from_pairs(pairs)
}

/// Refuses every request, so a routed adapter's send fails loudly rather
/// than silently answering `NotConfigured`.
struct NoNetwork;

#[async_trait::async_trait]
impl HttpClient for NoNetwork {
    async fn send(
        &self,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        Err(HttpError::Transport("no network in tests".to_owned()))
    }
}

fn assemble(config: &dyn Config) -> (Arc<dyn Push>, PushWiring) {
    let http: Arc<dyn HttpClient> = Arc::new(NoNetwork);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    build_push(config, &http, &clock)
}

/// One recipient per transport.
fn recipients() -> Vec<(Platform, Recipient)> {
    vec![
        (Platform::Ios, Recipient::apns("device-token")),
        (Platform::Android, Recipient::fcm("registration-token")),
        (
            Platform::Web,
            Recipient::web_push(
                "https://push.example.test/subscription/abc",
                "BLc4xRzKlKORKWlbdgFaBrrPK3ydWAHo4M0gs0i1oEKgPpWG1KH0hOA5eVJs\
                 kzWCu5o9YJ3ZFhAqIzSEsRaqQFA",
                "aUFhbWJhc2FkZTEyMzQ1Ng",
            ),
        ),
    ]
}

/// Whether the router even tried: `NotConfigured` means the transport is
/// not routed at all, anything else means an adapter took the send.
fn routed(push: &Arc<dyn Push>, recipient: &Recipient) -> bool {
    let notification = Notification::new("title", "body");
    let outcome = pollster::block_on(push.send(recipient, &notification));
    !matches!(outcome, Ok(PushOutcome::NotConfigured))
}

// ---------------------------------------------------------------------------
// Nothing configured

#[test]
fn with_nothing_configured_every_transport_is_absent() {
    let wiring = inspect_push(&config(&[]));
    for transport in TRANSPORTS {
        assert_eq!(
            wiring.get(transport),
            &TransportWiring::Absent,
            "{}",
            transport_key(transport)
        );
    }
    assert!(wiring.problems().is_empty(), "{:?}", wiring.problems());
    // Absent is a choice, not a defect — even in production.
    assert_eq!(
        wiring.severity(VentureEnv::Production),
        WiringSeverity::Ok,
        "{}",
        wiring.summary()
    );
    assert!(wiring.check(VentureEnv::Production).is_ok());
}

#[test]
fn with_nothing_configured_every_recipient_variant_is_not_configured() {
    // The acceptance criterion the `wrangler dev` smoke exercises: an empty
    // router must answer, not panic, for every variant of `Recipient`.
    let (push, _) = assemble(&config(&[]));
    let notification = Notification::new("title", "body");
    for (transport, recipient) in recipients() {
        let outcome = pollster::block_on(push.send(&recipient, &notification));
        assert_eq!(
            outcome.expect("an unconfigured transport is an outcome, not an error"),
            PushOutcome::NotConfigured,
            "{}",
            transport_key(transport)
        );
    }
}

// ---------------------------------------------------------------------------
// Full configuration

#[test]
fn a_fully_configured_transport_is_configured_and_routed() {
    let mut pairs = full_apns();
    pairs.push(("FCM_SERVICE_ACCOUNT_JSON", service_account_json()));
    pairs.push(("VAPID_PRIVATE_KEY", TEST_P8.to_owned()));
    pairs.push(("VAPID_SUBJECT", "mailto:ops@example.test".to_owned()));

    let (push, wiring) = assemble(&owned(pairs));
    for transport in TRANSPORTS {
        assert_eq!(
            wiring.get(transport),
            &TransportWiring::Configured,
            "{}: {}",
            transport_key(transport),
            wiring.summary()
        );
    }
    assert!(wiring.problems().is_empty(), "{:?}", wiring.problems());
    for (transport, recipient) in recipients() {
        assert!(
            routed(&push, &recipient),
            "{} answered NotConfigured although it is configured",
            transport_key(transport)
        );
    }
}

#[test]
fn apns_host_is_optional_and_defaults_without_becoming_partial() {
    // Four of the five variables is a complete APNs configuration: the fifth
    // has a documented default. Reporting that as `partial` would make the
    // documented default unusable.
    let pairs: Vec<_> = full_apns()
        .into_iter()
        .filter(|(name, _)| *name != "APNS_HOST")
        .collect();
    let wiring = inspect_push(&owned(pairs));
    assert_eq!(wiring.get(Platform::Ios), &TransportWiring::Configured);
}

// ---------------------------------------------------------------------------
// Partial configuration — the case this exists for

#[test]
fn a_missing_variable_is_partial_and_names_both_halves() {
    // The typo case: the operator set the secret and mistyped one of the
    // plain variables, so it never arrived.
    let pairs: Vec<_> = full_apns()
        .into_iter()
        .filter(|(name, _)| *name != "APNS_TEAM_ID")
        .collect();
    let wiring = inspect_push(&owned(pairs));

    let TransportWiring::Partial { present, missing } = wiring.get(Platform::Ios) else {
        panic!("expected partial, got {:?}", wiring.get(Platform::Ios));
    };
    assert_eq!(missing, &["APNS_TEAM_ID"]);
    assert!(present.contains(&"APNS_KEY_P8"), "{present:?}");
    assert!(present.contains(&"APNS_KEY_ID"), "{present:?}");
}

#[test]
fn a_partial_transport_is_not_routed() {
    // The whole point: half a configuration must not become an adapter that
    // fails on every send, nor a silent `NotConfigured` nobody is told
    // about. It stays unrouted *and* it is reported.
    let pairs: Vec<_> = full_apns()
        .into_iter()
        .filter(|(name, _)| *name != "APNS_TOPIC")
        .collect();
    let (push, wiring) = assemble(&owned(pairs));
    assert!(!routed(&push, &Recipient::apns("device-token")));
    assert!(wiring.get(Platform::Ios).is_problem());
}

#[test]
fn an_optional_variable_alone_is_still_partial() {
    // `APNS_HOST` on its own has no required variables with it, but setting
    // it is an unambiguous statement of intent: somebody meant to wire APNs.
    let wiring = inspect_push(&config(&[("APNS_HOST", "production")]));
    let TransportWiring::Partial { present, missing } = wiring.get(Platform::Ios) else {
        panic!("expected partial, got {:?}", wiring.get(Platform::Ios));
    };
    assert_eq!(present, &["APNS_HOST"]);
    assert_eq!(
        missing,
        &["APNS_KEY_P8", "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC"]
    );
}

#[test]
fn partial_is_an_error_in_production_and_a_warning_below_it() {
    let wiring = inspect_push(&config(&[("VAPID_PRIVATE_KEY", TEST_P8)]));
    assert!(wiring.get(Platform::Web).is_problem(), "{wiring:?}");

    assert_eq!(
        wiring.severity(VentureEnv::Production),
        WiringSeverity::Error
    );
    assert_eq!(
        wiring.severity(VentureEnv::Staging),
        WiringSeverity::Warning
    );
    assert_eq!(
        wiring.severity(VentureEnv::Development),
        WiringSeverity::Warning
    );

    let error = wiring
        .check(VentureEnv::Production)
        .expect_err("production must refuse a half-wired transport");
    assert!(error.contains("VAPID_SUBJECT"), "{error}");
    assert!(
        wiring.check(VentureEnv::Development).is_ok(),
        "wiring a transport one variable at a time is what development is"
    );
}

#[test]
fn a_blank_value_counts_as_unset() {
    // An empty Workers secret and an unset one mean the same thing to an
    // operator; treating `""` as configured would hand the adapter a
    // credential it must then refuse, and report `invalid` for what is
    // really `partial`.
    let mut pairs = full_apns();
    for pair in &mut pairs {
        if pair.0 == "APNS_KEY_ID" {
            pair.1 = "   ".to_owned();
        }
    }
    let wiring = inspect_push(&owned(pairs));
    let TransportWiring::Partial { missing, .. } = wiring.get(Platform::Ios) else {
        panic!("expected partial, got {:?}", wiring.get(Platform::Ios));
    };
    assert_eq!(missing, &["APNS_KEY_ID"]);
}

// ---------------------------------------------------------------------------
// Invalid configuration

#[test]
fn credentials_the_adapter_refuses_are_invalid_and_not_routed() {
    let mut pairs = full_apns();
    for pair in &mut pairs {
        if pair.0 == "APNS_KEY_P8" {
            pair.1 = "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----".to_owned();
        }
    }
    let (push, wiring) = assemble(&owned(pairs));
    assert!(
        matches!(wiring.get(Platform::Ios), TransportWiring::Invalid { .. }),
        "{:?}",
        wiring.get(Platform::Ios)
    );
    assert!(!routed(&push, &Recipient::apns("device-token")));
    assert_eq!(
        wiring.severity(VentureEnv::Production),
        WiringSeverity::Error
    );
}

#[test]
fn a_mistyped_apns_host_is_invalid_rather_than_a_silent_default() {
    // Defaulting a typo to the sandbox is how every production send comes
    // back `BadDeviceToken` with nothing in the logs to explain it.
    let mut pairs = full_apns();
    for pair in &mut pairs {
        if pair.0 == "APNS_HOST" {
            pair.1 = "produciton".to_owned();
        }
    }
    let wiring = inspect_push(&owned(pairs));
    let TransportWiring::Invalid { reason } = wiring.get(Platform::Ios) else {
        panic!("expected invalid, got {:?}", wiring.get(Platform::Ios));
    };
    assert!(reason.contains("produciton"), "{reason}");
    assert!(reason.contains("APNS_HOST"), "{reason}");
}

#[test]
fn a_service_account_that_is_not_json_is_invalid() {
    let wiring = inspect_push(&config(&[("FCM_SERVICE_ACCOUNT_JSON", "{not json")]));
    assert!(
        matches!(
            wiring.get(Platform::Android),
            TransportWiring::Invalid { .. }
        ),
        "{:?}",
        wiring.get(Platform::Android)
    );
}

// ---------------------------------------------------------------------------
// The report never carries a value

#[test]
fn the_report_names_variables_and_never_prints_a_value() {
    // Every secret in the table gets a distinctive, deliberately invalid
    // value, so both the summary and the problem list are built from the
    // worst case: the adapter refused and had something to say about it.
    let marker = "SUPERSECRETMATERIALc0ffee";
    let pairs = vec![
        (
            "APNS_KEY_P8",
            format!("-----BEGIN PRIVATE KEY-----\n{marker}\n-----END PRIVATE KEY-----"),
        ),
        ("APNS_KEY_ID", "ABCDE12345".to_owned()),
        ("APNS_TEAM_ID", "TEAM123456".to_owned()),
        ("APNS_TOPIC", "ventures.factory0.example".to_owned()),
        (
            "FCM_SERVICE_ACCOUNT_JSON",
            format!("{{\"private_key\":\"{marker}\"}}"),
        ),
        ("VAPID_PRIVATE_KEY", marker.to_owned()),
        ("VAPID_SUBJECT", "mailto:ops@example.test".to_owned()),
    ];
    let wiring = inspect_push(&owned(pairs));

    let printed = format!(
        "{}\n{}\n{wiring:?}",
        wiring.summary(),
        wiring.problems().join("\n")
    );
    assert!(
        !printed.contains(marker),
        "the report leaked a secret value: {printed}"
    );
    // And it is not vacuous: it did report on all three.
    for transport in TRANSPORTS {
        assert!(
            printed.contains(transport_key(transport)),
            "{} is missing from the report: {printed}",
            transport_key(transport)
        );
    }
}

#[test]
fn the_summary_names_every_variable_of_a_partial_transport() {
    let wiring = inspect_push(&config(&[("APNS_KEY_P8", TEST_P8)]));
    let summary = wiring.summary();
    assert!(summary.contains("apns=partial"), "{summary}");
    for var in vars_for(Platform::Ios).filter(|var| var.required) {
        assert!(
            summary.contains(var.name),
            "{} missing: {summary}",
            var.name
        );
    }
}

// ---------------------------------------------------------------------------
// The generated document

#[test]
fn the_generated_doc_covers_every_variable_in_the_table() {
    let doc = notifications_doc();
    for var in PUSH_ENV {
        assert!(doc.contains(var.name), "{} is not in the doc", var.name);
    }
    for transport in TRANSPORTS {
        assert!(doc.contains(transport_key(transport)), "{doc}");
    }
}

#[test]
fn the_checked_in_doc_has_no_drift() {
    // The same check CI runs, so a table change that forgets the doc fails
    // here first rather than in the pipeline.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/PUSH-ENV.md");
    let current = std::fs::read_to_string(&path).expect("docs/PUSH-ENV.md exists");
    assert_eq!(
        current,
        notifications_doc(),
        "docs/PUSH-ENV.md is stale; regenerate with `cargo run -p \
         cratefield-push-wiring --example push-env-doc`"
    );
}
