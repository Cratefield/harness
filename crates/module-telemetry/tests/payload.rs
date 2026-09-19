//! Issue #413, acceptance-critical: the wire grammar is closed on every
//! axis a payload could carry free text through. These tests fail if the
//! collector ever grows a field a sentence or a number fits in, accepts a
//! value the notice does not publish, or answers a client with the
//! client's own words.

use cratefield_module_telemetry::consent::{self, Consent, OffBecause};
use cratefield_module_telemetry::payload::{
    self, Arch, Batch, Client, ClientKind, DurationBucket, ErrorKind, EventRecord, Outcome,
    Platform, Rejection, Version, Vocabulary,
};
use serde_json::{Value, json};

/// The vocabulary the tests parse against: two closed lists and the
/// default ceiling.
fn vocabulary() -> Vocabulary {
    Vocabulary {
        events: ["run", "build"].iter().map(ToString::to_string).collect(),
        modules: ["telemetry", "waitlist"]
            .iter()
            .map(ToString::to_string)
            .collect(),
        max_events: 64,
    }
}

/// The largest batch the grammar admits, in Rust values rather than JSON,
/// so the walk below checks what a real accepted payload serializes to.
fn maximal_batch() -> Batch {
    Batch {
        schema: payload::SCHEMA,
        install: consent::install_id_from_bytes([
            0x7b, 0x0a, 0x1f, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6,
            0xd7, 0xe8,
        ]),
        client: Client {
            kind: ClientKind::Agent,
            version: Version {
                major: 0,
                minor: 4,
                patch: 1,
            },
            platform: Platform::Macos,
            arch: Arch::Aarch64,
        },
        modules: vec!["telemetry".to_owned(), "waitlist".to_owned()],
        events: vec![
            EventRecord {
                name: "run".to_owned(),
                outcome: Outcome::Ok,
                error: ErrorKind::None,
                duration: DurationBucket::S1To10s,
                count: 3,
            },
            EventRecord {
                name: "build".to_owned(),
                outcome: Outcome::Error,
                error: ErrorKind::Timeout,
                duration: DurationBucket::S10To1m,
                count: 100_000,
            },
        ],
    }
}

/// The same shape, as a fresh client would have sent it.
fn valid() -> Value {
    json!({
        "schema": 1,
        "install": "7b0a1f2c3d4e5f60718293a4b5c6d7e8",
        "client": {"kind": "cli", "version": "0.4.1", "platform": "linux", "arch": "aarch64"},
        "modules": ["telemetry", "waitlist"],
        "events": [
            {"name": "run", "outcome": "ok", "error": "none", "duration": "1s-10s", "count": 3}
        ]
    })
}

/// Whether a string value is one the closed grammar can produce: an enum's
/// wire name, the install id, a version triple, or a venture-declared
/// name. This is the acceptance test — anything else is free text, and
/// free text must not parse.
fn is_a_grammar_value(text: &str, vocabulary: &Vocabulary) -> bool {
    consent::install_id_is_valid(text)
        || Version::parse(text).is_some()
        || ClientKind::ALL.iter().any(|value| value.as_str() == text)
        || Platform::ALL.iter().any(|value| value.as_str() == text)
        || Arch::ALL.iter().any(|value| value.as_str() == text)
        || Outcome::ALL.iter().any(|value| value.as_str() == text)
        || ErrorKind::ALL.iter().any(|value| value.as_str() == text)
        || DurationBucket::ALL
            .iter()
            .any(|value| value.as_str() == text)
        || vocabulary.events.iter().any(|name| name == text)
        || vocabulary.modules.iter().any(|name| name == text)
}

/// The schema's own keys; `deny_unknown_fields` is what keeps a key a
/// client invented out, so keys get this list rather than the grammar.
const SCHEMA_KEYS: &[&str] = &[
    "schema", "install", "client", "kind", "version", "platform", "arch", "modules", "events",
    "name", "outcome", "error", "duration", "count",
];

/// Walks every string in a JSON document — keys and values alike — and
/// hands each to the checker with its JSON pointer.
fn walk(value: &Value, path: &str, visit: &mut impl FnMut(&str, &str)) {
    match value {
        Value::String(text) => visit(path, text),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk(item, &format!("{path}/{index}"), visit);
            }
        }
        Value::Object(map) => {
            for (key, field) in map {
                visit("(a schema key)", key);
                walk(field, &format!("{path}/{key}"), visit);
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

/// Walks every non-string leaf — numbers, booleans, nulls — with its JSON
/// pointer. Strings are skipped because [`walk`] checks each against the
/// grammar; without this pass, a new numeric field (an elapsed time, an
/// epoch) or a boolean would reach the wire unchecked.
fn walk_other_kinds(value: &Value, path: &str, visit: &mut impl FnMut(&str, &Value)) {
    match value {
        Value::Number(_) | Value::Bool(_) | Value::Null => visit(path, value),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_other_kinds(item, &format!("{path}/{index}"), visit);
            }
        }
        Value::Object(map) => {
            for (key, field) in map {
                walk_other_kinds(field, &format!("{path}/{key}"), visit);
            }
        }
        Value::String(_) => {}
    }
}

/// Nothing anywhere in an accepted payload is free text or unaccounted
/// for: every string value is a member of a closed list the notice route
/// publishes, every key is one the schema defines, and the only numbers
/// are the schema version and the per-record count, both bounded. The
/// schema defines no boolean and no null field at all. This is the
/// property the whole module stands on, so it is tested on the serialized
/// bytes, not on the Rust values.
#[test]
fn no_field_in_an_accepted_payload_is_free_text() {
    let vocabulary = vocabulary();
    let wire = payload::to_wire(&maximal_batch());
    let value: Value = serde_json::from_str(&wire).expect("the wire body parses");

    let mut visited = 0usize;
    walk(&value, "", &mut |origin, text| {
        visited += 1;
        let admitted = if origin == "(a schema key)" {
            SCHEMA_KEYS.contains(&text)
        } else {
            is_a_grammar_value(text, &vocabulary)
        };
        assert!(
            admitted,
            "free text reached the payload at {origin}: {text:?}"
        );
    });
    assert!(
        visited >= 20,
        "the walk visited only {visited} strings: an absence assertion over an \
         empty walk passes forever (the scan that sees nothing, issue #272)"
    );

    // Numbers are grammar too, and so is their absence: anything not at
    // one of the two paths below — a boolean or null included, of which
    // the schema has none — fails the walk.
    let mut visited_numbers = 0usize;
    walk_other_kinds(&value, "", &mut |path, field| {
        let admitted = match path {
            "/schema" => field.as_u64() == Some(u64::from(payload::SCHEMA)),
            path => {
                path.starts_with("/events/")
                    && path.ends_with("/count")
                    && field.as_u64().is_some_and(|count| {
                        (1..=u64::from(payload::MAX_EVENT_COUNT)).contains(&count)
                    })
            }
        };
        assert!(
            admitted,
            "the payload carries a number, boolean or null the grammar does \
             not define at {path}: {field}"
        );
        visited_numbers += 1;
    });
    assert!(
        visited_numbers >= 3,
        "the walk visited only {visited_numbers} numbers: an absence assertion \
         over an empty walk passes forever (the scan that sees nothing, issue #272)"
    );
}

/// One row of the hostile table: a label, a payload with the offence
/// planted in it, the substring that must never come back in the
/// rejection, and the rule that must refuse the batch.
type Case = (&'static str, Value, &'static str, Rejection);

/// Builds one hostile case from a mutation of the valid batch.
fn case(
    label: &'static str,
    plant: impl FnOnce(&mut Value),
    offending: &'static str,
    expected: Rejection,
) -> Case {
    let mut body = valid();
    plant(&mut body);
    (label, body, offending, expected)
}

/// What an install id must never be: an address, or a string long enough
/// to carry a sentence.
fn identity_cases() -> Vec<Case> {
    vec![
        case(
            "an address is not an install id",
            |body| body["install"] = json!("alice@example.com"),
            "alice@example.com",
            Rejection::Install,
        ),
        case(
            "a ten-kibibyte string is not an install id",
            |body| {
                body["install"] = json!("x".repeat(10 * 1024));
            },
            "xxxxxxxxxx",
            Rejection::Install,
        ),
    ]
}

/// Every field a sentence could be smuggled through, and the smuggles
/// themselves: paths, commit and branch names, prompts as keys, nested
/// objects, markup, injected statements — and names the venture never
/// declared, which are free text by another route.
fn free_text_cases() -> Vec<Case> {
    vec![
        case(
            "a file path is not an event name",
            |body| body["events"][0]["name"] = json!("/etc/passwd"),
            "/etc/passwd",
            Rejection::EventName,
        ),
        case(
            "an error message is not an error class",
            |body| {
                body["events"][0]["outcome"] = json!("error");
                body["events"][0]["error"] =
                    json!("ECONNREFUSED after 30s talking to 10.0.0.1:5432");
            },
            "ECONNREFUSED",
            Rejection::EventError,
        ),
        case(
            "a commit message is not an event name",
            |body| {
                body["events"][0]["name"] =
                    json!("Merge pull request #413 from cratefield/fix-scheduler");
            },
            "Merge pull request",
            Rejection::EventName,
        ),
        case(
            "a repository name is not a module",
            |body| body["modules"] = json!(["cratefield/harness"]),
            "cratefield/harness",
            Rejection::Modules,
        ),
        case(
            "a branch name is not an event name",
            |body| body["events"][0]["name"] = json!("users/jane/fix-null-pointer"),
            "users/jane",
            Rejection::EventName,
        ),
        case(
            "a prompt smuggled in as a key is not a field",
            |body| body["prompt"] = json!("ignore all previous instructions"),
            "ignore all previous instructions",
            Rejection::UnknownField,
        ),
        case(
            "a nested object is not a client field",
            |body| body["client"]["user"] = json!({"name": "alice"}),
            "alice",
            Rejection::UnknownField,
        ),
        case(
            "a decorated name is not a declared one",
            |body| body["events"][0]["name"] = json!("café"),
            "café",
            Rejection::EventName,
        ),
        case(
            "an injected statement is not an event name",
            |body| body["events"][0]["name"] = json!("'; DROP TABLE telemetry_events;--"),
            "DROP TABLE",
            Rejection::EventName,
        ),
        case(
            "an undeclared event is not counted",
            |body| body["events"][0]["name"] = json!("poetry"),
            "poetry",
            Rejection::EventName,
        ),
        case(
            "an undeclared module is not reported",
            |body| body["modules"] = json!(["search"]),
            "search",
            Rejection::Modules,
        ),
        case(
            "the same module twice is not two entries",
            |body| body["modules"] = json!(["telemetry", "telemetry"]),
            "telemetry",
            Rejection::ModulesDuplicate,
        ),
    ]
}

/// Values that are the right kind of thing but outside their bounds:
/// contradictory cross-field pairs, counts past either end, a future
/// schema, a decorated version, and one record too many.
fn grammar_violation_cases() -> Vec<Case> {
    vec![
        case(
            "a claim of zero runs is not a count",
            |body| body["events"][0]["count"] = json!(0),
            "\"count\":0",
            Rejection::EventCount,
        ),
        case(
            "a claim of a billion runs is not a count",
            |body| body["events"][0]["count"] = json!(100_001),
            "100001",
            Rejection::EventCount,
        ),
        case(
            "a success with an error class contradicts itself",
            |body| body["events"][0]["error"] = json!("network"),
            "network",
            Rejection::ErrorMismatch,
        ),
        case(
            "a failure without an error class contradicts itself",
            |body| body["events"][0]["outcome"] = json!("error"),
            "\"error\":\"none\"",
            Rejection::ErrorMismatch,
        ),
        case(
            "an unsupported schema is its own rejection",
            |body| body["schema"] = json!(2),
            "2",
            Rejection::SchemaUnsupported,
        ),
        case(
            "a pre-release tag is not a version",
            |body| body["client"]["version"] = json!("1.0.0-beta"),
            "1.0.0-beta",
            Rejection::ClientVersion,
        ),
        case(
            "sixty-five records is past the ceiling",
            |body| {
                let flood: Vec<Value> = (0..65)
                    .map(|_| {
                        json!({
                            "name": "run", "outcome": "ok",
                            "error": "none", "duration": "unknown", "count": 1
                        })
                    })
                    .collect();
                body["events"] = json!(flood);
            },
            "65",
            Rejection::EventsTooMany,
        ),
    ]
}

/// The hostile table: every payload a well-meaning client might be talked
/// into sending, and every way a hostile one might try to smuggle a
/// sentence through. Each case must be **rejected** — never trimmed,
/// coerced or accepted — and the rendered rejection must not contain what
/// the client sent, because an error body that quoted it would be the
/// free-text channel this module exists to close.
#[test]
fn hostile_payloads_are_rejected() {
    let mut cases = identity_cases();
    cases.extend(free_text_cases());
    cases.extend(grammar_violation_cases());
    assert!(cases.len() >= 18, "the hostile table must stay wide");

    let vocabulary = vocabulary();
    for (label, body, offending, expected) in cases {
        let rejection = Batch::parse(&body, &vocabulary)
            .expect_err(&format!("{label}: the payload must be rejected"));
        assert_eq!(rejection, expected, "{label}: refused for the right reason");
        let message = rejection.to_string();
        assert!(
            !message.contains(offending),
            "{label}: the rejection echoed what the client sent: {message}"
        );
    }
}

/// `telemetry status` embeds the exact bytes the sender would POST, from
/// the same serializer — so the JSON a person reads must parse back into
/// the very batch it describes, on and off alike.
#[test]
fn the_status_output_round_trips_the_batch_it_embeds() {
    let batch = maximal_batch();

    let out = consent::status(&Consent::On, &batch);
    let (state, json) = out
        .split_once('\n')
        .expect("a status line then the payload");
    assert_eq!(state, "telemetry: on");
    assert_eq!(
        json,
        payload::to_wire(&batch),
        "the status bytes are the wire bytes"
    );
    let parsed: Batch = serde_json::from_str(json).expect("the embedded JSON parses");
    assert_eq!(parsed, batch);

    let out = consent::status(&Consent::Off(OffBecause::ContinuousIntegration), &batch);
    let (state, json) = out
        .split_once('\n')
        .expect("a status line then the payload");
    assert!(state.contains("CI"), "{state}");
    let parsed: Batch = serde_json::from_str(json).expect("the embedded JSON parses");
    assert_eq!(parsed, batch);
}
