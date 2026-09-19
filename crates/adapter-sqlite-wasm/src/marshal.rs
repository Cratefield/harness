//! The sea-query <-> JSON marshalling for the sqlite-wasm bridge.
//!
//! Scalar values match `cratefield-runtime-cloudflare`'s D1 adapter exactly
//! (the ADR 0004 portable subset round-trips identically). BLOBs intentionally
//! do **not** share D1's wire encoding: the D1 bridge receives real binary
//! arrays, while this bridge's only crossing into JS is a JSON string (see
//! `imp.rs`), so a blob needs a textual tag. [`sea_to_json`] encodes
//! [`SeaValue::Bytes`] as `{"$bytes": "<base64>"}` and [`json_to_sea`] decodes
//! exactly that shape back; the JS bridge (`crates/runtime-browser/web/
//! sqlite_bridge.js`) converts the tag to/from `Uint8Array` at the sqlite
//! boundary. Both adapters agree on the Rust-level outcome —
//! `SeaValue::Bytes` in, `SeaValue::Bytes` out — not on the wire bytes.
//!
//! A TEXT value that merely *looks* like the tag is never decoded as bytes:
//! the tag only matches a JSON **object** with exactly one `$bytes` key whose
//! value is valid canonical base64 (padding required, no nonzero trailing
//! bits). Anything else — including a tag-shaped object with invalid base64
//! or extra keys — falls through to the ordinary JSON-object handling.
//!
//! This module is deliberately **not** gated on `wasm32` (unlike the rest of
//! the crate): the marshalling is pure, so it is unit-tested on the host with
//! plain `cargo test -p cratefield-adapter-sqlite-wasm`, which no other module
//! here allows. It is a `pub` module because on native targets the wasm-only
//! modules do not exist to call it, and a private module of uncalled functions
//! is dead code there.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sea_query::Value as SeaValue;
use serde_json::Value as Json;

/// The single object key that marks an encoded BLOB: `{"$bytes": "<base64>"}`.
const BYTES_TAG: &str = "$bytes";

/// Encodes `bytes` as the tagged blob object `{"$bytes": "<base64>"}` —
/// standard (padded) base64, the same alphabet the JS bridge decodes with
/// `atob`.
#[must_use]
fn bytes_to_json(bytes: &[u8]) -> Json {
    let mut map = serde_json::Map::with_capacity(1);
    map.insert(BYTES_TAG.to_owned(), Json::String(BASE64.encode(bytes)));
    Json::Object(map)
}

/// Decodes `value` if it is exactly the tagged blob `{"$bytes": "<base64>"}`:
/// a single-key object whose value is a string of valid canonical base64.
/// Everything else is [`None`], leaving the caller to treat the value as an
/// ordinary JSON object — that fall-through is what keeps a TEXT value that
/// merely looks like the tag from being silently read as bytes.
fn tagged_bytes(value: &Json) -> Option<Vec<u8>> {
    let Json::Object(map) = value else {
        return None;
    };
    if map.len() != 1 {
        return None;
    }
    let Json::String(encoded) = map.get(BYTES_TAG)? else {
        return None;
    };
    // `STANDARD` requires canonical padding and rejects nonzero trailing
    // bits, so malformed input errors rather than decoding to wrong bytes.
    BASE64.decode(encoded.as_bytes()).ok()
}

/// Marshals a sea-query value to the JSON form that crosses the bridge.
#[must_use]
pub fn sea_to_json(value: &SeaValue) -> Json {
    match value {
        SeaValue::Bool(Some(v)) => Json::Bool(*v),
        SeaValue::TinyInt(Some(v)) => (*v).into(),
        SeaValue::SmallInt(Some(v)) => (*v).into(),
        SeaValue::Int(Some(v)) => (*v).into(),
        SeaValue::BigInt(Some(v)) => (*v).into(),
        SeaValue::TinyUnsigned(Some(v)) => (*v).into(),
        SeaValue::SmallUnsigned(Some(v)) => (*v).into(),
        SeaValue::Unsigned(Some(v)) => (*v).into(),
        SeaValue::BigUnsigned(Some(v)) => (*v).into(),
        SeaValue::Float(Some(v)) => f64::from(*v).into(),
        SeaValue::Double(Some(v)) => (*v).into(),
        SeaValue::String(Some(v)) => v.as_str().into(),
        SeaValue::Char(Some(v)) => v.to_string().into(),
        SeaValue::Bytes(Some(bytes)) => bytes_to_json(bytes),
        // An absent blob is SQL NULL, like every other absent value.
        _ => Json::Null,
    }
}

/// Marshals a JSON value from the bridge back to a sea-query value.
#[must_use]
pub fn json_to_sea(value: &Json) -> SeaValue {
    // The tagged-blob check must precede the `Json::Object(_)` arm below,
    // which stringifies ordinary JSON objects.
    if let Some(bytes) = tagged_bytes(value) {
        return SeaValue::Bytes(Some(Box::new(bytes)));
    }
    match value {
        Json::Null => SeaValue::String(None),
        Json::Bool(v) => SeaValue::Bool(Some(*v)),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                SeaValue::BigInt(Some(i))
            } else {
                SeaValue::Double(Some(n.as_f64().unwrap_or_default()))
            }
        }
        Json::String(s) => SeaValue::String(Some(Box::new(s.clone()))),
        Json::Array(_) | Json::Object(_) => SeaValue::String(Some(Box::from(value.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(bytes: &[u8]) -> SeaValue {
        let value = SeaValue::Bytes(Some(Box::new(bytes.to_vec())));
        json_to_sea(&sea_to_json(&value))
    }

    #[test]
    fn blob_with_nul_and_invalid_utf8_round_trips() {
        // 0x80/0xFE are never valid UTF-8 single bytes: encoding the payload
        // as a JSON string would be lossy, which is why the tag exists.
        let bytes = [0x00, 0xFF, 0x80, 0xFE, 0x00, 0x41];
        let json = sea_to_json(&SeaValue::Bytes(Some(Box::new(bytes.to_vec()))));
        assert_eq!(
            json,
            serde_json::json!({ "$bytes": "AP+A/gBB" }),
            "the wire form is the tagged object, not a string"
        );
        assert_eq!(
            json_to_sea(&json),
            SeaValue::Bytes(Some(Box::new(bytes.to_vec())))
        );
    }

    #[test]
    fn every_base64_padding_case_round_trips() {
        // Prefixes hit len % 3 == 0 (0, 3, 6), == 1 (1, 4) and == 2 (2, 5);
        // len 0 is the empty slice.
        let payload = [0xFF, 0x80, 0x00, 0x7F, 0xFE, 0x01];
        let encoded = [
            "", "/w==", "/4A=", "/4AA", "/4AAfw==", "/4AAf/4=", "/4AAf/4B",
        ];
        for (len, want) in encoded.iter().enumerate() {
            let bytes = &payload[..len];
            let json = sea_to_json(&SeaValue::Bytes(Some(Box::new(bytes.to_vec()))));
            assert_eq!(
                json.get(BYTES_TAG).and_then(Json::as_str),
                Some(*want),
                "wrong encoding at len {len}"
            );
            assert_eq!(
                round_trip(bytes),
                SeaValue::Bytes(Some(Box::new(bytes.to_vec())))
            );
        }
    }

    #[test]
    fn tagged_text_stays_text() {
        // A TEXT column holding the literal tag is a JSON *string* from the
        // bridge, and strings are never decoded as bytes.
        let text = r#"{"$bytes":"AAAA"}"#;
        assert_eq!(
            json_to_sea(&Json::String(text.to_owned())),
            SeaValue::String(Some(Box::new(text.to_owned())))
        );
    }

    #[test]
    fn near_miss_tag_objects_stay_objects() {
        // Only the exact tagged shape decodes as bytes: extra keys, a
        // non-string payload and invalid base64 all fall through to the
        // ordinary object handling (stringified, losslessly preserved).
        let cases = [
            r#"{"$bytes":"AAAA","n":1}"#,    // extra key
            r#"{"$bytes":42}"#,              // non-string payload
            r#"{"$bytes":"not base64!!!"}"#, // invalid base64
            r#"{"$bytes":"AAA"}"#,           // missing padding (canonical required)
            r#"{"$bytes":"AAB="}"#,          // nonzero trailing bits
        ];
        for case in cases {
            let json: Json = serde_json::from_str(case).expect("test case is valid JSON");
            assert_eq!(
                json_to_sea(&json),
                SeaValue::String(Some(Box::new(case.to_owned()))),
                "near-miss tag must not decode as bytes: {case}"
            );
        }
    }

    #[test]
    fn absent_blob_is_null() {
        assert_eq!(sea_to_json(&SeaValue::Bytes(None)), Json::Null);
        // And SQL NULL comes back absent — the pre-existing shape.
        assert_eq!(json_to_sea(&Json::Null), SeaValue::String(None));
    }

    #[test]
    fn scalars_still_round_trip_through_the_bridge_form() {
        // The bytes fix must not disturb the ADR 0004 portable subset.
        let cases: Vec<SeaValue> = vec![
            SeaValue::Bool(Some(true)),
            SeaValue::BigInt(Some(-7)),
            SeaValue::Double(Some(1.5)),
            SeaValue::String(Some(Box::new("plain".to_owned()))),
        ];
        for value in &cases {
            let json = sea_to_json(value);
            assert_ne!(json, Json::Null, "scalar dropped to NULL: {value:?}");
            assert_eq!(json_to_sea(&json), *value);
        }
        // JSON numbers carry no signedness, so a `BigUnsigned` that fits i64
        // comes back as `BigInt` — the pre-existing read shape, unchanged.
        let json = sea_to_json(&SeaValue::BigUnsigned(Some(9)));
        assert_eq!(json, Json::from(9u64));
        assert_eq!(json_to_sea(&json), SeaValue::BigInt(Some(9)));
    }
}
