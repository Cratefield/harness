//! `HmacSigner` acceptance tests (issue #3, ADR 0006).

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use cratefield_core::{HmacSigner, Kid, Payload, Signer, SignerError};

// Obvious dummy secrets, never real.
const SECRET_CUR: &str = "test-secret-current-0123456789abcdef";
const SECRET_NEW: &str = "test-secret-rotated---0123456789abcdef";

fn signer() -> HmacSigner {
    HmacSigner::new(SECRET_CUR, None).expect("test signer")
}

fn payload(purpose: &str) -> Payload {
    Payload {
        purpose: purpose.to_string(),
        subject: "nick@example.com".to_string(),
        exp: Some(
            (time::OffsetDateTime::now_utc().unix_timestamp() + 3600)
                .max(0)
                .cast_unsigned(),
        ),
        kid: Kid::Cur,
    }
}

#[test]
fn round_trip() {
    let signer = signer();
    let token = signer.sign(&payload("confirm"));
    let verified = signer
        .verify(&token, "confirm")
        .expect("round trip verifies");
    assert_eq!(verified.subject, "nick@example.com");
    assert_eq!(verified.purpose, "confirm");
    assert_eq!(verified.kid, Kid::Cur);
    assert!(verified.exp.is_some());
}

#[test]
fn tampered_payload_is_rejected() {
    let signer = signer();
    let token = signer.sign(&payload("confirm"));
    let (encoded, mac) = token.split_once('.').expect("token splits");
    let mut bytes = URL_SAFE_NO_PAD.decode(encoded).expect("payload decodes");
    // Flip a character in the subject.
    let mut json = String::from_utf8(bytes.clone()).expect("utf8");
    let subject_at = json.find("nick@").expect("subject present");
    json.replace_range(subject_at..=subject_at, "r");
    bytes = json.into_bytes();
    let tampered = format!("{}.{}", URL_SAFE_NO_PAD.encode(bytes), mac);
    assert!(signer.verify(&tampered, "confirm").is_none());
}

#[test]
fn tampered_mac_is_rejected() {
    let signer = signer();
    let token = signer.sign(&payload("confirm"));
    let (encoded, mac) = token.split_once('.').expect("token splits");
    let mut mac_bytes = URL_SAFE_NO_PAD.decode(mac).expect("mac decodes");
    mac_bytes[0] ^= 0x01;
    let tampered = format!("{}.{}", encoded, URL_SAFE_NO_PAD.encode(mac_bytes));
    assert!(signer.verify(&tampered, "confirm").is_none());
}

#[test]
fn expired_token_is_rejected() {
    let signer = signer();
    let mut p = payload("confirm");
    p.exp = Some(
        time::OffsetDateTime::now_utc()
            .unix_timestamp()
            .max(0)
            .cast_unsigned(),
    );
    let token = signer.sign(&p);
    assert!(signer.verify(&token, "confirm").is_none());
}

#[test]
fn wrong_purpose_is_rejected() {
    let signer = signer();
    let token = signer.sign(&payload("confirm"));
    assert!(signer.verify(&token, "unsubscribe").is_none());
}

#[test]
fn rotation_via_previous_secret() {
    // Before rotation: the old signer signs with kid=cur.
    let old = HmacSigner::new(SECRET_CUR, None).expect("old signer");
    let token = old.sign(&payload("confirm"));

    // After rotation: cur is new, prev is old. Tokens signed with the old
    // secret must keep verifying (named key fails, fallback prev passes).
    let wrong_prev = HmacSigner::new(
        SECRET_NEW,
        Some("test-secret-wrong----0123456789abcdef".to_string()),
    )
    .expect("signer");
    assert!(
        wrong_prev.verify(&token, "confirm").is_none(),
        "a different old secret must not verify"
    );

    let actual_rotated =
        HmacSigner::new(SECRET_NEW, Some(SECRET_CUR.to_string())).expect("rotated");
    let verified = actual_rotated
        .verify(&token, "confirm")
        .expect("rotated signer accepts old-secret token via prev");
    assert_eq!(verified.kid, Kid::Cur);

    // New tokens signed by the rotated signer verify as cur.
    let fresh = actual_rotated.sign(&payload("confirm"));
    assert!(actual_rotated.verify(&fresh, "confirm").is_some());
    // ...and still verify on a signer that only knows the new secret.
    let only_new = HmacSigner::new(SECRET_NEW, None).expect("only new");
    assert!(only_new.verify(&fresh, "confirm").is_some());
}

#[test]
fn malformed_input_never_panics() {
    let signer = signer();
    for bad in [
        "",
        ".",
        "..",
        "a.b",
        "a.b.c",
        "!!!.???",
        "aaaa.////",
        "\u{0}\u{1}.x",
        "eyJraWQiOiJjdXIifQ.not-base64!!",
    ] {
        assert!(signer.verify(bad, "confirm").is_none(), "input {bad:?}");
    }
}

#[test]
fn reencoded_payload_with_padding_is_rejected() {
    let signer = signer();
    let token = signer.sign(&payload("confirm"));
    let (encoded, mac) = token.split_once('.').expect("token splits");

    // Re-encode the same JSON with padded base64 and re-encode the ORIGINAL
    // MAC: the MAC was computed over the unpadded encoding, so the padded
    // variant must fail (one valid encoding per token, ADR 0006).
    let raw = URL_SAFE_NO_PAD.decode(encoded).expect("decodes");
    let padded_payload = URL_SAFE.encode(raw);
    let mac_bytes = URL_SAFE_NO_PAD.decode(mac).expect("mac decodes");
    let padded = format!("{}.{}", padded_payload, URL_SAFE_NO_PAD.encode(mac_bytes));
    assert!(signer.verify(&padded, "confirm").is_none());

    // Appending padding to the original payload part is also rejected.
    let with_eq = format!("{encoded}=.{mac}");
    assert!(signer.verify(&with_eq, "confirm").is_none());
}

#[test]
fn short_secret_is_rejected() {
    assert_eq!(
        HmacSigner::new("too-short", None).unwrap_err(),
        SignerError::SecretTooShort
    );
}

#[test]
fn unsubscribe_tokens_do_not_expire() {
    let signer = signer();
    let p = Payload {
        purpose: "unsubscribe".to_string(),
        subject: "nick@example.com".to_string(),
        exp: None,
        kid: Kid::Cur,
    };
    let token = signer.sign(&p);
    let verified = signer
        .verify(&token, "unsubscribe")
        .expect("no-expiry token verifies");
    assert!(verified.exp.is_none());
}

#[test]
fn prev_kid_without_previous_secret_signs_as_cur() {
    let signer = signer();
    let p = Payload {
        purpose: "confirm".to_string(),
        subject: "s".to_string(),
        exp: None,
        kid: Kid::Prev,
    };
    let token = signer.sign(&p);
    let verified = signer.verify(&token, "confirm").expect("verifies");
    assert_eq!(verified.kid, Kid::Cur);
}
