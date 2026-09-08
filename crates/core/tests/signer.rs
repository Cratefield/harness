//! `HmacSigner` acceptance tests (issue #3, ADR 0006).

//! `HmacSigner` acceptance tests (issue #3, ADR 0006) and the key-ring,
//! policy, binding and revocation adversarial suite (issue #137, ADR 0014).

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use cratefield_core::{
    CONFIRM_TOKEN_MAX_TTL_SECS, Clock, DEFAULT_TOKEN_MAX_TTL_SECS, HmacSigner, KeyRing, KeyState,
    Kid, MAX_KID_NAME, Payload, STATUS_TOKEN_MAX_TTL_SECS, Signer, SignerError, TokenPolicy,
};
use std::sync::Arc;

// Obvious dummy secrets, never real.
const SECRET_CUR: &str = "test-secret-current-0123456789abcdef";
const SECRET_NEW: &str = "test-secret-rotated---0123456789abcdef";
const SECRET_THIRD: &str = "test-secret-third----0123456789abcdef";
const SECRET_FOURTH: &str = "test-secret-fourth---0123456789abcdef";
const SECRET_FIFTH: &str = "test-secret-fifth----0123456789abcdef";

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

// The issue #137 adversarial suite: ring states, eviction, revocation,
// purpose expiry policy and venture/environment binding (ADR 0014).

/// A time source pinned for expiry arithmetic; the `Clock` port is the
/// only way into the signer's notion of now, so tests pin it rather than
/// sleeping (architecture section 5).
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(i64::try_from(NOW).expect("fits"))
            .expect("valid epoch")
    }
}

const NOW: u64 = 1_780_000_000;

fn secret(value: &str) -> Vec<u8> {
    value.as_bytes().to_vec()
}

fn named(value: &str) -> Kid {
    Kid::Named(value.to_string())
}

fn mint(purpose: &str, exp: Option<u64>) -> Payload {
    Payload {
        purpose: purpose.to_string(),
        subject: "nick@example.com".to_string(),
        exp,
        kid: Kid::Cur,
    }
}

fn cur_ring() -> KeyRing {
    let mut ring = KeyRing::new();
    ring.rotate_signing(Kid::Cur, secret(SECRET_CUR))
        .expect("test ring");
    ring
}

/// The decoded JSON payload part of a token: the wire is what callers
/// and other runtimes see, so binding, clamping and kid stamping are
/// asserted there rather than through implementation internals.
fn wire(token: &str) -> serde_json::Value {
    let (encoded, _) = token.split_once('.').expect("token splits");
    let bytes = URL_SAFE_NO_PAD.decode(encoded).expect("payload decodes");
    serde_json::from_slice(&bytes).expect("payload json")
}

#[test]
fn revoked_key_refuses_its_prior_signatures() {
    let mut mint_ring = KeyRing::new();
    mint_ring
        .rotate_signing(named("k1"), secret(SECRET_CUR))
        .expect("k1 signs");
    let token = HmacSigner::from_ring(mint_ring).sign(&payload("confirm"));

    let mut ring = KeyRing::new();
    ring.rotate_signing(named("k2"), secret(SECRET_NEW))
        .expect("k2 signs");
    ring.add_verifying_only(named("k1"), secret(SECRET_CUR))
        .expect("k1 verifies only");
    let live = HmacSigner::from_ring(ring.clone());
    assert!(
        live.verify(&token, "confirm").is_some(),
        "a demoted key keeps links alive until revoked"
    );
    assert!(ring.revoke(&named("k1")), "k1 existed to revoke");
    let after = HmacSigner::from_ring(ring);
    assert!(
        after.verify(&token, "confirm").is_none(),
        "revocation must kill old links even while the secret is still configured"
    );
}

#[test]
fn revoking_an_absent_id_burns_it() {
    let mut ring = cur_ring();
    assert!(
        !ring.revoke(&named("ghost")),
        "nothing existed to flip to revoked"
    );
    assert_eq!(
        ring.state_of(&named("ghost")),
        Some(KeyState::Revoked),
        "the id is burned anyway, so `revoke(prev)` survives an operator also dropping the env entry"
    );
    let err = ring
        .add_verifying_only(named("ghost"), secret(SECRET_NEW))
        .unwrap_err();
    assert!(
        matches!(err, SignerError::KeyRevoked(ref id) if id == "ghost"),
        "{err}"
    );
}

#[test]
fn revoked_secret_cannot_re_enter_under_a_new_id() {
    let mut ring = KeyRing::new();
    ring.rotate_signing(named("k1"), secret(SECRET_CUR))
        .expect("k1 signs");
    ring.revoke(&named("k1"));
    let err = ring
        .rotate_signing(named("k2"), secret(SECRET_CUR))
        .unwrap_err();
    assert_eq!(err, SignerError::RevokedSecretReuse);
}

#[test]
fn duplicate_key_ids_are_refused() {
    let mut ring = KeyRing::new();
    ring.rotate_signing(named("k1"), secret(SECRET_CUR))
        .unwrap();
    ring.rotate_signing(named("k2"), secret(SECRET_NEW))
        .unwrap();
    let err = ring
        .add_verifying_only(named("k1"), secret(SECRET_THIRD))
        .unwrap_err();
    assert!(
        matches!(err, SignerError::KeyIdTaken(ref id) if id == "k1"),
        "{err}"
    );
}

#[test]
fn only_the_signing_key_signs_and_caller_kid_is_ignored() {
    let mut ring = KeyRing::new();
    ring.rotate_signing(named("k1"), secret(SECRET_CUR))
        .unwrap();
    ring.rotate_signing(named("k2"), secret(SECRET_NEW))
        .unwrap();
    let signer = HmacSigner::from_ring(ring);
    let mut p = payload("confirm");
    p.kid = named("k1");
    let token = signer.sign(&p);
    assert_eq!(wire(&token)["kid"], "k2", "the signing key stamps its id");
    assert_eq!(
        signer.verify(&token, "confirm").expect("verifies").kid,
        named("k2")
    );
}

#[test]
fn ring_capacity_bounds_the_key_history() {
    let mut ring = KeyRing::new();
    ring.rotate_signing(named("k1"), secret(SECRET_CUR))
        .unwrap();
    ring.rotate_signing(named("k2"), secret(SECRET_NEW))
        .unwrap();
    ring.rotate_signing(named("k3"), secret(SECRET_THIRD))
        .unwrap();
    ring.rotate_signing(named("k4"), secret(SECRET_FOURTH))
        .unwrap();
    assert_eq!(ring.len(), KeyRing::CAPACITY);
    let retired = ring
        .rotate_signing(named("k5"), secret(SECRET_FIFTH))
        .expect("the oldest verifying key makes room");
    assert_eq!(retired, Some(named("k1")));
    assert_eq!(ring.len(), KeyRing::CAPACITY, "the ring stays bounded");
    let signer = HmacSigner::from_ring(ring);
    assert_eq!(
        signer
            .ring_states()
            .iter()
            .filter(|(_, state)| *state == KeyState::Signing)
            .count(),
        1,
        "exactly one key signs"
    );
    let mut first = KeyRing::new();
    first
        .rotate_signing(named("k1"), secret(SECRET_CUR))
        .unwrap();
    let old = HmacSigner::from_ring(first).sign(&payload("confirm"));
    assert!(
        signer.verify(&old, "confirm").is_none(),
        "a retired key's tokens are dead by design — the documented cost of bounded history"
    );
}

#[test]
fn binding_refuses_cross_venture_and_env_replay() {
    let acme_prod = HmacSigner::from_ring(cur_ring())
        .with_binding(Some("acme".to_string()), Some("prod".to_string()));
    let acme_dev = HmacSigner::from_ring(cur_ring())
        .with_binding(Some("acme".to_string()), Some("dev".to_string()));
    let globex_prod = HmacSigner::from_ring(cur_ring())
        .with_binding(Some("globex".to_string()), Some("prod".to_string()));
    let token = acme_prod.sign(&payload("confirm"));
    assert_eq!(wire(&token)["iss"], "acme|prod");
    assert!(acme_prod.verify(&token, "confirm").is_some());
    assert!(
        acme_dev.verify(&token, "confirm").is_none(),
        "tokens must not cross environments"
    );
    assert!(
        globex_prod.verify(&token, "confirm").is_none(),
        "tokens must not cross ventures"
    );
}

#[test]
fn unbound_legacy_tokens_verify_under_a_bound_signer_and_scoped_tokens_fail_closed() {
    let legacy = HmacSigner::new(SECRET_CUR, None).expect("test signer");
    let token = legacy.sign(&payload("confirm"));
    assert!(
        wire(&token).get("iss").is_none(),
        "an unbound signer mints no issuer"
    );
    let bound = legacy
        .clone()
        .with_binding(Some("acme".to_string()), Some("prod".to_string()));
    assert!(
        bound.verify(&token, "confirm").is_some(),
        "links already in the wild must not break when binding is switched on"
    );
    let scoped = bound.sign(&payload("confirm"));
    assert!(
        legacy.verify(&scoped, "confirm").is_none(),
        "a scoped token must never verify on an unbound verifier"
    );
}

#[test]
fn empty_binding_labels_leave_the_signer_unbound() {
    let signer = HmacSigner::new(SECRET_CUR, None)
        .expect("test signer")
        .with_binding(Some(String::new()), Some(String::new()));
    let token = signer.sign(&payload("confirm"));
    assert!(wire(&token).get("iss").is_none());
    let plain = HmacSigner::new(SECRET_CUR, None).expect("test signer");
    assert!(plain.verify(&token, "confirm").is_some());
}

#[test]
fn policy_clamps_at_mint_time() {
    let signer = HmacSigner::from_ring(cur_ring()).with_clock(Arc::new(FixedClock));
    let status = u64::try_from(STATUS_TOKEN_MAX_TTL_SECS).expect("positive");
    let confirm = u64::try_from(CONFIRM_TOKEN_MAX_TTL_SECS).expect("positive");
    let default = u64::try_from(DEFAULT_TOKEN_MAX_TTL_SECS).expect("positive");

    let overlong = signer.sign(&mint("waitlist.status", Some(NOW + 365 * 86_400)));
    assert_eq!(
        wire(&overlong)["exp"].as_u64(),
        Some(NOW + status),
        "a year-long status token is clamped to the policy ceiling"
    );
    let missing = signer.sign(&mint("waitlist.status", None));
    assert_eq!(
        wire(&missing)["exp"].as_u64(),
        Some(NOW + status),
        "a missing expiry gets the ceiling, never an omission"
    );
    let short = signer.sign(&mint("email-signup.confirm", Some(NOW + 3_600)));
    assert_eq!(
        wire(&short)["exp"].as_u64(),
        Some(NOW + 3_600),
        "a request under the ceiling survives untouched"
    );
    let unknown = signer.sign(&mint("whatever.new.purpose", None));
    assert_eq!(
        wire(&unknown)["exp"].as_u64(),
        Some(NOW + default),
        "unknown purposes get the default ceiling"
    );
    let confirm_default = signer.sign(&mint("email-signup.confirm", None));
    assert_eq!(
        wire(&confirm_default)["exp"].as_u64(),
        Some(NOW + confirm),
        "a confirm link minted with no expiry gets the seven-day ceiling"
    );
    assert!(signer.verify(&overlong, "waitlist.status").is_some());
    assert_eq!(
        signer
            .verify(&overlong, "waitlist.status")
            .expect("verifies")
            .exp,
        Some(NOW + status)
    );
}

#[test]
fn unsubscribe_purpose_never_expires_in_any_namespace() {
    let signer = HmacSigner::from_ring(cur_ring()).with_clock(Arc::new(FixedClock));
    let token = signer.sign(&mint("email-signup.unsubscribe", None));
    assert!(
        wire(&token).get("exp").is_none(),
        "the one action with a justified non-expiring ceiling"
    );
    assert!(
        signer
            .verify(&token, "email-signup.unsubscribe")
            .expect("verifies")
            .exp
            .is_none()
    );
}

#[test]
fn pre_policy_indefinite_status_tokens_still_verify() {
    let permissive = HmacSigner::from_ring(cur_ring())
        .with_clock(Arc::new(FixedClock))
        .with_policy(TokenPolicy::default().with_max("status", None));
    let token = permissive.sign(&mint("waitlist.status", None));
    assert!(
        wire(&token).get("exp").is_none(),
        "an explicitly non-expiring ceiling mints forever — a named decision, not an omission"
    );
    let strict = HmacSigner::from_ring(cur_ring()).with_clock(Arc::new(FixedClock));
    assert!(
        strict.verify(&token, "waitlist.status").is_some(),
        "verification never re-clamps: issued links survive the tightening"
    );
}

#[test]
fn debug_never_prints_key_material() {
    let mut ring = KeyRing::new();
    ring.rotate_signing(Kid::Cur, secret(SECRET_CUR)).unwrap();
    ring.add_verifying_only(Kid::Prev, secret(SECRET_NEW))
        .unwrap();
    let signer = HmacSigner::new(SECRET_CUR, Some(SECRET_NEW.to_string())).expect("signer");
    // All dummy secrets share this suffix; a single hit means a leak.
    for rendered in [
        format!("{ring:?}"),
        format!("{signer:?}"),
        format!("{:?}", signer.ring_states()),
    ] {
        assert!(
            !rendered.contains("0123456789abcdef"),
            "key material in debug output: {rendered}"
        );
    }
}

#[test]
fn empty_ring_emits_an_invalid_token_instead_of_panicking() {
    let signer = HmacSigner::from_ring(KeyRing::new());
    assert_eq!(signer.sign(&payload("confirm")), "");
    assert!(signer.verify("", "confirm").is_none());
}

#[test]
fn previous_secret_must_also_meet_the_minimum() {
    // Issue #137 tightened this: the old signer never length-checked the
    // previous secret.
    assert_eq!(
        HmacSigner::new(SECRET_CUR, Some("too-short".to_string())).unwrap_err(),
        SignerError::SecretTooShort
    );
}

#[test]
fn key_ids_are_length_capped() {
    let long = "x".repeat(MAX_KID_NAME + 1);
    let mut ring = KeyRing::new();
    let err = ring
        .rotate_signing(Kid::Named(long.clone()), secret(SECRET_CUR))
        .unwrap_err();
    assert!(
        matches!(err, SignerError::KeyIdTooLong(ref id) if *id == long),
        "{err}"
    );
}

#[test]
fn named_kids_round_trip_through_the_wire() {
    let mut ring = KeyRing::new();
    ring.rotate_signing(named("v2"), secret(SECRET_CUR))
        .unwrap();
    let signer = HmacSigner::from_ring(ring);
    let token = signer.sign(&payload("confirm"));
    assert_eq!(wire(&token)["kid"], "v2");
    assert_eq!(
        signer.verify(&token, "confirm").expect("verifies").kid,
        named("v2")
    );
}
