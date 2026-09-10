//! RFC 8291 from both ends: the published example reproduced byte for byte,
//! and the user agent's own decryptor run against arbitrary payloads.
//!
//! The two are complementary, and neither alone is enough. A vector proves
//! the one input it contains and says nothing about an empty payload or one
//! at the size limit. A round trip proves internal consistency and would
//! happily agree with a `key_info` built in the wrong order — a mistake that
//! makes every real browser drop the message. `support::decrypt` is written
//! from the RFC text and shares no code with `src/ece.rs`, so the round trip
//! is an independent reading rather than the encoder's own mirror.

mod support;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cratefield_adapter_webpush::ece::{self, Ece, EceError, SubscriptionKeys};
use support::{DecryptError, decrypt, public_key_of};

/// RFC 8291 §5 / Appendix A.
const PLAINTEXT: &str = "When I grow up, I want to be a watermelon";
const UA_PUBLIC: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
const AUTH_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";
const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
/// The whole content body of RFC 8291 §5, its three presentation lines
/// joined. 144 octets: the 86-octet header and a 58-octet record.
const BODY: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
                    mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
                    pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

fn b64(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).expect("base64url")
}

fn fixed<const N: usize>(value: &str) -> [u8; N] {
    b64(value).try_into().expect("fixed-size vector value")
}

fn subscription() -> SubscriptionKeys {
    SubscriptionKeys::parse(UA_PUBLIC, AUTH_SECRET).expect("the RFC's own subscription")
}

/// The end-to-end assertion: the RFC's inputs produce the RFC's body,
/// every octet of it.
#[test]
fn the_rfc8291_example_body_is_reproduced_byte_for_byte() {
    let body = Ece::new(4096)
        .expect("the vector's record size")
        .seal_with(
            &subscription(),
            PLAINTEXT.as_bytes(),
            &fixed(SALT),
            &fixed(AS_PRIVATE),
        )
        .expect("the RFC's own inputs");

    assert_eq!(body, b64(BODY));
    // 144 octets, not the `Content-Length: 145` printed above the example:
    // the RFC's own base64url is 192 characters, which is 144 octets, and
    // the same off-by-one appears in RFC 8188 §3.1.
    assert_eq!(body.len(), 144);
    assert_eq!(URL_SAFE_NO_PAD.encode(&body), BODY);
}

/// And the browser's half agrees: the RFC's body, opened with the RFC's
/// user agent private key, is the RFC's plaintext.
#[test]
fn the_rfc8291_example_body_decrypts_with_the_user_agent_key() {
    let opened =
        decrypt(&fixed(UA_PRIVATE), &fixed(AUTH_SECRET), &b64(BODY)).expect("the RFC's own body");
    assert_eq!(opened, PLAINTEXT.as_bytes());
}

/// The published private key really is the published public key, so the
/// decryptor is being run against the same subscription the encoder used
/// and not a coincidence.
#[test]
fn the_vector_key_pair_belongs_together() {
    assert_eq!(public_key_of(&fixed(UA_PRIVATE)).as_slice(), b64(UA_PUBLIC));
}

/// Arbitrary payloads, through the production path (fresh salt, fresh
/// ephemeral key) and back out of the decryptor. These are the inputs no
/// vector contains.
#[test]
fn arbitrary_payloads_round_trip_through_the_user_agent() {
    let keys = subscription();
    let ua_private: [u8; 32] = fixed(UA_PRIVATE);
    let auth: [u8; 16] = fixed(AUTH_SECRET);
    let ece = Ece::default();

    let at_limit = vec![b'z'; ece.max_plaintext()];
    let payloads: Vec<&[u8]> = vec![
        b"",
        b"x",
        br#"{"title":"Room starting","body":"Yoga in 10 min","silent":false}"#,
        "unicode: \u{e9}\u{4e2d}\u{6587}\u{1f680}".as_bytes(),
        // Trailing zero octets are the case the "last non-zero octet is the
        // delimiter" rule exists for: the delimiter is appended *after*
        // them, so it is still the last non-zero octet and the zeros are
        // part of the message.
        b"trailing\x00\x00\x00",
        &[0u8; 64],
        &at_limit,
    ];

    for payload in payloads {
        let body = ece.seal(&keys, payload).expect("sealed");
        let opened = decrypt(&ua_private, &auth, &body).expect("the browser opens it");
        assert_eq!(opened, payload, "payload of {} bytes", payload.len());
        // The header a browser parses is the one the RFC describes.
        assert_eq!(body.len(), ece::WEB_PUSH_HEADER_LEN + payload.len() + 17);
        assert_eq!(usize::from(body[20]), ece::PUBLIC_KEY_LEN, "idlen");
    }
}

/// The same plaintext twice is two different bodies that both open — which
/// is the salt and the ephemeral key doing their job.
#[test]
fn two_sealings_of_one_payload_differ_and_both_decrypt() {
    let keys = subscription();
    let ua_private: [u8; 32] = fixed(UA_PRIVATE);
    let auth: [u8; 16] = fixed(AUTH_SECRET);

    let first = Ece::default().seal(&keys, b"same").expect("sealed");
    let second = Ece::default().seal(&keys, b"same").expect("sealed");
    assert_ne!(first, second);
    assert_eq!(decrypt(&ua_private, &auth, &first).unwrap(), b"same");
    assert_eq!(decrypt(&ua_private, &auth, &second).unwrap(), b"same");
}

/// A record size the venture chose is honoured end to end, and the browser
/// reads it back out of the header.
#[test]
fn a_raised_record_size_round_trips_too() {
    let keys = subscription();
    let ece = Ece::new(8192).expect("valid");
    let payload = vec![b'q'; 5_000];
    let body = ece.seal(&keys, &payload).expect("sealed");

    assert_eq!(u32::from_be_bytes(body[16..20].try_into().unwrap()), 8192);
    assert_eq!(
        decrypt(&fixed(UA_PRIVATE), &fixed(AUTH_SECRET), &body).unwrap(),
        payload
    );
    // ...and the default would have refused this payload, so the two limits
    // really are different.
    assert!(matches!(
        Ece::default().seal(&keys, &payload),
        Err(EceError::PayloadTooLarge { .. })
    ));
}

/// The authentication tag is doing its job: nothing about the body can be
/// changed without the browser noticing.
#[test]
fn a_tampered_body_does_not_decrypt() {
    let keys = subscription();
    let ua_private: [u8; 32] = fixed(UA_PRIVATE);
    let auth: [u8; 16] = fixed(AUTH_SECRET);
    let body = Ece::default().seal(&keys, b"authentic").expect("sealed");

    // Every region of the body: the salt, the ephemeral public key, the
    // ciphertext, and the tag.
    for offset in [0, 20, ece::WEB_PUSH_HEADER_LEN, body.len() - 1] {
        let mut tampered = body.clone();
        tampered[offset] ^= 0x01;
        assert!(
            matches!(
                decrypt(&ua_private, &auth, &tampered),
                Err(DecryptError::Aead | DecryptError::ServerKey)
            ),
            "a flipped bit at offset {offset} was accepted"
        );
    }
    // Truncation too.
    assert!(decrypt(&ua_private, &auth, &body[..body.len() - 1]).is_err());
    assert_eq!(
        decrypt(&ua_private, &auth, b"short"),
        Err(DecryptError::Truncated)
    );
}

/// Encrypted to one subscription, unreadable by another — the property the
/// whole scheme exists for.
#[test]
fn another_subscription_cannot_open_it() {
    let intended = subscription();
    let body = Ece::default().seal(&intended, b"private").expect("sealed");

    // A different user agent private key.
    let other_private = [7u8; 32];
    assert_eq!(
        decrypt(&other_private, &fixed(AUTH_SECRET), &body),
        Err(DecryptError::Aead)
    );
    // The right key, the wrong authentication secret: `auth` is mixed into
    // the key schedule, so it is not decoration.
    assert_eq!(
        decrypt(&fixed(UA_PRIVATE), &[0u8; 16], &body),
        Err(DecryptError::Aead)
    );
}

/// A subscription this crate has never seen: keys generated here, not taken
/// from the RFC, so nothing about the round trip depends on the vector's
/// particular numbers.
#[test]
fn a_freshly_generated_subscription_round_trips() {
    let ua_private = [
        0x4c, 0x2f, 0x1a, 0x9d, 0x77, 0x03, 0xe8, 0x51, 0x62, 0xbb, 0x94, 0x0d, 0x38, 0xa7, 0x11,
        0xc6, 0x05, 0xfe, 0x83, 0x2a, 0x49, 0xd0, 0x6b, 0x17, 0x9c, 0x24, 0xef, 0x50, 0x8b, 0x36,
        0x72, 0xa1,
    ];
    let auth = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];
    let keys = SubscriptionKeys::from_bytes(&public_key_of(&ua_private), &auth)
        .expect("a generated subscription");

    let payload = br#"{"title":"Hi","body":"there","silent":false}"#;
    let body = Ece::default().seal(&keys, payload).expect("sealed");
    assert_eq!(decrypt(&ua_private, &auth, &body).unwrap(), payload);
}
