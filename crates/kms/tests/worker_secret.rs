//! `WorkerSecretKms` against the port's conformance suite, plus the two
//! behaviours that are specific to it: rotation by version, and the
//! configuration an operator can get wrong (issue #535).

use std::collections::HashMap;

use base64::Engine as _;

use cratefield_kms::{Dek, Kms, KmsError, WorkerSecretKms, conformance};

/// What the runtime hands the constructor: `None` when the secret is
/// not set, the value verbatim when it is.
type Lookup = HashMap<String, String>;

fn to_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A config where `HARNESS_KEK_CURRENT` is `current` and versions
/// `1..=current` are distinct 32-byte keys.
fn ring(current: u32) -> Lookup {
    let mut lookup = Lookup::new();
    lookup.insert("HARNESS_KEK_CURRENT".to_owned(), current.to_string());
    for version in 1..=current {
        let byte = u8::try_from(version).expect("test versions fit in a byte");
        lookup.insert(format!("HARNESS_KEK_V{version}"), to_base64(&[byte; 32]));
    }
    lookup
}

fn kms(lookup: Lookup) -> WorkerSecretKms {
    WorkerSecretKms::from_lookup(move |name| lookup.get(name).cloned()).expect("the config holds")
}

#[pollster::test]
async fn worker_secret_passes_the_port_conformance() {
    let kms = kms(ring(2));
    assert_eq!(kms.provider(), "worker-secret");
    assert_eq!(kms.key_ref(), "worker-secret:HARNESS_KEK_V2");
    conformance(&kms).await;
}

#[pollster::test]
async fn a_blob_survives_a_rotation_and_then_the_old_secret_dies() {
    let dek = Dek::generate().expect("rng");

    // Before: CURRENT is 1, V1 wraps.
    let old = kms(ring(1));
    assert_eq!(old.key_ref(), "worker-secret:HARNESS_KEK_V1");
    let wrapped = old.wrap(&dek).await.expect("wrap");
    assert_eq!(wrapped[..4], 1_u32.to_be_bytes(), "the header names V1");

    // After: CURRENT is 2, both versions held. The old blob still
    // unwraps; new wraps have moved to V2.
    let rotated = kms(ring(2));
    let recovered = rotated.unwrap(&wrapped).await.expect("V1 still held");
    assert_eq!(dek.expose(), recovered.expose());
    let fresh = rotated.wrap(&dek).await.expect("wrap");
    assert_eq!(fresh[..4], 2_u32.to_be_bytes(), "new wraps use V2");
    assert!(rotated.unwrap(&fresh).await.is_ok());

    // The re-wrap has run and V1 is deleted: blobs under it fail,
    // naming the missing secret, while V2 blobs keep working.
    let mut without_v1 = ring(2);
    without_v1.remove("HARNESS_KEK_V1");
    let without_v1 = kms(without_v1);
    let err = without_v1.unwrap(&wrapped).await.expect_err("V1 is gone");
    assert!(matches!(err, KmsError::Tampered(_)), "{err}");
    assert!(
        err.to_string()
            .contains("wrapped under HARNESS_KEK_V1, which this deployment does not hold"),
        "{err}"
    );
    assert!(
        err.to_string().contains("restore the secret or re-wrap"),
        "{err}"
    );
    without_v1
        .unwrap(&fresh)
        .await
        .expect("V2 blobs unaffected");

    // A blob naming a version this deployment never holds is refused
    // at the lookup, before any crypto. That is the missing-secret
    // case, not proof the header is authenticated — the relabel test
    // below covers a version this deployment does hold.
    let mut lying = fresh.clone();
    lying[..4].copy_from_slice(&9_u32.to_be_bytes());
    let err = without_v1.unwrap(&lying).await.expect_err("V9 not held");
    assert!(matches!(err, KmsError::Tampered(_)), "{err}");
    assert!(err.to_string().contains("HARNESS_KEK_V9"), "{err}");
}

/// The header is authenticated, not just consulted. Conformance's
/// single-bit flips on this blob's header all land on versions the KMS
/// does not hold, which are refused at the lookup before any crypto —
/// so if the AAD stopped covering the version, only a relabel between
/// two held versions could tell.
#[pollster::test]
async fn a_relabelled_header_is_refused_between_held_versions() {
    // V1 and V2 hold the same key material on purpose: with distinct
    // keys a relabelled blob dies under the wrong key and the test
    // would pass whether or not the version is in the AAD.
    let lookup: Lookup = [
        ("HARNESS_KEK_CURRENT".to_owned(), "2".to_owned()),
        ("HARNESS_KEK_V1".to_owned(), to_base64(&[9_u8; 32])),
        ("HARNESS_KEK_V2".to_owned(), to_base64(&[9_u8; 32])),
    ]
    .into();
    let both = kms(lookup.clone());
    let mut first_only = lookup;
    first_only.insert("HARNESS_KEK_CURRENT".to_owned(), "1".to_owned());
    let first_only = kms(first_only);

    let dek = Dek::generate().expect("rng");
    let v2_blob = both.wrap(&dek).await.expect("wrap");
    let v1_blob = first_only.wrap(&dek).await.expect("wrap");

    for (blob, claimed) in [(&v2_blob, 1_u32), (&v1_blob, 2)] {
        let mut relabelled = blob.clone();
        relabelled[..4].copy_from_slice(&claimed.to_be_bytes());
        let err = both
            .unwrap(&relabelled)
            .await
            .expect_err("the header names a version the blob was not sealed under");
        assert!(matches!(err, KmsError::Tampered(_)), "{err}");
        assert!(
            err.to_string().contains(&format!("HARNESS_KEK_V{claimed}")),
            "{err}"
        );
    }

    // The untouched blobs still unwrap under the very keys above, so
    // the refusals are the AAD and not the keys.
    both.unwrap(&v2_blob)
        .await
        .expect("the true header unwraps");
    both.unwrap(&v1_blob)
        .await
        .expect("the true header unwraps");
}

#[test]
fn bad_configuration_is_invalid_and_never_echoes_the_key() {
    let key = [7_u8; 32];
    let encoded = to_base64(&key);
    let truncated = to_base64(&key[..31]);
    let padded = to_base64(&[0_u8; 33]);
    let mut missing_current = ring(1);
    missing_current.remove("HARNESS_KEK_CURRENT");
    let mut missing_key = ring(1);
    missing_key.remove("HARNESS_KEK_V1");
    let mut as_well = ring(1);
    as_well.insert("HARNESS_KEK_V1".to_owned(), "not base64!!".to_owned());
    let mut short = ring(1);
    short.insert("HARNESS_KEK_V1".to_owned(), truncated.clone());
    let mut long = ring(1);
    long.insert("HARNESS_KEK_V1".to_owned(), padded.clone());

    for (what, lookup) in [
        ("a missing HARNESS_KEK_CURRENT", missing_current),
        (
            "a non-numeric version",
            [("HARNESS_KEK_CURRENT".to_owned(), "two".to_owned())].into(),
        ),
        (
            "a plus-signed version",
            [("HARNESS_KEK_CURRENT".to_owned(), "+1".to_owned())].into(),
        ),
        (
            "a zero version",
            [("HARNESS_KEK_CURRENT".to_owned(), "0".to_owned())].into(),
        ),
        (
            "an over-bound version",
            [("HARNESS_KEK_CURRENT".to_owned(), "1025".to_owned())].into(),
        ),
        ("a missing current-version secret", missing_key),
        ("a value that is not base64", as_well),
        ("a value that decodes short", short),
        ("a value that decodes long", long),
    ] {
        let err = WorkerSecretKms::from_lookup(|name| lookup.get(name).cloned()).expect_err(what);
        assert!(matches!(err, KmsError::Invalid(_)), "{what}: {err}");
        assert!(!err.is_retryable(), "{what}: a config fix is not a retry");
        assert!(err.to_string().contains("HARNESS_KEK"), "{what}: {err}");
        assert!(
            err.to_string().contains("wrangler secret put"),
            "{what}: the error should name the fix: {err}"
        );
        assert!(
            !err.to_string().contains(&encoded),
            "{what}: the error echoed the key material: {err}"
        );
        assert!(
            !err.to_string().contains(&truncated) && !err.to_string().contains(&padded),
            "{what}: the error echoed the secret value: {err}"
        );
    }

    // The over-bound error says what the bound is, so the operator can
    // tell a typo from a key ring that outgrew the constant on purpose.
    let mut over = ring(1);
    over.insert("HARNESS_KEK_CURRENT".to_owned(), "1025".to_owned());
    let err =
        WorkerSecretKms::from_lookup(|name| over.get(name).cloned()).expect_err("over the bound");
    assert!(err.to_string().contains("1024"), "{err}");
}

#[test]
fn the_current_value_tolerates_a_trailing_newline() {
    // The value travels through shells and editors; the difference
    // between printf and echo should not be a cryptographic event.
    let lookup: Lookup = [
        ("HARNESS_KEK_CURRENT".to_owned(), "1\n".to_owned()),
        (
            "HARNESS_KEK_V1".to_owned(),
            format!("{}\n", to_base64(&[1_u8; 32])),
        ),
    ]
    .into();
    assert!(WorkerSecretKms::from_lookup(|name| lookup.get(name).cloned()).is_ok());
}

#[test]
fn debug_output_names_the_version_and_never_the_key() {
    let kms = kms(ring(1));
    let shown = format!("{kms:?}");
    assert!(shown.contains("worker-secret"), "{shown}");
    assert!(shown.contains("HARNESS_KEK_V1"), "{shown}");
    assert!(!shown.contains(&to_base64(&[1_u8; 32])), "{shown}");
    assert!(!shown.contains("01010101"), "{shown}");
}
