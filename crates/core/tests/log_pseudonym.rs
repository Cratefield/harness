//! The keyed log pseudonym (issue #135) is tested in its own binary because
//! `set_log_pseudonym_key` installs a *process-wide* key — running it inside
//! the crate's unit tests would race the other `subject_hash` tests.

use cratefield_core::{set_log_pseudonym_key, subject_hash};

#[test]
fn keyed_pseudonym_differs_from_the_bare_hash_and_is_stable() {
    // Before any key is installed: the bare SHA-256 digest form.
    let bare = subject_hash("alice@example.com");
    assert_eq!(bare.len(), 12);

    set_log_pseudonym_key(b"a-test-harness-secret-0123456789");

    let keyed = subject_hash("alice@example.com");
    assert_eq!(keyed.len(), 12);
    assert!(keyed.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(keyed, bare, "keying changes the pseudonym");
    assert_eq!(
        keyed,
        subject_hash("alice@example.com"),
        "stable under one key"
    );
    assert_ne!(
        keyed,
        subject_hash("bob@example.com"),
        "distinct inputs differ"
    );
}
