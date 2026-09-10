//! One home for the Web Push test vectors, enforced rather than asserted.
//!
//! `RFC8291_UA_PUBLIC` and its `auth` secret are a *matched* pair — a real
//! point on the P-256 curve and the 16-byte secret the RFC publishes
//! alongside it — and four crates used to carry their own copy, each with a
//! comment claiming it was "the same one" another crate used and nothing
//! making that true. A copy that drifts by one character stops being a
//! point on the curve, and the suite that holds it starts asserting the
//! error path of every check it meant to exercise: still green, proving
//! nothing.
//!
//! So `cratefield-testing`'s `vectors` module owns them and this guard
//! fails the build if any other Rust source writes one down again. Same
//! shape as `push_env_guard.rs` and `card_data_guard.rs`: the rule is a
//! test, and the test proves the detector fires.

mod common;

use common::{relative_to, repo_root, rust_sources};
use cratefield_testing::vectors::{
    RFC8291_AUTH_SECRET, RFC8291_UA_PRIVATE, RFC8291_UA_PUBLIC, WEB_PUSH_ENDPOINT,
};

/// The crate that is allowed to write them down: the one home.
///
/// The trailing slash is load-bearing, for the reason `push_env_guard.rs`
/// gives: as a bare prefix it would exempt `crates/testing-anything` too.
const HOME: &str = "crates/testing/";

/// The vectors this guards: the Web Push subscription, whose parts only
/// work as a set.
///
/// `TEST_P256_PEM` is shared from the same module but deliberately **not**
/// guarded here. It is a signing key that predates Web Push in this
/// workspace — `cratefield-push-auth`'s own tests mint with it, and the
/// APNs suite asserts bytes from it — so moving those copies is a change
/// to crates this one has no business touching. The Web Push vectors are
/// the set the review found four copies of.
const VECTORS: [(&str, &str); 4] = [
    ("the RFC 8291 user agent's public key", RFC8291_UA_PUBLIC),
    ("the RFC 8291 user agent's private key", RFC8291_UA_PRIVATE),
    ("the RFC 8291 auth secret", RFC8291_AUTH_SECRET),
    ("the shared Web Push endpoint", WEB_PUSH_ENDPOINT),
];

/// Which vectors a source writes down.
fn offenders_in(source: &str) -> Vec<&'static str> {
    VECTORS
        .iter()
        .filter(|(_, value)| source.contains(value))
        .map(|(what, _)| *what)
        .collect()
}

#[test]
fn only_the_testing_crate_writes_a_web_push_vector_down() {
    let root = repo_root();
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    assert!(
        sources.len() > 100,
        "the walk found only {} Rust sources, so it is not walking the workspace",
        sources.len()
    );

    let mut violations = Vec::new();
    for path in sources {
        let relative = relative_to(&root, &path);
        if relative.starts_with(HOME) {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        for what in offenders_in(&source) {
            violations.push(format!("{relative} carries its own copy of {what}"));
        }
    }

    assert!(
        violations.is_empty(),
        "the Web Push test vectors live in `{HOME}src/vectors.rs`. Import them from \
         `cratefield_testing::vectors` instead:\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn the_guard_fires_on_a_source_that_copies_one() {
    // A guard nobody tests is a guard nobody knows is wired (issue #44's
    // lesson). This is what a fifth copy would look like.
    let source = format!("const P256DH: &str = \"{RFC8291_UA_PUBLIC}\";\n");
    assert_eq!(
        offenders_in(&source),
        vec!["the RFC 8291 user agent's public key"]
    );
}

#[test]
fn the_guard_leaves_ordinary_sources_alone() {
    let source = "//! The subscription's `p256dh` is an uncompressed P-256 point.\n";
    assert!(offenders_in(source).is_empty(), "{source}");
}
