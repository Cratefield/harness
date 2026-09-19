//! `Ports::provides()` answers for every port, including `Auth`.
//!
//! It was fifteen hand-written `if`s and it had lost one: `Port::Auth`
//! was missing, so a bundle with a verifier wired reported fourteen of
//! the fifteen and said it had no `Auth`. Nothing called it — every
//! `provides()` in the repository is the `Runtime` trait's — which is why
//! a wrong answer sat there. Dead code that looks authoritative is worse
//! than none: the next caller gets the wrong answer about the one port
//! that decides whether a table is served to a stranger.

use std::sync::Arc;

use cratefield_core::{Port, Ports};

#[test]
fn an_empty_bundle_provides_nothing() {
    assert!(Ports::empty().provides().is_empty());
    for port in Port::ALL {
        assert!(!Ports::empty().has(*port), "{port:?}");
    }
}

#[test]
fn a_wired_auth_port_is_reported() {
    // The variant that was missing, asserted on its own so the general
    // test below cannot pass by luck of a shared helper.
    let mut ports = Ports::empty();
    ports.auth = Some(Arc::new(cratefield_core::Unconfigured::new(
        "a test bundle",
    )));
    assert!(ports.has(Port::Auth));
    assert_eq!(ports.provides(), vec![Port::Auth]);
}

#[test]
fn every_port_has_an_answer_and_the_enum_cannot_outgrow_it() {
    // `has` matches `Port` exhaustively, so this is the compiler's
    // guarantee restated where a reader meets it: a variant added to the
    // enum fails to build until it is wired here. What this asserts is
    // the other half — that `provides` walks every variant rather than a
    // list of its own that could fall behind.
    //
    // Compared on a bundle with something wired, not an empty one: on an
    // empty bundle both sides are empty whatever `provides` walks, so the
    // comparison passes vacuously — it did, against a `provides` that
    // filtered `Auth` back out.
    let mut ports = Ports::empty();
    ports.auth = Some(Arc::new(cratefield_core::Unconfigured::new(
        "a test bundle",
    )));
    ports.clock = Some(Arc::new(cratefield_core::SystemClock));
    let walked: Vec<Port> = Port::ALL
        .iter()
        .copied()
        .filter(|port| ports.has(*port))
        .collect();
    assert_eq!(walked, ports.provides());
    assert!(!walked.is_empty(), "the comparison must not be vacuous");
    assert_eq!(Port::ALL.len(), 18, "a new port needs a case in `has`");
}
