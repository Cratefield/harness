//! Port-only conformance helpers (issue #201): checks over a single port
//! trait that need nothing beyond `cratefield-core`. Gated behind the
//! light `port-conformance` feature so an adapter whose whole use of the
//! kit is one free function does not pay for the harness, the router or
//! a database adapter.
//!
//! The helpers that grew heavier stayed in [`crate::conformance`]
//! (behind `harness`): the module suite needs the `TestHarness`, and the
//! fakes were left there too because `FakeHttpClient` reads axum bodies.

use cratefield_core::PushError;

/// The three recipients an adapter can be handed, one per transport.
///
/// Every `Recipient` variant appears here, so a new transport added to the
/// port makes this list — and therefore every adapter's conformance run —
/// fail to compile until it is decided what the existing adapters answer.
fn every_recipient() -> Vec<cratefield_core::Recipient> {
    let all = [
        cratefield_core::Recipient::apns("conformance-device-token"),
        cratefield_core::Recipient::fcm("conformance-registration-token"),
        cratefield_core::Recipient::web_push(
            "https://push.example.test/conformance",
            "BConformanceP256dhKey",
            "ConformanceAuthKey",
        ),
    ];
    for recipient in &all {
        // Exhaustive by construction: adding a variant breaks this match.
        match recipient {
            cratefield_core::Recipient::Apns { .. }
            | cratefield_core::Recipient::Fcm { .. }
            | cratefield_core::Recipient::WebPush { .. } => {}
        }
    }
    all.to_vec()
}

/// Runs a [`Push`](cratefield_core::Push) adapter against **every**
/// [`Recipient`](cratefield_core::Recipient) variant and asserts the port's
/// contract for transports it does not serve (issue #177): a clean
/// [`PushError::Rejected`](cratefield_core::PushError::Rejected) naming the
/// recipient as unsupported — never a panic, never a silent success, and
/// never a `Transient` that an outbox would retry forever.
///
/// `serves` lists the transports this adapter does speak; those must answer
/// something other than an unsupported-recipient rejection.
///
/// ```rust,ignore
/// // The APNs adapter serves iOS and nothing else.
/// push_recipient_conformance(&apns, &[Platform::Ios]).await;
/// ```
///
/// # Panics
///
/// Panics with the failing recipient named when the contract is broken.
pub async fn push_recipient_conformance(
    push: &dyn cratefield_core::Push,
    serves: &[cratefield_core::Platform],
) {
    let notification = cratefield_core::Notification::new("conformance", "probe");
    for recipient in every_recipient() {
        let platform = recipient.platform();
        let result = push.send(&recipient, &notification).await;
        let unsupported = matches!(
            &result,
            Err(PushError::Rejected(message)) if message.contains("unsupported recipient")
        );
        if serves.contains(&platform) {
            assert!(
                !unsupported,
                "adapter claims to serve {platform} but rejected its recipient as unsupported"
            );
        } else {
            assert!(
                unsupported,
                "adapter does not serve {platform}: the port's answer is \
                 PushError::Rejected(\"unsupported recipient…\"), got {result:?}"
            );
        }
    }
}

/// Asserts the named crate's normal dependency tree carries none of the
/// dependencies a wasm module must never see: `worker`, `wasm-bindgen`,
/// `tokio`, `reqwest`. Shell-out check (`cargo tree --edges normal`) so
/// the assertion is made against the graph cargo actually resolves, not
/// a copy of it that could drift.
///
/// # Panics
///
/// Panics when a forbidden dependency is found or cargo fails.
pub fn assert_wasm_safe_deps(module_crate: &str) {
    let output =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["tree", "-p", module_crate, "--edges", "normal"])
            .output()
            .unwrap_or_else(|err| panic!("cargo tree failed: {err}"));
    assert!(
        output.status.success(),
        "cargo tree failed for {module_crate}"
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    for forbidden in ["worker v", "wasm-bindgen v", "tokio v", "reqwest v"] {
        assert!(
            !tree.contains(forbidden),
            "{module_crate} pulls forbidden dependency `{}`:\n{tree}",
            forbidden.trim_end_matches(" v")
        );
    }
}
