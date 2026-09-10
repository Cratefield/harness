//! `fz push` acceptance tests (issue #184).
//!
//! Three properties this pins that a unit test in `cratefield-cli` cannot:
//!
//! 1. **The generated key round-trips through the adapter.** `fz push vapid
//!    keygen` prints a public key and writes a private one; the assertion is
//!    that `cratefield-adapter-webpush` — the code that actually presents
//!    `k=` on every send — derives the *same* public key from the file. A
//!    CLI that re-derived it with its own encoding would pass its own tests
//!    and fail against every push service.
//! 2. **`fz push send` and the runtime read the same environment.** Not by
//!    inspection: every variable in `PUSH_ENV` is removed in turn from a
//!    fully-configured environment, and the CLI's verdict has to move
//!    exactly when the wiring crate's does. A CLI reading one key of its own
//!    would keep routing after that key was dropped.
//! 3. **The commands need no harness.** `fz push` is dispatched before the
//!    venture's harness is built, so the standalone binary serves it — which
//!    is how a live proof (issue #186) runs it against a deployment's
//!    environment.
//!
//! No variable is named here as a string literal: the names come from
//! `PushKey`/`PUSH_ENV`, the property `tests/push_env_guard.rs` enforces
//! across the workspace.

use std::path::PathBuf;
use std::process::ExitCode;

use cratefield_adapter_webpush::vapid::{Vapid, VapidKeys};
use cratefield_cli::push::{
    KeygenOptions, PriorityArg, SendArgs, SendRequest, Transport, inspect_subscription, plan,
    vapid_keygen,
};
use cratefield_cli::{run, run_standalone};
use cratefield_core::{MapConfig, Platform};
use cratefield_push_wiring::{PUSH_ENV, PushKey, PushVar, inspect_push};
use venture_fixture::harness_v1;

/// RFC 8291 Appendix A's subscription keys: a real point on the curve and a
/// real 16-byte auth secret.
const P256DH: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
/// A push endpoint with a long, subscription-specific path — the part that
/// must never reach the `aud`.
const ENDPOINT: &str =
    "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABmSubscriptionCapability";
const SUBJECT: &str = "mailto:ops@example.test";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fz-push-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(ToString::to_string).collect()
}

fn subscription_json() -> String {
    format!(
        "{{\"endpoint\":\"{ENDPOINT}\",\"expirationTime\":null,\
         \"keys\":{{\"p256dh\":\"{P256DH}\",\"auth\":\"{AUTH}\"}}}}"
    )
}

fn web_push_request() -> SendRequest {
    SendRequest::from_args(&SendArgs {
        transport: Transport::WebPush,
        recipient: subscription_json(),
        title: "title".to_owned(),
        body: "body".to_owned(),
        data: None,
        url: None,
        ttl: None,
        priority: PriorityArg::Immediate,
        silent: false,
    })
    .expect("the subscription parses")
}

/// The acceptance criterion the issue states: the printed public key equals
/// the one the Web Push adapter derives from the stored private key —
/// checked *through the adapter*, not by re-deriving it in the CLI.
#[test]
fn the_printed_public_key_is_the_one_the_adapter_derives_from_the_stored_private_one() {
    let tmp = TempDir::new("keygen-roundtrip");
    let path = tmp.join("vapid.key");
    let generated = vapid_keygen(&KeygenOptions {
        file: Some(&path),
        force: false,
        print_private: false,
    })
    .expect("generates");

    // Exactly what an operator configures: the file's contents, whitespace
    // and all, as the environment would hand them over.
    let stored = std::fs::read_to_string(&path).expect("the private key was written");
    let adapter = Vapid::new(VapidKeys::new(stored.clone(), SUBJECT)).expect("the adapter parses");
    assert_eq!(
        adapter.public_key(),
        generated.public_key(),
        "the key a browser is given must be the key the adapter presents as `k=`"
    );

    // And the same key, through the whole wiring: a venture that configures
    // it routes Web Push.
    let wiring = inspect_push(&MapConfig::from_pairs([
        (PushKey::VapidPrivateKey.name().to_owned(), stored),
        (PushKey::VapidSubject.name().to_owned(), SUBJECT.to_owned()),
    ]));
    assert!(
        wiring.get(Platform::Web).is_routed(),
        "{}",
        wiring.summary()
    );
    assert!(
        !generated.render().contains("rotated"),
        "a first keygen is not a rotation"
    );
}

/// `fz push send` builds its adapters from the same table `serve()` reads,
/// so dropping any one of a transport's variables has to un-route it in the
/// CLI exactly as it does in the wiring crate. A CLI that read a name of its
/// own would keep routing after that name was dropped.
#[test]
fn the_cli_reads_exactly_the_variables_the_runtime_wiring_reads() {
    let request = web_push_request();
    let full = full_environment();

    let complete = MapConfig::from_pairs(full.clone());
    assert!(
        plan(&complete, &request).ok(),
        "a fully configured environment routes Web Push: {}",
        plan(&complete, &request).render()
    );

    for var in PUSH_ENV {
        let without: Vec<(String, String)> = full
            .iter()
            .filter(|(name, _)| name != var.name())
            .cloned()
            .collect();
        let config = MapConfig::from_pairs(without);
        let cli_routed = plan(&config, &request).ok();
        let wiring_routed = inspect_push(&config).get(Platform::Web).is_routed();
        assert_eq!(
            cli_routed,
            wiring_routed,
            "dropping {} moved the CLI and the wiring crate apart",
            var.name()
        );
        // The required Web Push variables are the ones whose absence must
        // stop the send; the rest belong to other transports, or are
        // optional, and must not.
        let expected = !(var.transport == Platform::Web && var.required);
        assert_eq!(
            cli_routed,
            expected,
            "dropping {} routed Web Push = {cli_routed}",
            var.name()
        );
    }
}

/// Every variable in the table, set to something each adapter accepts.
fn full_environment() -> Vec<(String, String)> {
    // Throwaway keys, generated for the adapter tests only — not Apple's,
    // not Google's. The same ones `crates/push-wiring/tests/wiring.rs` uses.
    const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n-----END PRIVATE KEY-----";
    PUSH_ENV
        .iter()
        .map(|var| {
            let value = match var.key {
                PushKey::VapidPrivateKey => TEST_P8.to_owned(),
                PushKey::VapidSubject => SUBJECT.to_owned(),
                // Only the Web Push half has to be *valid*: this test moves
                // one variable at a time and asserts the CLI and the wiring
                // crate agree, which they must for a transport that is
                // configured and for one that is not.
                _ => "set".to_owned(),
            };
            (var.name().to_owned(), value)
        })
        .collect()
}

/// A subscription check catches the two mistakes that reach a push service
/// as a mystery `400`/`401`: a key of the wrong length, and an `aud` that
/// carries the subscription's path.
#[test]
fn inspect_subscription_catches_wrong_lengths_and_prints_a_path_free_aud() {
    let report = inspect_subscription(&subscription_json()).expect("a valid subscription");
    assert_eq!(report.aud(), "https://updates.push.services.mozilla.com");
    assert!(
        !report.aud().contains("wpush"),
        "the aud is the origin, never the subscription path: {}",
        report.aud()
    );
    assert!(
        !report.render().contains("gAAAAABmSubscriptionCapability"),
        "the endpoint's path is a bearer capability and is not printed: {}",
        report.render()
    );

    // 64 bytes instead of 65 — a point re-encoded by something that dropped
    // the 0x04 prefix, which is the usual way this goes wrong.
    let truncated = &P256DH[..P256DH.len() - 2];
    let error = inspect_subscription(&format!(
        "{{\"endpoint\":\"{ENDPOINT}\",\"keys\":{{\"p256dh\":\"{truncated}\",\"auth\":\"{AUTH}\"}}}}"
    ))
    .expect_err("a short p256dh is refused");
    assert!(error.contains("p256dh"), "{error}");

    let error = inspect_subscription(&format!(
        "{{\"endpoint\":\"{ENDPOINT}\",\"keys\":{{\"p256dh\":\"{P256DH}\",\"auth\":\"dG9vLXNob3J0\"}}}}"
    ))
    .expect_err("a short auth secret is refused");
    assert!(error.contains("auth"), "{error}");
}

/// The exit-code contract, through `run` — and, for the two commands that
/// need nothing from the venture, through `run_standalone` as well.
#[test]
fn push_exit_codes_mirror_the_verdict() {
    let tmp = TempDir::new("exit");
    let path = tmp.join("vapid.key");
    let path = path.to_str().expect("utf-8 path");

    assert_eq!(
        run(
            harness_v1,
            args(&["push", "vapid", "keygen", "--file", path])
        ),
        ExitCode::SUCCESS,
        "the first keygen writes the key"
    );
    assert_eq!(
        run(
            harness_v1,
            args(&["push", "vapid", "keygen", "--file", path])
        ),
        ExitCode::FAILURE,
        "the second refuses to rotate without --force"
    );
    assert_eq!(
        run(
            harness_v1,
            args(&["push", "vapid", "keygen", "--file", path, "--force"])
        ),
        ExitCode::SUCCESS,
        "--force rotates"
    );
    assert_eq!(
        run(harness_v1, args(&["push", "vapid", "keygen"])),
        ExitCode::FAILURE,
        "a keygen that would keep the private key nowhere is refused"
    );

    // `fz push` needs no compiled-in harness: the standalone binary — the
    // Docker image, an installed `fz` — serves it.
    assert_eq!(
        run_standalone(args(&[
            "push",
            "inspect-subscription",
            &subscription_json()
        ])),
        ExitCode::SUCCESS,
        "inspect-subscription runs without a venture"
    );
    assert_eq!(
        run_standalone(args(&["push", "inspect-subscription", "{}"])),
        ExitCode::FAILURE,
        "and still fails on a subscription that is not one"
    );
    assert_eq!(
        run_standalone(args(&["modules"])),
        ExitCode::FAILURE,
        "a command that does need the harness still says so"
    );
}

/// A recipient of the wrong shape fails before anything is built, and says
/// which transport it belongs to.
#[test]
fn a_recipient_of_the_wrong_shape_fails_the_command() {
    assert_eq!(
        run(
            harness_v1,
            args(&[
                "push",
                "send",
                "--transport",
                "apns",
                "--recipient",
                &subscription_json(),
                "--title",
                "t",
                "--body",
                "b",
                "--dry-run",
            ])
        ),
        ExitCode::FAILURE,
        "a Web Push subscription is not an APNs device token"
    );
}

/// The table itself is what both sides read, and it has to name every
/// transport — a transport with no variables could never be routed, and
/// this test's per-variable sweep above would silently cover nothing.
#[test]
fn every_transport_has_at_least_one_required_variable_in_the_table() {
    for transport in [Platform::Ios, Platform::Android, Platform::Web] {
        assert!(
            PUSH_ENV
                .iter()
                .any(|var: &PushVar| var.transport == transport && var.required),
            "{transport} has no required variable"
        );
    }
}
