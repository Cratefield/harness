//! **The leg that proves the encryption interoperates** (issue #181).
//!
//! Every other test in this crate is this crate talking to itself. The
//! status mappings are proven against a scripted `HttpClient` that answers
//! whatever the test told it to, and the round trip against a decryptor
//! written from the RFC text — independent readings, but both of them ours.
//! Two consistent misreadings of the same paragraph agree with each other
//! perfectly, and a browser push service cannot be driven headlessly to
//! settle it.
//!
//! Web Push has an escape hatch APNs and FCM do not. **ntfy** (Apache-2.0 /
//! GPL-2.0, a single Go binary) is a UnifiedPush distributor: a
//! `https://<ntfy>/<topic>?up=1` endpoint accepts exactly the RFC 8030
//! request a browser push service accepts, and hands the body back — still
//! encrypted, base64-encoded — over its own JSON API. So this test
//!
//! 1. generates a subscription the way a browser does (a fresh P-256 key
//!    pair and a 16-byte `auth` secret, held only here),
//! 2. sends through the real [`WebPush`] adapter over the native runtime's
//!    `HttpClient` — a real socket, a real server, nothing scripted,
//! 3. reads the stored body back out of ntfy, and
//! 4. **opens it with the private key from step 1.**
//!
//! Step 4 is the proof. A server that is not ours accepted the request,
//! stored ciphertext it could not read, and what came back out is the
//! notification.
//!
//! # Running it
//!
//! Skips, with the reason printed, when `NTFY_URL` is unset — so
//! `cargo test --workspace` stays green without Docker. Locally:
//!
//! ```sh
//! docker run --rm -p 8090:80 \
//!   -e NTFY_VISITOR_SUBSCRIBER_RATE_LIMITING=false \
//!   binwiederhier/ntfy:v2.28.0 serve
//! NTFY_URL=http://127.0.0.1:8090 cargo test -p cratefield-adapter-webpush \
//!   --test ntfy_live -- --nocapture
//! ```
//!
//! `127.0.0.1`, not `localhost`: the native runtime's `HttpClient` refuses
//! loopback *names* outright, before any resolver is consulted, so that the
//! answer never depends on `/etc/hosts` (`ports::http::vet_domain`). The
//! address form is admitted by `OutboundOptions::allow_loopback`, which the
//! test sets and a deployment does not.
//!
//! # What this test does not prove
//!
//! `PushError::Unregistered`. ntfy's "nobody is listening" signal is a
//! `507` (see below), not the `410` RFC 8030 defines as gone, and no real
//! server produces a `410` on demand — that mapping stays a unit test in
//! `webpush.rs`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use cratefield_adapter_webpush::WebPush;
use cratefield_adapter_webpush::vapid::VapidKeys;
use cratefield_core::{
    HttpClient, Notification, Priority, Push, PushError, PushOutcome, Recipient,
};
use cratefield_runtime_native::{OutboundOptions, ReqwestClient, TokioClock};
use p256::SecretKey;
use serde_json::Value;
use support::{decrypt, public_key_of};

/// A throwaway P-256 key, generated for these tests only — NOT a real VAPID
/// key. The same one `webpush.rs`, `cratefield-push-auth` and
/// `cratefield-adapter-apns` use.
const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n-----END PRIVATE KEY-----";
const SUBJECT: &str = "mailto:ops@example.test";

/// The line the CI job greps for. A test that skips is a silent no-op, and
/// this leg exists precisely because silent no-ops are the failure mode
/// worth spending a container on.
const MARKER: &str = "ntfy conformance:";

/// How long the poll for the relayed message keeps trying. ntfy writes to
/// its message cache on the publish path, so the first attempt normally
/// wins; the budget is for a loaded runner, not for an eventually
/// consistent store.
const POLL_ATTEMPTS: usize = 25;
const POLL_INTERVAL: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------
// The server under test

/// The ntfy base URL from `NTFY_URL`, when set (trimmed, no trailing slash).
fn base_url() -> Option<String> {
    std::env::var("NTFY_URL")
        .ok()
        .map(|url| url.trim().trim_end_matches('/').to_owned())
        .filter(|url| !url.is_empty())
}

/// The skip reason, printed when there is no server to talk to.
fn skip_reason() -> &'static str {
    "NTFY_URL is not set — start one with `docker run --rm -p 8090:80 \
     -e NTFY_VISITOR_SUBSCRIBER_RATE_LIMITING=false binwiederhier/ntfy:v2.28.0 serve` \
     and set NTFY_URL=http://127.0.0.1:8090 (the address, not `localhost`)"
}

/// A UnifiedPush topic, shaped the way a distributor's own are: the `up`
/// prefix and 14 characters in total.
///
/// ntfy treats a topic beginning with `up` as a UnifiedPush topic in
/// addition to the `?up=1` marker, and its subscriber-based rate limiting
/// is eligible for a topic of exactly 14 characters, the `up` included
/// (`unifiedPushTopicPrefix` / `unifiedPushTopicLength` in
/// `server/server.go`). Matching that shape is
/// deliberate: if `visitor-subscriber-rate-limiting` is ever on, this topic
/// earns the `507` and the leg fails loudly, where a differently-shaped
/// topic would sail past the trap and prove less than it claims.
fn unified_push_topic() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut raw = [0u8; 12];
    getrandom::fill(&mut raw).expect("the platform has randomness");
    let mut topic = String::from("up");
    for byte in raw {
        topic.push(char::from(ALPHABET[usize::from(byte) % ALPHABET.len()]));
    }
    topic
}

// ---------------------------------------------------------------------------
// The browser

/// The half of a subscription a browser keeps to itself: the P-256 private
/// key and the `auth` secret. Only this value can open what the adapter
/// sends.
struct Browser {
    private: [u8; 32],
    auth: [u8; 16],
}

impl Browser {
    /// A fresh subscription, drawn the way `pushManager.subscribe()` does —
    /// per test, never a constant, so a body that decrypts cannot be one
    /// that decrypts against a key baked into the encoder.
    fn subscribe() -> Self {
        loop {
            let mut private = [0u8; 32];
            getrandom::fill(&mut private).expect("the platform has randomness");
            // A uniform 32 octets is a valid P-256 scalar with probability
            // 1 - 2^-32; the loop is for the case that never happens.
            if SecretKey::from_slice(&private).is_err() {
                continue;
            }
            let mut auth = [0u8; 16];
            getrandom::fill(&mut auth).expect("the platform has randomness");
            return Self { private, auth };
        }
    }

    /// The `p256dh` the subscription publishes.
    fn p256dh(&self) -> String {
        URL_SAFE_NO_PAD.encode(public_key_of(&self.private))
    }

    /// The `auth` secret the subscription publishes.
    fn auth(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.auth)
    }

    /// What the service worker would read out of `event.data.json()`.
    fn open(&self, body: &[u8]) -> Value {
        let plaintext = decrypt(&self.private, &self.auth, body).unwrap_or_else(|err| {
            panic!(
                "the browser could not open what ntfy relayed ({err:?}) — the RFC 8291 \
                 implementation does not interoperate, which is the one thing this leg exists \
                 to catch"
            )
        });
        serde_json::from_slice(&plaintext).unwrap_or_else(|err| {
            panic!(
                "the decrypted body is not the JSON payload the adapter builds: {err} \
                 (as text: {})",
                String::from_utf8_lossy(&plaintext)
            )
        })
    }
}

// ---------------------------------------------------------------------------
// The exchange

/// The adapter, over a client that will talk to a loopback address.
///
/// `allow_loopback` is the whole difference from a deployment's client: the
/// outbound policy (issue #136) refuses non-routable destinations, and a
/// test server is exactly one.
fn adapter() -> (WebPush, Arc<ReqwestClient>) {
    let http = Arc::new(ReqwestClient::with_options(OutboundOptions {
        allow_loopback: true,
        ..OutboundOptions::default()
    }));
    let push = WebPush::new(
        http.clone(),
        Arc::new(TokioClock),
        VapidKeys::new(TEST_PEM, SUBJECT),
    )
    .expect("a valid VAPID key");
    (push, http)
}

/// Sends and insists on a 2xx, naming the two failures that mean something
/// specific rather than letting them arrive as "the test failed".
async fn publish(push: &WebPush, endpoint: &str, browser: &Browser, notification: &Notification) {
    let to = Recipient::web_push(endpoint, browser.p256dh(), browser.auth());
    match push.send(&to, notification).await {
        Ok(PushOutcome::Delivered { id }) => {
            // ntfy answers `200 OK` with no `Location`, where RFC 8030
            // specifies `201 Created` with one. Both are accepted; the
            // adapter's README says why.
            println!("{MARKER} publish accepted, id={id:?}");
        }
        Ok(PushOutcome::NotConfigured) => {
            panic!("the adapter reported NotConfigured: the test's VAPID key did not load")
        }
        // The trap this leg was built around. ntfy answers 507 / code 50701
        // "cannot publish to UnifiedPush topic without previously active
        // subscriber" when it runs with `visitor-subscriber-rate-limiting`
        // on, as the public ntfy.sh does. Nothing was delivered, nothing was
        // decrypted, and a skip here would be indistinguishable from a pass.
        Err(PushError::Rejected(message)) if message.contains("507") => panic!(
            "ntfy refused the publish with 507: the server has \
             `visitor-subscriber-rate-limiting` enabled, so a UnifiedPush publish needs a \
             previously active subscriber on the topic. Start it with \
             NTFY_VISITOR_SUBSCRIBER_RATE_LIMITING=false. ({message})"
        ),
        Err(err) => panic!("the publish to a real ntfy server failed: {err}"),
    }
}

/// Polls ntfy's own JSON API until the message shows up, and returns it.
///
/// `GET /<topic>/json?poll=1` replays the cached messages as newline-
/// delimited JSON and closes — no `open` event, no keepalives, which is why
/// it is the poll form and not the stream.
async fn relayed_message(http: &Arc<ReqwestClient>, base: &str, topic: &str) -> Value {
    let uri = format!("{base}/{topic}/json?poll=1");
    for attempt in 0..POLL_ATTEMPTS {
        let request = http::Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Bytes::new())
            .expect("a well-formed request");
        let response = http
            .send(request)
            .await
            .unwrap_or_else(|err| panic!("could not reach ntfy's JSON API: {err}"));
        assert!(
            response.status().is_success(),
            "ntfy's JSON API answered {}: {}",
            response.status(),
            String::from_utf8_lossy(response.body())
        );
        let body = String::from_utf8_lossy(response.body()).into_owned();
        for line in body.lines().filter(|line| !line.trim().is_empty()) {
            let message: Value = serde_json::from_str(line).unwrap_or_else(|err| {
                panic!("ntfy answered a line that is not JSON: {err} ({line})")
            });
            if message.get("event").and_then(Value::as_str) == Some("message") {
                return message;
            }
        }
        if attempt + 1 < POLL_ATTEMPTS {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    panic!(
        "ntfy never replayed a message on {topic} — the publish was accepted but nothing was stored"
    );
}

/// The still-encrypted body, out of the message ntfy stored.
///
/// ntfy base64-encodes a UnifiedPush body only when it is not valid UTF-8
/// (`handleBodyAsMessageAutoDetect`), and an `aes128gcm` body is
/// indistinguishable from random, so in practice it is always the base64
/// branch — but "in practice" is not "always", and the field that says
/// which is right there.
fn encrypted_body(message: &Value) -> Vec<u8> {
    let text = message
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("ntfy's message has no `message` field: {message}"));
    match message.get("encoding").and_then(Value::as_str) {
        Some("base64") => STANDARD
            .decode(text)
            .unwrap_or_else(|err| panic!("ntfy's own base64 did not decode: {err}")),
        None => text.as_bytes().to_vec(),
        Some(other) => panic!("ntfy used an encoding this test does not know: {other}"),
    }
}

// ---------------------------------------------------------------------------
// The tests

/// The whole point: a real third-party server relays a body only the
/// browser's private key can open.
#[tokio::test]
async fn a_real_ntfy_server_relays_a_body_only_the_browser_can_open() {
    let Some(base) = base_url() else {
        println!("skipped: {}", skip_reason());
        return;
    };

    let browser = Browser::subscribe();
    let topic = unified_push_topic();
    let endpoint = format!("{base}/{topic}?up=1");
    let (push, http) = adapter();

    let notification = Notification {
        data: serde_json::json!({ "room": "sauna", "starts_in": 10 }),
        ..Notification::new("Room starting", "Yoga in 10 minutes")
    };
    publish(&push, &endpoint, &browser, &notification).await;

    let message = relayed_message(&http, &base, &topic).await;
    assert_eq!(
        message.get("topic").and_then(Value::as_str),
        Some(topic.as_str()),
        "ntfy stored the message under another topic: {message}"
    );

    let body = encrypted_body(&message);
    // The server held ciphertext. If the plaintext were readable in what
    // ntfy stored, everything below would still pass and the encryption
    // would be doing nothing.
    assert!(
        !contains(&body, notification.title.as_bytes()),
        "the notification title is readable in the body ntfy stored — it was not encrypted"
    );
    assert!(
        !contains(&body, notification.body.as_bytes()),
        "the notification body is readable in the body ntfy stored — it was not encrypted"
    );
    // RFC 8188 §2.1: salt(16) | rs(4) | idlen(1) | keyid(65).
    assert_eq!(
        body.get(20).copied(),
        Some(65),
        "the `idlen` octet of the header ntfy relayed is not a P-256 point length"
    );

    let opened = browser.open(&body);
    assert_eq!(opened["title"], "Room starting");
    assert_eq!(opened["body"], "Yoga in 10 minutes");
    assert_eq!(opened["silent"], false);
    assert_eq!(opened["data"]["room"], "sauna");
    assert_eq!(opened["data"]["starts_in"], 10);
    println!(
        "{MARKER} decrypted {} octets relayed by ntfy: {opened}",
        body.len()
    );
}

/// The rest of the RFC 8030 request, against a server that is not a fake:
/// `TTL`, `Urgency` and `Topic` are all sent, and a real distributor
/// accepts them.
///
/// It also records what ntfy does with them: **nothing**. ntfy reads
/// `Content-Encoding` (which alone marks a publish as UnifiedPush) and its
/// own `X-*` headers, and no `TTL`, `Urgency` or `Topic` — verified against
/// v2.28.0's `parsePublishParams`, which is the version the CI job pins by
/// digest. So the assertion is their **absence** from what ntfy exposes: a
/// tripwire for the day an image bump changes it, not a claim that the
/// headers do not matter (a browser push service acts on all three).
#[tokio::test]
async fn the_optional_rfc8030_headers_are_accepted_by_a_real_server() {
    let Some(base) = base_url() else {
        println!("skipped: {}", skip_reason());
        return;
    };

    let browser = Browser::subscribe();
    let topic = unified_push_topic();
    let endpoint = format!("{base}/{topic}?up=1");
    let (push, http) = adapter();

    let notification = Notification {
        collapse_id: Some("room-42".to_owned()),
        thread_id: Some("sauna".to_owned()),
        ttl: Some(Duration::from_secs(60)),
        priority: Priority::Conserve,
        icon: Some("https://example.test/icon.png".to_owned()),
        url: Some("https://example.test/rooms/42".to_owned()),
        silent: true,
        ..Notification::new("Room ending", "Five minutes left")
    };
    publish(&push, &endpoint, &browser, &notification).await;

    let message = relayed_message(&http, &base, &topic).await;
    for ignored in ["ttl", "urgency", "title", "click", "icon"] {
        assert!(
            message.get(ignored).is_none(),
            "ntfy now exposes `{ignored}`, which v2.28.0 did not read from an RFC 8030 \
             request: {message}"
        );
    }

    let opened = browser.open(&encrypted_body(&message));
    assert_eq!(opened["title"], "Room ending");
    assert_eq!(opened["tag"], "sauna", "thread_id is the payload's `tag`");
    assert_eq!(opened["icon"], "https://example.test/icon.png");
    assert_eq!(opened["url"], "https://example.test/rooms/42");
    assert_eq!(opened["silent"], true);
    assert!(
        opened.get("collapse_id").is_none(),
        "collapse_id is the `Topic` header, never a payload field: {opened}"
    );
    println!("{MARKER} the full header set was accepted and the payload round-tripped");
}

/// Whether `haystack` contains `needle`, for the "it really is ciphertext"
/// assertions.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
