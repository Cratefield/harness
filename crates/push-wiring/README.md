<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-push-wiring

The runtime wiring for the push adapters (issue #191): given a venture's
environment, which push transports exist, and how do they become the single
`Arc<dyn Push>` a module receives?

One table of variable names, one function that reads it, and every call site
— `serve()` on both runtimes, `fz push send`, `fz doctor` — calls that
function. Reading the names in three places is how a venture ends up with a
`serve()` that wires FCM, a doctor that checks a different variable, and an
Android notification that silently never sends.

```rust,ignore
use cratefield_push_wiring::{build_push, WiringSeverity};

let (push, wiring) = build_push(&config, http, clock);
// One line, names and verdicts only — never a value:
//   push wiring: apns=configured fcm=partial (set: …; unset: …) web_push=absent
tracing::info!("{}", wiring.summary());
match wiring.severity(env) {
    WiringSeverity::Ok => {}
    WiringSeverity::Warning => for p in wiring.problems() { tracing::warn!("{p}") },
    WiringSeverity::Error => for p in wiring.problems() { tracing::error!("{p}") },
}
let runtime = Cloudflare::new().push_arc(push);
```

Or let the runtime do it, which is what the example venture does:

```rust,ignore
let runtime = Cloudflare::new().db("DB").push_from_env();  // feature = "push"
```

## Verdicts

| Verdict | When | Consequence |
|---|---|---|
| `configured` | every required variable is set and the adapter accepted them | routed |
| `absent` | not one of the transport's variables is set | not routed; `NotConfigured`. A choice, not a defect |
| `partial` | some are set and some are not | not routed. **Error in production**, warning elsewhere |
| `invalid` | all are set and the adapter refused them | not routed. **Error in production**, warning elsewhere |

Partial is the case this crate exists for. A venture that meant to enable FCM
and mistyped one variable must not boot into a state where every Android send
answers `NotConfigured` and nothing says why.

Nothing is ever broken by a bad environment: an unrouted transport degrades
to `PushOutcome::NotConfigured`, the same contract each adapter's
`not_configured()` constructor gives, so a Worker with nothing configured
still boots and still answers every send.

## The variables

`docs/NOTIFICATIONS.md` is generated from this crate's `PUSH_ENV` table:

```sh
cargo run -p cratefield-push-wiring --example notifications-doc          # write
cargo run -p cratefield-push-wiring --example notifications-doc -- --check
```

No other Rust source in the workspace may name one of those keys in a string
literal; `crates/cli-acceptance/tests/push_env_guard.rs` fails the build if
one does.
