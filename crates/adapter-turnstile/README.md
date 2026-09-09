<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-turnstile"><img src="https://img.shields.io/crates/v/cratefield-adapter-turnstile.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-turnstile on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-turnstile"><img src="https://img.shields.io/docsrs/cratefield-adapter-turnstile?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-turnstile documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-turnstile

[`Captcha`] port over Cloudflare [Turnstile](https://developers.cloudflare.com/turnstile/)
`siteverify` for the Factory Zero harness. Runs on the runtime's
`HttpClient` port; the 5 s timeout is supplied by the runtime's `Clock`.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_turnstile::Turnstile;
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

// Turnstile::from_env returns None when TURNSTILE_SECRET is absent — the
// port is then simply not provided, and Harness::build refuses a
// production venture whose routes declare a HumanForm policy without an
// effectively configured captcha (issue #133). TURNSTILE_HOSTNAME and
// TURNSTILE_ACTION, when set, bind the matching checks.
let runtime = match Turnstile::from_env(Arc::new(FetchClient), Arc::new(WorkersClock)) {
    Some(turnstile) => runtime.captcha(turnstile),
    None => runtime,
};
```

Behavior:

- `verify(token, remote_ip)` POSTs `secret`, `response`, `remoteip` as a
  form to `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
- The verdict's `reason` is the **first** `error-codes` entry.
- Transport failure or timeout is **fail-closed**:
  `{ ok: false, reason: "unavailable" }`. `.fail_open(true)` flips that
  for staging only.
- `.expected_hostname("example.com")` checks the response `hostname`; a
  mismatch — or a response that omits the hostname — fails with
  `hostname-mismatch`.
- `.expected_action("signup")` checks the response `action`, so a token
  minted for another widget flow cannot authorize this one; mismatch or
  absence fails with `action-mismatch`.
- `Captcha::binding()` reports both checks (and the fail-open posture) so
  `Harness::build` can tell "port provided" from "verification actually
  configured" for `HumanForm` routes (issue #133).
