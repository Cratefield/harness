# factory0-adapter-turnstile

[`Captcha`] port over Cloudflare [Turnstile](https://developers.cloudflare.com/turnstile/)
`siteverify` for the Factory Zero harness. Runs on the runtime's
`HttpClient` port; the 5 s timeout is supplied by the runtime's `Clock`.

## Usage

```rust,ignore
use std::sync::Arc;
use factory0_adapter_turnstile::Turnstile;
use factory0_runtime_cloudflare::{FetchClient, WorkersClock};

// Turnstile::from_env returns None when TURNSTILE_SECRET is absent — the
// port is then simply not provided, and fz doctor refuses a production
// build whose modules write publicly without captcha.
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
  mismatch fails with `hostname-mismatch`.
