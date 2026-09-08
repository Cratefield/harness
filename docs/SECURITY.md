# Security policy

## Assets and entry points

| Asset | Exposure |
|---|---|
| `HARNESS_SECRET` (and `HARNESS_SECRET_PREVIOUS`) | Workers secret; signs confirm/unsubscribe/status tokens (ADR 0006) |
| `ADMIN_TOKEN` | Workers secret; gates `/v1/<module>/admin/*` |
| `RESEND_API_KEY`, `TURNSTILE_SECRET` | Adapter secrets, read by the venture's runtime composition |
| Subscriber/waitlist tables (D1/SQLite) | Email addresses + state; per-venture database |
| Public HTTP surface | `/v1/email-signup`, `/v1/waitlist` (+ `confirm`/`unsubscribe`/`status`), `/__health`, `/__ready` |

## Controls (architecture section 11)

- **No enumeration.** Signup and waitlist writes answer a byte-identical
  `202` for every row state; tests compare all four responses byte for
  byte.
- **Signed, purpose-scoped, expiring tokens.** HMAC-SHA256 with key
  rotation by `kid`; MAC comparison constant-time (`subtle`); single-use
  via row state.
- **Fixed redirects.** Confirm/unsubscribe/status redirect only to URLs
  from `Venture` config or module builders; a test asserts no route
  reads `redirect`/`return`/`next` query parameters.
- **Admin auth.** `cratefield_core::admin::require_admin`: disabled (401)
  when `ADMIN_TOKEN` is unset, SHA-256-digest constant-time compare,
  403 on a wrong token; the token never appears in tracing fields.
- **CSV formula-injection guard.** `cratefield_core::csv::escape` prefixes
  `= + - @ \t \r` leading cells with `'` before RFC 4180 quoting.
- **Rate limits on every public route** — including confirm and status —
  keyed `ip:<cf-connecting-ip>` (never `x-forwarded-for` on Workers) and
  `email:<normalized>`; 429 carries `Retry-After`.
- **Captcha mandatory in production** when any module has
  `public_writes()`: `fz doctor` fails the build; `--allow-no-captcha
  <reason>` downgrades to a warning for the stated reason.
- **PII minimalism and retention.** See [PRIVACY.md](PRIVACY.md).
- **Redaction.** Field names matching `(?i)secret|token|key|
  authorization|password` are replaced with `[redacted]`; email values
  appear only as a 12-hex `subject_hash` — a **keyed** HMAC pseudonym
  (`HMAC-SHA256` under a key the runtime derives from `HARNESS_SECRET`,
  domain-separated) so a low-entropy address is not dictionary-reversible
  (issue #135); with no key installed it emits the fixed placeholder
  `000000000000` instead — fail-closed, never a bare digest.
  Redaction is also **value-level**: any other logged string — a generic
  `error`, `uri` or message — is scrubbed by `cratefield_core::scrub_text`
  before it reaches a sink, replacing embedded emails with their
  pseudonym and URL/path queries, dotted signed tokens, `Bearer`
  credentials and URL userinfo with `[redacted]`. `DbError`'s `Display`
  scrubs the wrapped driver message the same way, so a Postgres
  `DETAIL:` line quoting a row cannot disclose it. The internal-error
  forwarder scrubs each line it hands to the runtime sink.
  Rules in `cratefield_core::logging`, shared by every runtime formatter;
  verified by tests.
- **Token-bearing URLs.** Signed links carry their credential in the
  query (`?token=`). Every response to a request whose query has a
  `token` parameter — on any path, including `/ui/*` — carries
  `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer`, so no cache stores the credential and
  no outbound navigation leaks it through `Referer` (issue #135). The
  admin hard-delete route keys on the opaque row id, never the email
  (`DELETE /v1/email-signup/admin/subscribers/{id}`).
- **No `unsafe`** in core or any module (`#![forbid(unsafe_code)]`); the
  only `unsafe`-adjacent code is `worker::send::SendWrapper` inside the
  `worker` crate (ADR 0002).

## Dependency policy

- `cargo deny check` runs in CI on every PR: advisories (vulnerabilities
  and yanked crates) are **deny**, licenses restricted to the allowlist
  in `deny.toml`, unknown registries and git sources denied.
- Runtime dependency boundaries are enforced in CI: `cratefield-core` and
  every `cratefield-module-*` must build to `wasm32-unknown-unknown` and
  must not pull `worker`, `wasm-bindgen`, `tokio`, `reqwest`, `sqlx` or
  `rusqlite` (the example venture's `worker-build` job catches it).
- Ventures pin exact crate versions; Renovate opens bumps, CI re-runs
  the full deny + build gate on every bump.

## Out of scope

- The Cloudflare account, D1 infrastructure and Workers secrets
  provisioning (managed by each venture's deployment workflow).
- The `factory0.ventures` website and any front end that posts to the
  API.
- The phase-3 native runtime and Postgres adapter (separate review when
  they land).

## Reporting a vulnerability

Report privately to `security@factory0.ventures` (or a GitHub security
advisory on `Cratefield/harness`). Please include reproduction steps
and affected commit; do not open a public issue for exploitable
findings. We aim to respond within 72 hours and will credit reporters
unless anonymity is requested.
