# ADR 0200: wasm32 crypto and WebAuthn on Workers

Status: proposed (spike result). Date: 2026-09-06. Issue: #2.

Context: the passkey, OIDC and password modules of this service must run
inside one Cloudflare Worker (wasm32-unknown-unknown). The spike
(`spikes/wasm-auth`, branch `spike/wasm-compile`) answered four questions;
every claim below is reproducible with the commands in
`spikes/wasm-auth/README.md`.

## Q1 — does webauthn-rs main build for wasm32? No.

`webauthn-rs` master at `be696b79800bd1953df78e87d0215571733cc26f`
(2026-06-02, workspace version still 0.5.5) does not build for
wasm32-unknown-unknown: `cargo build --target wasm32-unknown-unknown`
fails in `openssl-sys v0.9.117`'s build script (exit 101).
`cargo tree --target wasm32-unknown-unknown -i openssl-sys` shows
`openssl 0.10.81` as a hard dependency of both `webauthn-rs-core 0.5.5`
and `webauthn-attestation-ca 0.5.5`. There is no feature to switch it
off and `default-features = false` (attestation off) does not help. The
0.6 pre-release line has not removed OpenSSL.

## Q2 — the pure-Rust verification path. Adopted.

Since upstream cannot compile to wasm, relying-party verification is
implemented directly on:

- `webauthn-rs-proto 0.5.5` — wire types (`RegisterPublicKeyCredential`,
  `PublicKeyCredential`, `CollectedClientData`); pure serde deps, builds
  on wasm32.
- `ciborium 0.2.2` + `coset 0.4.2` — attestation-object CBOR and COSE
  key parse/serialise.
- `p256 0.14.0` + `sha2 0.10.9` — ES256 verification over
  `authenticatorData || SHA-256(clientDataJSON)`.

Scope: registration and assertion only; attestation format `none`
accepted, other formats stored unverified (the consumer-relying-party
position). Checks implemented: rpId hash, UP/UV flags, client-data
type/challenge/origin, credential-id match, signature-counter advance,
signature. Size: ~340 lines in `src/q2_webauthn.rs` — inside the "a few
hundred lines" estimate.

Proof: `fixtures/passkey.json`, recorded by a software authenticator
(`examples/mint_passkey.rs`, fixed key, deterministic RFC 6979 signing —
no hardware authenticator on the spike machine, so the fixture is
machine-generated but the ES256 math, authenticator-data layout and
Chrome-shaped clientDataJSON are real). The fixture verifies inside
`wrangler dev` (`POST /q2/verify-passkey` -> `verified:true,
sign_count:2`); native tests reject a tampered signature, a wrong
challenge, a wrong origin and a replayed assertion.

Risks: no hardware-authenticator fixture yet; attestation formats other
than `none` are accepted but unverified (deliberate); counter semantics
simplified (strictly-greater when both non-zero); no extension outputs
checked. Production work must add: challenge storage in D1
(delete-on-use per the architecture), origin allow-list per client, and
a hardware-authenticator fixture in CI.

## Production status of Q2 (issues #13, #14)

`crates/auth-passkeys` carries the spike's verification into production.
Three of the four things this ADR listed as missing are now done, and the
fourth is recorded rather than quietly dropped:

- **Challenge storage in D1**: done. Challenges are `single_use_tokens`
  rows consumed by auth-core's conditional update, whose affected-row
  count decides which of two concurrent attempts wins. Registration and
  login challenges carry a purpose and are not interchangeable.
- **Origin allow-list**: done, and checked at configuration time rather
  than per request. An origin that is not the RP id or a subdomain of it
  is a configuration error, because such a ceremony could never be valid.
- **Counter semantics**: unchanged (strictly greater when both are
  non-zero), and a regression now marks the credential suspect and keeps
  refusing it, rather than only failing the one login.
- **Algorithms**: the spike verified ES256 only. Production also accepts
  RS256 (Windows Hello) and EdDSA, each with its own test; an unsupported
  COSE key is refused at registration rather than stored and failed at
  every later login.
- **User verification**: the spike required the UV flag. Production
  requires user *presence* always and user *verification* only when the
  configured policy is `required`, because refusing under `preferred`
  would shut out every security key without a PIN.
- **Check order**: the signature is verified before the counter is
  compared, which is the spec's order (7.2 steps 21 then 22). The spike had
  it the other way round, which was harmless there because it persisted
  nothing; a module that marks a credential on a counter regression must
  not act on an assertion it has not verified.
- **Extension outputs**: the authenticator data may carry a CBOR extension
  map after the credential data, and Chrome asks for `credProtect` under
  exactly the options this module sends. The spike treated those bytes as
  corruption; production reads past them.
- **Still missing: a hardware-authenticator fixture.** The tests mint
  ceremonies with a software authenticator, which exercises all three
  algorithms and every negative case but cannot prove a real device's
  quirks. Issue #13's last acceptance box — a manual run in a browser
  against `wrangler dev` — remains the only thing that can close that,
  and it needs hardware CI does not have.

## Q3 — openidconnect through the harness HttpClient port. Works.

`openidconnect 4.0.1` (default features off; no reqwest) +
`oauth2 5.0.0` build to wasm32 unchanged. The harness `HttpClient` port
(`http::Request<Bytes> -> http::Response<Bytes>`, `Send + Sync`,
async_trait) was copied verbatim into `src/port.rs` and implemented over
`worker::Fetch`. `oauth2`'s `AsyncHttpClient` is implemented over that
port (`OidcHttpClient`) — this adapter transfers unchanged to the real
harness crate.

Proven inside `wrangler dev` (`GET /q3/oidc`): **discovery runs live**
against the real Google document through the port (issuer
`https://accounts.google.com`, token endpoint
`https://oauth2.googleapis.com/token`); **token exchange and ID-token
verification run from recorded fixtures** — no Google client credential
exists on the spike machine, so the adapter intercepts the token and
JWKS endpoints and serves `fixtures/google-token-response.json` /
`fixtures/google-jwks.json`, a Google-shaped RS256 ID token minted by
`examples/mint_id_token.rs`. Verification checks signature, issuer,
audience, expiry and nonce, and extracts `sub` + `email`. Native tests
reject a wrong audience and a wrong nonce.

Integration finding (must reach the harness): the port's `#[async_trait]`
requires `Send` futures, but every `worker`/wasm-bindgen handle is
`!Send` (single-threaded runtime). The adapter bridges with
`wasm_bindgen_futures::spawn_local` plus a Send oneshot channel
(`futures-channel`). Either the harness Workers adapter adopts the same
bridge, or the port grows a `?Send`-future variant for wasm targets.
Also: ID-token `exp`/`iat` checks need `IdTokenVerifier::set_time_fn`
backed by `worker::Date` (chrono's default `Utc::now` is unusable on
wasm32).

Risk: the token exchange is fixture-driven, not live; first production
integration must run one live code exchange against a real Google
client. Provider JWKS should be cached (KV) rather than fetched per
login — out of spike scope.

## Q4 — argon2 cost on Workers. Measured.

Argon2id v19 in `wrangler dev` (local workerd, Apple Silicon host),
2026-09-06; each cell = 3 x (hash + verify), time from `Date.now()`
inside the Worker (advances in local dev) and external wall time:

| m (KiB) | t | p | internal ms | external s |
|---|---|---|---|---|
| 19456 | 2 | 1 (OWASP minimal) | 118 | 0.12 |
| 19456 | 3 | 1 | 173 | 0.18 |
| 32768 | 2 | 1 | 204 | 0.21 |
| 47104 | 1 | 1 (OWASP tolerable) | 144 | 0.15 |
| 65536 | 2 | 1 | 413 | 0.42 |
| 65536 | 3 | 1 | 626 | 0.63 |
| 131072 | 2 | 1 | 931 | 0.93 |
| 19456 | 2 | 2 | 117 | 0.12 |

Recommendation: **m=19456 KiB, t=2, p=1** (~40 ms per hash+verify
locally; ~20 ms for a single verify). It is OWASP's minimal preset,
leaves three orders of magnitude of headroom under the paid-plan 30 s
CPU limit, and keeps login latency low. p>1 adds nothing on a Worker
(single-threaded). Escalate to m=47104/t=1 only if a slower hash per
attempt is preferred. Caveats: local workerd on one machine, not a
deployed Worker (no Cloudflare credentials on this machine) — re-measure
on staging during auth-password and keep a config knob. **The free
tier's 10 ms CPU cannot fit even one Argon2id verify at any sane
parameters — password login requires the paid plan.**

## Hard-constraint proof

`cargo tree --target wasm32-unknown-unknown`: `openssl`, `openssl-sys`,
`reqwest` and `mio` are absent from the tree entirely. `tokio v1.53.1`
is present solely through the `worker 0.8.5` SDK (which compiles to
wasm32 cleanly); no auth dependency pulls it (0 matches in the
`openidconnect`, `argon2`, `webauthn-rs-proto`, `p256`, `coset`
subtrees). If the constraint is read as literally forbidding `worker`'s
own tokio, no Workers-based spike can satisfy it; we read it as scoped
to the dependencies added for auth, matching how it was originally
measured (scratch crate, no worker).

## Decision

Passkeys: implement relying-party verification in-house on
`webauthn-rs-proto` + `ciborium`/`coset` + `p256`/`sha2` (Q2 path),
pinning those crates; revisit upstream webauthn-rs if its 0.6 release
makes OpenSSL optional. OIDC: `openidconnect 4` through the harness
`HttpClient` port with the `spawn_local` bridge, live discovery, cached
JWKS. Passwords: Argon2id m=19456 t=2 p=1 on the paid plan, re-measured
on staging before launch.
