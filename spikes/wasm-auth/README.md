# spikes/wasm-auth — auth issue #2 spike

Scratch crate answering the four questions of
[issue #2](https://github.com/Factory-Zero/auth/issues/2): can WebAuthn,
OpenID Connect and argon2 run on Cloudflare Workers (wasm32)?

It is a spike: rough by design, no production code. Answers and risks live in
`docs/adr/0100-wasm-crypto-and-webauthn.md`; per-question evidence commands
are below.

## Layout

- `src/q2_webauthn.rs` — pure-Rust WebAuthn relying-party verification
  (registration + assertion, attestation format `none` accepted).
- `src/q3_oidc.rs` — `openidconnect` wired to a copy of the harness
  `HttpClient` port, driven by recorded Google fixtures.
- `src/q4_bench.rs` — argon2 parameter measurement endpoint.
- `examples/mint_passkey.rs` — host-only software authenticator that records
  `fixtures/passkey.json` (deterministic RFC 6979 signature, so the fixture is
  byte-reproducible).
- `examples/mint_id_token.rs` — host-only minter for the Google-shaped ID
  token and JWKS fixtures (`fixtures/google-*.{json,jwks}`).
- `src/port.rs` — the harness `HttpClient` port, copied verbatim from
  `Factory-Zero/harness` `crates/core/src/ports/http.rs` (commit `f0c0179`,
  2026-09-06). Copied instead of a git dependency so the spike does not pull
  `factory0-core`'s axum tree into the wasm build; the trait is identical, so
  the adapter proven here transfers unchanged.

## Build and run

```sh
cargo build --target wasm32-unknown-unknown   # whole workspace builds for wasm
cd spikes/wasm-auth
worker-build --release                        # Workers bundle (build/worker/)
bunx wrangler dev                             # serve on http://127.0.0.1:8787
```

## Q1 — does webauthn-rs main build for wasm32?

No. Evidence (run outside this crate, e.g. in /tmp):

```sh
cargo new q1-probe && cd q1-probe
cat >> Cargo.toml <<'EOF'
webauthn-rs = { git = "https://github.com/kanidm/webauthn-rs", rev = "be696b79800bd1953df78e87d0215571733cc26f", default-features = false }
EOF
cargo build --target wasm32-unknown-unknown
# error: failed to run custom build command for `openssl-sys v0.9.117`
cargo tree --target wasm32-unknown-unknown -i openssl-sys
# openssl 0.10.81 -> webauthn-attestation-ca 0.5.5 and webauthn-rs-core 0.5.5
```

`master@be696b7` (2026-06-02, workspace version still 0.5.5) declares
`openssl.workspace = true` and `openssl-sys.workspace = true` in
`webauthn-rs-core` as hard dependencies — no feature disables them, and
`default-features = false` (attestation off) does not help.

## Q2 — pure-Rust verification, proven in wasm

```sh
cargo run -p wasm-auth-spike --example mint_passkey   # records fixtures/passkey.json
cargo test -p wasm-auth-spike                         # 5 native tests, incl. tamper/replay rejection
cd spikes/wasm-auth && worker-build --release && bunx wrangler dev &
curl -s -X POST localhost:8787/q2/verify-passkey \
  -H 'content-type: application/json' --data @fixtures/passkey.json
# {"verified":true,"sign_count":2,...}  — inside wrangler dev, i.e. in wasm
```

The fixture is recorded by a software authenticator (no hardware key on the
spike machine): real ES256 math over spec-shaped `authenticatorData` and
Chrome-shaped `clientDataJSON`, wire-encoded with `webauthn-rs-proto` types.
That limitation is recorded in the ADR.

## Q3 — openidconnect through the harness HttpClient port

```sh
cargo run -p wasm-auth-spike --example mint_id_token  # records google-* fixtures
cargo test -p wasm-auth-spike                          # 3 native tests incl. wrong aud/nonce
cd spikes/wasm-auth && worker-build --release && bunx wrangler dev &
curl -s localhost:8787/q3/oidc | python3 -m json.tool
```

Inside `wrangler dev` the report shows three ok steps: **discovery runs
live** against the real Google document through the port (`src/port.rs`,
copied verbatim from the harness) over `worker::Fetch`; the token exchange
is served from `fixtures/google-token-response.json` by intercepting the
real token endpoint URL inside the adapter; the Google-shaped RS256 ID token
(`fixtures/google-token-response.json` + `fixtures/google-jwks.json`, minted
by the host-only example) verifies — signature, issuer, audience, expiry,
nonce. No Google client exists on the spike machine, so exchange/verify are
fixture-driven and the ADR says so.

Integration finding: the port's `#[async_trait]` future must be `Send`, but
every `worker`/wasm-bindgen handle is `!Send`; the adapter bridges with
`spawn_local` + a Send oneshot channel. The harness Workers adapter needs
the same pattern (or the port needs `?Send` futures on wasm).
