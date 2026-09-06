# ADR 0101: Token issuing — ES256 access tokens with a published JWKS, opaque single-use refresh tokens

Status: accepted. Date: 2026-09-06. Issue: #9.

## Context

Consuming apps must verify something on every request. Issue #9 carries
the trade-off table; it is reproduced here with the decision and the
two things investigation changed.

| | Signed JWT + published JWKS | Opaque token + introspection endpoint |
|---|---|---|
| Verification | Local, no network, one cached JWKS fetch per key rotation | One call to the auth service per request, or per cache window |
| Revocation | Only by short lifetime; a revoked session's tokens stay valid until `exp` | Immediate |
| Latency and coupling | Apps stay up when auth is down, for the token lifetime | Apps depend on auth being up, on every request |
| Cost on Workers | A signature verify per request in wasm, sub-millisecond for ES256 | A subrequest per request, which counts against Worker limits |
| Claims | Carried in the token: `sub`, `aud` (client id), `exp`, `iat`, `sid`, `email`, `email_verified`, `amr` | Returned by introspection, can change without reissuing |
| Key handling | Private key is a Worker secret; rotation via `kid` and a JWKS holding current and previous | A shared secret or mTLS between apps and auth |

## Decision

**Signed JWT, ES256, with a refresh-token backstop** — the issue's
recommendation, adopted unchanged in shape:

- **Access tokens**: ES256 (P-256), lifetime 10 minutes, RFC 9068
  shape (`typ: at+jwt`, `kid` in the header). Claims: `iss`, `sub`
  (user id), `aud` (client id), `exp`, `iat`, `sid` (session id),
  `email`/`email_verified` (present only when the user has an email),
  `amr` (the session's login methods, RFC 8176; an empty array until
  the login-method issues #13-#22 wire their values through
  `sessions::issue`).
- **Refresh tokens**: opaque, 32 random bytes base64url, single-use
  `single_use_tokens` rows of kind `refresh_token`, bound to the
  session (`payload.sid`) and the client, 30-day expiry aligned with
  the session slide window. Refreshing fails the moment the session is
  revoked, so the revocation gap is bounded by the access-token
  lifetime. **Reuse of a consumed refresh token revokes the session**
  (reuse detection) — a stolen-token replay is treated as a compromise
  alarm, not just a failed request. A token presented for the wrong
  client is refused *without* being consumed, so a wrong-client
  presentation cannot burn the rightful client's token.
- **Discovery**: `/.well-known/jwks.json` (every configured key's
  public half, `Cache-Control: public, max-age=300`) and
  `/.well-known/openid-configuration` (`max-age=3600`), served at the
  root through the harness `Module::well_known` mount (harness issue
  #46). Because `well_known()` is called without a `ModuleContext`,
  the router fills a shared cell at assembly time — when the config is
  visible — and the discovery handlers read it per request.
- **Key rotation is operational, not code**: keys live in
  configuration as JSON JWKs. Rotate by adding a key, switching the
  active id, and dropping the old key after the longest token
  lifetime; the JWKS publishes whatever the configuration holds, so
  tokens from the old key verify throughout the overlap.
- **Instant revocation**, when an app needs it for a specific action,
  stays the documented exception (`/session/check`-style call), not
  the norm.

Configuration keys follow the harness module prefix
(`ModuleConfig::new("auth-core", ..)`), which the issue's service-level
names (`AUTH_SIGNING_KEYS`, `AUTH_SIGNING_KEY_ACTIVE`) do not carry:

- `AUTH_CORE_SIGNING_KEYS` — JSON array of private EC JWKs (`kty: EC`,
  `crv: P-256`, `kid`, `d`), at most 16, kids unique.
- `AUTH_CORE_SIGNING_KEY_ACTIVE` — the signing `kid`; must be one of
  the configured kids.
- `AUTH_CORE_ISSUER` — absolute http(s) issuer URL the discovery
  documents and the `iss` claim are built from.

Unset keys are a valid configuration (the module boots; every
token-facing surface answers the stable `auth/tokens-unconfigured`
problem, 503). Malformed keys fail `validate_config` at doctor time
and degrade the same way at runtime — the service never fails to boot
over a key typo, and never names key material in an error.

## What investigation changed

**1. `jsonwebtoken` was checked and not adopted.** The issue
recommended `jsonwebtoken` with its `rust_crypto` backend. Checked
against wasm32 before adopting, as the brief requires: `jsonwebtoken`
11.0.0 `rust_crypto` does **not** build for `wasm32-unknown-unknown` —
it depends on `rand` 0.8 → `getrandom` 0.2, which raises a hard
`compile_error!` on wasm32 unless its separate `js` feature is forced
on from outside (reproduced with a scratch crate on this machine,
2026-09-06). It also pins `p256` 0.13 (duplicating the 0.14 line ADR
0100 validated) and pulls `rsa` — carrying RUSTSEC-2023-0071 into the
main tree — for algorithms this service never issues. Signing is
therefore hand-framed JWT on `p256` 0.14 (`ecdsa`, deterministic
RFC 6979): the framing is two base64url halves and a fixed-width
signature; all elliptic-curve math stays in the library. The JWKS is
built from the public point **re-derived from `d`**, never from
configured `x`/`y`, and `SigningKeys`'s `Debug` prints key ids only.

**2. The sessions table grows `amr`.** The claim list requires `amr`,
and the only place login-method knowledge enters the system is session
issuance. Migration `0003` adds `sessions.amr` (JSON array, NULL until
a login method exists) and `Login` gains an `amr` field the
login-method issues will populate; the same migration rebuilds
`single_use_tokens` (SQLite cannot `ALTER` a `CHECK` constraint) to
admit the `refresh_token` kind.

The issue's other acceptance items — a live rotation rehearsal on
staging and a `wrangler dev` browser run — need credentials this
machine does not have; they are recorded as pending in `PROGRESS.md`
and the PR body.
