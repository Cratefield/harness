# ADR 0006: HMAC-signed tokens for confirm and unsubscribe links

Status: accepted, 2026-09-05

## Context
Double opt-in and unsubscribe need links that work without server-side
sessions, on a stateless Worker, and must keep working across secret rotation.

## Decision
The `Signer` port produces `base64url(json).base64url(hmac)` where payload
is `{ purpose, subject, exp?, kid }`. HMAC-SHA256 via the `hmac` and `sha2`
crates; comparison via `subtle::ConstantTimeEq`. Confirm tokens expire (7 days
default); unsubscribe tokens do not. `Signer` verifies against
`HARNESS_SECRET` and `HARNESS_SECRET_PREVIOUS`, selected by `kid`. Single-use
is enforced by row state, not by storing tokens. The MAC is computed over the
encoded payload string, so a token has exactly one valid encoding.

## Consequences
- No token table, no KV dependency for the opt-in flow.
- Rotation: set `HARNESS_SECRET_PREVIOUS` to the old value, roll the new one, drop the previous after the confirm TTL.
