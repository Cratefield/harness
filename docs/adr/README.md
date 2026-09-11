# Architecture decision records

One file per decision, numbered, never edited after acceptance (supersede instead).

Numbers are allocated in blocks so that two codebases can never claim the
same one — which is what happened to 0102 while auth lived in its own
repository (ADR 0013):

| Block | Subject |
|---|---|
| 0000–0099 | the harness itself |
| 0100–0199 | cross-cutting harness concerns |
| 0200–0299 | the auth service |
| 0300–0399 | the control plane |

## The harness

ADR 0000 records why the TypeScript v1 was discarded.
ADR 0011 supersedes the naming half of ADR 0005: public crates are
`cratefield-*`, renamed before the first crates.io release.
ADR 0012 extends 0011: the bare `cratefield` name is published as a facade
crate, not held as a placeholder.
ADR 0013 supersedes the distribution half of 0005 and 0011: every crate
lives in this repository, and `publish = false` — not a separate
repository — is what makes a crate private.
ADR 0014 amends ADR 0006 without retracting it: the signer's two secret
slots become a bounded key ring with revocation as a state, expiry becomes
a mint-time policy, tokens gain a venture/environment binding, and the
never-dies unsubscribe link gains an opaque, per-subscription revocable
form.
ADR 0015 extends ADR 0002 for the `Push` port: a recipient is an enum with
one variant per transport, `platform()` is a transport fact rather than a
device fact, and the routing combinator sits above the adapters in core.
ADR 0016 records the two answers the notifications module (#182) needed and
the harness did not have: a dead letter is a module-owned table rather than
a new terminal state on core's `Outbox`, and a module learns the calling
account from `factory0-auth-client`'s `Authenticated` extractor — the first
module to depend on it.

ADR 0017 decides how events cross a sidecar boundary (#62): inbound
only, forwarded to `POST /__events` where ports are resolved rather than
through a `Scope` change that would bump `HARNESS_API`, carrying exactly
the guarantees the in-process bus already gave. Bidirectional was
rejected for the cycle it admits and the delivery question it forces.

[0102](0102-crypto-crate.md) chose the crypto crate: RustCrypto's
`chacha20poly1305`.

## The auth service

Numbered from 0200. These were 0100–0104 in `Factory-Zero/auth`; they were
renumbered when that repository was folded in (ADR 0013), because 0102 was
already taken here. Each spike produced one, and so does any decision a
login method forces.

| ADR | Decision |
|---|---|
| [0200](0200-wasm-crypto-and-webauthn.md) | Pure-Rust WebAuthn verification, because `webauthn-rs` cannot reach wasm32 |
| [0201](0201-token-issuing.md) | Signed ES256 JWTs with a published JWKS, over opaque tokens |
| [0202](0202-sign-in-with-apple.md) | Apple's minted client secret, `form_post` cookie policy and one-time name |
| [0203](0203-the-login-chooser-and-browser-side-methods.md) | The login chooser lists configured methods, and this service ships the passkey page because nothing else can |
| [0204](0204-facebook-login-without-openid-connect.md) | Meta is OAuth 2.0 with a Graph profile call, and its email is never stored as verified |

## The control plane

Its architecture and pricing are written up in
[`docs/control-plane/`](../control-plane/); it has no ADRs of its own yet.
They take the 0300 block when it does.
