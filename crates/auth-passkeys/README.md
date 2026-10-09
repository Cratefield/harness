# auth-passkeys

Passkey registration and login for the auth service
(issues #13, #14). Mounted at `/v1/auth-passkeys`.

## Routes

| Route | Session | What it does |
|---|---|---|
| `POST /register/options` | required | A challenge plus the RP, the user handle, the algorithms we accept and the credentials to exclude |
| `POST /register/verify` | required | Checks the ceremony and stores the credential |
| `POST /login/options` | no | A challenge; with an email, the account's credential ids, otherwise an empty list for discoverable credentials |
| `POST /login/verify` | no | Checks the assertion, advances the counter, issues a session |
| `GET /credentials` | required | The account's passkeys |
| `DELETE /credentials/{id}` | required | Removes one, unless it is the account's only way in |
| `GET /passkeys/prf` | required | The account's passkeys with what each ceremony has shown about PRF support, and the salt each one evaluates with |
| `GET /add?return_to=<url>` | optional | The hosted "Add a passkey" page. Signed out, it offers the sign-in links and comes back here; signed in, it runs the registration ceremony (asking for PRF) and returns to `return_to` with `#cf_passkey=<credential id>&cf_aaguid=<uuid>&cf_prf=1\|0` — or `#cf_passkey_error=cancelled` from its "Not now" link. `return_to` must be an `https` URL on the origin of an active client's registered redirect URI; anything else is dropped, never redirected to |

`POST /login/verify` refuses a cross-site request — `403`,
`auth/cross-site-request`, ahead of the rate limiter. A verified
assertion issues a session, and `SameSite=Lax` stops a cross-site POST
from *carrying* our session cookie, not from *setting* one (issue #439).

## Configuration

| Key | Required | Default |
|---|---|---|
| `AUTH_PASSKEYS_RP_ID` | yes | the registrable domain passkeys are bound to |
| `AUTH_PASSKEYS_ORIGINS` | no | `https://<rp id>`; comma-separated |
| `AUTH_PASSKEYS_RP_NAME` | no | `AUTH_BRAND_NAME`, else the RP id |
| `AUTH_PASSKEYS_CHALLENGE_TTL_SECS` | no | `300`, bounded to 60..900 |
| `AUTH_PASSKEYS_USER_VERIFICATION` | no | `preferred` |

Every origin must be the RP id or a subdomain of it. That is WebAuthn's own
rule, checked at configuration time because an origin outside it could never
produce a valid ceremony: allowing one would only ever be a way to get it
wrong.

## What this module owns in the database

Two tables. The challenge budget behind `login/options`
(`auth_passkeys_challenge_budget`, migration `0001` here) — the issuance
cap that keeps the public endpoint from being swept for accounts whether or
not a rate limiter is wired up — and one PRF row per passkey
(`auth_passkeys_prf`, migration `0002` here): its salt and what the
ceremonies so far have shown about its PRF support. Everything else belongs
to `auth-core`, which owns `users`, `credentials`, `sessions` and
`single_use_tokens`, and publishes the typed store API this module writes
through, so that schema has one definition and one migration history. The
`passkey_suspect_at` column this module needs was added there, in migration
`0004`.

## The PRF extension

The `prf` extension (issue #756) lets an app unseal, at sign-in, what it
sealed at registration — this module asks for it, hands out the salts, and
records what each ceremony shows about whether a passkey can answer. It
never accepts the extension's *output*: the output is a hash of this
service's salt with the authenticator's own secret, useful only on the
device, so a verify body carrying `clientExtensionResults.prf.results` is
refused with `400`, `auth/passkey-prf-output-rejected` — before the
challenge is spent or anything is stored. Clients send a redacted
`prf: { enabled }` instead. Details and a client walkthrough:
[`docs/auth/PASSKEYS-PRF.md`](../../docs/auth/PASSKEYS-PRF.md).

- Registration options ask for the extension with an empty input,
  `publicKey.extensions.prf = {}`; the salts are chosen per assertion, at
  login. The verify response names the outcome, `prf` and `prfSalt`, so the
  app that sealed something at registration holds its salt at once (the
  pair is omitted when the row could not be written; the registration
  stands, and the salt turns up at the next login).
- Login options hand one salt per allowed credential: `prf.eval` when
  exactly one credential may answer, `prf.evalByCredential` — keyed by the
  base64url credential id — when several, and no extension at all for a
  discoverable login, where the credential that will answer is unknown.
- Each passkey's capability is `supported` (the authenticator's signed
  `hmac-secret: true`, or a client `enabled: true`), `unsupported` (a
  client `enabled: false` at login), or `unknown` (no signal yet, the
  honest default). Registration never records `unsupported` — some
  authenticators report only on the next sign-in — and `supported` is
  sticky against a later `false`. Rows are created lazily, so a credential
  registered before the extension existed gets its salt at its next login.

## Verification

`webauthn-rs` cannot build for `wasm32-unknown-unknown` — OpenSSL is a hard
dependency of `webauthn-rs-core` — so relying-party verification is
implemented directly on the wire types (ADR 0200). ES256, RS256 and EdDSA
are all accepted; anything else is refused at registration rather than
stored and failed at every later login. Registration requests
`attestation: none` and accepts other formats without verifying them, which
is the ordinary consumer relying-party position; the statement itself is
logged and not retained, since nothing here would ever read it back.

## Two rules that run through the module

**A challenge is spent exactly once**, by a conditional update whose
affected-row count decides the winner. Not a read followed by a write, and
not KV, whose eventual consistency would let a replay through.

**Every failed login answers identically.** Unknown credential, spent
challenge, wrong origin and a bad signature return the same problem, because
an attacker who can tell them apart learns which half of the ceremony to
work on. The tests assert the responses are identical apart from the request
id.

**The signature is checked before the counter.** That order is the spec's
(7.2 steps 21 then 22) and it matters here more than most places: a counter
regression is the one failure this module acts on permanently, and every
part of an assertion except the signature is attacker-chosen. Checking the
counter first would let one unauthenticated request with a garbage signature
mark a stranger's passkey as a clone.

## What this module does not resist

`POST /login/options` with an email returns that account's credential ids,
which is inherent to the non-discoverable flow: the browser needs them to
choose an authenticator. An account with no passkeys and an address with no
account are indistinguishable, but an account *with* a passkey is not. The
leak is bounded, not closed: a database-enforced challenge budget caps
options at thirty calls per client address and five per named address a
minute — with or without a rate limiter, and before the account lookup, so
a refusal says nothing about the account named. Both public endpoints are
also rate limited by client address where the composition wires a limiter.

Registration requires a live session but not a *recent* one, so a hijacked
session can add a passkey. Requiring a fresh authentication before adding a
credential is the usual hardening and is filed separately.

## Known gap

The tests mint ceremonies with a software authenticator, which covers all
three algorithms and every negative case, but no test here has met real
hardware. Issue #13's last acceptance box is a manual run in a browser
against `wrangler dev` with a platform authenticator, and it stays open.

---

MIT. Part of the [Cratefield harness](https://github.com/Cratefield/harness).
