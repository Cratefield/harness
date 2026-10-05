<p align="center">
  <img src="https://img.shields.io/badge/STATUS-BETA-FF5A36?style=flat-square&labelColor=0A0A0B" alt="Status: beta">
  <img src="https://img.shields.io/badge/LANGUAGE-RUST-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Language: Rust">
  <img src="https://img.shields.io/badge/RUNS%20ON-THE%20HARNESS-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Runs on the harness">
  <img src="https://img.shields.io/badge/LOGIN-PASSKEYS%20%C2%B7%20GOOGLE%20%C2%B7%20APPLE%20%C2%B7%20META%20%C2%B7%20PASSWORD%20%C2%B7%20MAGIC%20LINK-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Six login methods">
  <img src="https://img.shields.io/badge/TOKENS-ES256%20JWT%20%2B%20JWKS-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Tokens: ES256 JWT with JWKS">
  <img src="https://img.shields.io/badge/LICENSE-MIT-FF5A36?style=flat-square&labelColor=0A0A0B" alt="License: MIT">
</p>

<p align="center">
  <b>auth.&lt;your-app&gt;</b> · ONE BRANDED INSTANCE PER APP
</p>

---

# The login

Every app built on the harness needs people to sign in, and none of them
should own a password table. This service is where those logins happen, and
it runs **once per app**: on the app's own domain (`auth.<app-domain>`), with
the app's name, logo and colours on every page and mail, its own passkey
relying party, its own cookies, sender, database and secrets. Nothing on an
instance names any other app, or the harness.

> **Six ways in, one session.**
> Passkeys, Google, Apple, Meta, email and password, magic links. Whichever a
> person picks, the result is the same session, and one person can use all
> six on one account.

An instance runs one of two ways:

- **Self-hosted.** The app's team deploys and operates the instance itself
  (the EarthOS pattern: `auth.earthos.world`).
- **Managed by Cratefield.** Cratefield operates the same instance on the
  app's domain (for example `auth.alphahunt.ing`). Cratefield's own app uses
  `auth.cratefield.com`. The instances Cratefield operates are the
  directories under [`instances/`](../../instances).

Either way it is the same, unmodified Worker
([`crates/auth-worker`](../../crates/auth-worker)): one Worker, one D1
database, harness modules that see only ports. Everything that makes an
instance somebody's is configuration, and a missing piece of it is refused at
boot rather than filled in with another app's value. The crates are
`cratefield-auth-*`; only `cratefield-auth-client` is published (harness ADR
0011, amended 2026-10-05).

| Read | For |
|---|---|
| [MANAGED-INSTANCES.md](MANAGED-INSTANCES.md) | Standing up a new instance: D1, domain, secrets, Owlpost, Turnstile, OIDC callbacks, client registration |
| [DEPLOYING.md](DEPLOYING.md) | The deploy workflow, the configuration surface, rotating signing keys and client secrets |
| [`crates/auth-worker/README.md`](../../crates/auth-worker/README.md) | Every configuration key |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How it fits the harness, and why |
| [WEB-APPS.md](WEB-APPS.md) | `@cratefield/auth` for TypeScript web apps |
| [MIGRATING.md](MIGRATING.md) | Importing an existing userbase |
| [META-APP-REVIEW.md](META-APP-REVIEW.md) | Getting an instance's Meta app through review |

## How an app uses it

1. Stand up the app's instance ([MANAGED-INSTANCES.md](MANAGED-INSTANCES.md)).
2. Register the app as a client of it: an id, a secret, and an exact list of
   redirect URIs. No wildcards.
3. Send people to `/authorize` with PKCE. They log in on the instance
   (`auth.<app-domain>`), by any method the instance enables.
4. Exchange the code at `/token` for a short-lived ES256 access token and a
   single-use refresh token.
5. Verify tokens locally with `cratefield-auth-client` against the
   instance's issuer (`https://auth.<app-domain>`), which fetches and caches
   the published JWKS and checks the audience so nobody has to remember to.
   TypeScript web apps do the same with `@cratefield/auth`; see
   [WEB-APPS.md](WEB-APPS.md).

## Branding

Each instance sets its own (`AUTH_BRAND_*`, full list in the Worker's
README): the display name used in page titles and every mail subject, an
optional logo, accent colour, support address, footer line, and privacy and
terms links. The passkey RP name defaults to the display name. The session
cookie is the neutral `__Host-session`, host-locked to the instance. Login
mail goes through the harness `Mailer` port, with
[Owlpost](../../crates/adapter-owlpost) as the recommended adapter and Resend
as an option.

## Modules

| Module | What it owns |
|---|---|
| `auth-core` | schema, clients, sessions, tokens, the authorization flow, account linking |
| `auth-passkeys` | WebAuthn registration and login |
| `auth-oidc` | Google and Apple: discovery, PKCE, ID tokens, minted Apple client secret, form_post callback |
| `auth-meta` | Facebook Login: OAuth 2.0 plus a Graph profile call, with no OpenID Connect anywhere, and Meta's data deletion callback ([META-APP-REVIEW.md](META-APP-REVIEW.md)) |
| `auth-password` | Email and password: argon2id, a per-account lockout, a breach check, and answers that reveal nothing about who has an account. **Needs the paid Workers plan** (ADR 0200) |
| `auth-magic-link` | Sign in by email: a single-use bearer credential, the way an address gets verified, and the way back in for a locked or passwordless account |

## Bringing an existing userbase

Running on another auth service today? [MIGRATING.md](MIGRATING.md) walks a
Supabase export through `fz auth import`, keeping each user's password and
verified email.

## The login chooser

`/v1/auth-core/authorize` renders a sign-in page whenever there is no session.
Which buttons it offers is configuration, not discovery:

```
AUTH_CORE_LOGIN_METHODS=passkey,google,apple,meta
```

Order is display order. An unknown slug fails `validate_config`, which today
means `cargo test` catches it: nothing on the production boot path calls that
check, so at runtime an unknown slug is silently dropped and simply renders no
button. Setting a provider's credentials does **not** by
itself put it on the chooser: which methods a deployment offers is a decision.

Redirect-shaped methods are plain links and work with script switched off. A
passkey cannot be: a WebAuthn credential is bound to a relying-party id, and a
browser only runs a ceremony on a page whose origin matches, so a passkey
registered here works on this service's own pages and nowhere else. That is why
the chooser ships one small inline script, and why it ships it only when a
passkey is enabled. See [ADR 0203](../adr/0203-the-login-chooser-and-browser-side-methods.md).

## Refresh tokens and the reuse grace

Refresh tokens are single-use. Presenting an already-consumed one is treated as
a compromise: the session is revoked before the request is refused.

That rule is right, but it has a false positive. A browser page can fire
several requests at once, and on Workers each lands in its own isolate holding
the same refresh cookie. If two of them refresh together, the loser presents a
token the winner has just consumed — and a session nobody attacked is revoked.
A short grace closes that hole:

```
AUTH_CORE_REFRESH_REUSE_GRACE_SECONDS=20   # default 0: off, today's behaviour
AUTH_CORE_REFRESH_REUSE_GRACE_MAX_USES=3   # graced reuses one token gets (1..=10)
```

Inside the window (measured from the original rotation, never extended by a
graced reuse) a second presentation by the **same client id** succeeds: the
consumed token gains a **sibling** successor instead of revoking, so each
racing request holds a usable token. Siblings stay live until one is used;
that first use retires the rest, and the family converges on the chain the
browser actually kept. A graced reuse past `MAX_USES` in the window, or one
arriving after another sibling's chain has moved on, revokes as before. The
window must be `0..=300` seconds and `MAX_USES` must be `1..=10`; a value
outside either range fails `validate_config`.

For a browser client, 10–30 seconds is the recommendation: long enough to cover
a page's parallel requests, short enough that a token stolen and replayed later
still trips the alarm. The trade-off is explicit — a stolen token used within
seconds of the legitimate refresh, **by the same client id**, is not detected.
Set the window to `0` where that risk outweighs the false positive.

## Status

Design adopted 2026-09-06; per-instance model adopted 2026-10-05 (issue
#777). The Worker composes all merged modules and deploys with wrangler, one
instance per app. `instances/alphahunt` and `instances/yoginini` are live on
staging only (`auth-staging.alphahunt.ing`, `auth-staging.yoginini.us`);
their production deploys and `instances/cratefield` wait on the steps in
[MANAGED-INSTANCES.md](MANAGED-INSTANCES.md) (secrets, Owlpost, Turnstile,
first `auth-v*` tag). Enterprise SAML SSO is deliberately deferred.

## License

MIT. Part of the [Cratefield harness](https://github.com/Cratefield/harness).
