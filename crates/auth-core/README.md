# auth-core

The schema and shared flows of the auth service. Mounted at
`/v1/auth-core`: `users`, `identities`, `credentials`, `sessions`,
`single_use_tokens`, `clients` and their redirect URIs, plus the
authorization flow, client registration, session and token issuing, the
user-import admin API, enterprise SSO connections, and changing the address
an account is reached at.

Every venture composes this module, so the tables, the personal-data
declarations and the migrations here are the ones `fz data export`, subject
access and erasure walk.

## Routes

| Route | What it does |
|---|---|
| `GET /authorize` | The sign-in chooser: client, redirect URI, login methods |
| `GET /logout`, `POST /logout`, `POST /logout/confirm` | End the current session |
| `POST /logout-all` | End every session the account holds |
| `GET /sessions`, `DELETE /sessions/{id}` | List and end sessions |
| `POST /token` | Access tokens, an ID token on the code grant, refresh tokens, reuse detection |
| `GET /jwks.json`, `GET /openid-configuration` | The JWKS and discovery document |
| `POST /admin/clients`, `GET /admin/clients`, `PATCH /admin/clients/{id}` | Register, list, rename or switch a client, and set its `roles_claim` (#912) |
| `POST /admin/clients/{id}/rotate-secret` | Rotate a confidential client's secret, with an overlap window |
| `POST /admin/users/import`, `GET /admin/users/by-external-id` | `fz auth import`'s server half |
| `POST /admin/users/{sub}/disable`, `POST /admin/users/{sub}/enable` | Switch an account off and back on (#854) |
| `GET /admin/users/{sub}/passkeys` | `{"passkeys": <count>}`: how many usable passkeys the account holds |
| `POST /admin/users/{sub}/role` | Set an account's role: `owner`, `admin` or `member`, audited (#912) |
| `POST /sso/connections`, `GET /sso/connections` | An organization's own identity provider (#627) |
| `POST /email/change` | `{ new_email, current_password? }`, signed in. Always `202`, always the same body |
| `GET /email/confirm?token=…` | The page an email-change link opens. Never reads or spends the token |
| `POST /email/confirm` | `{ token }` as JSON, or form-encoded from the page's button. Sets `primary_email`, verified. `200`, or one refusal |

Both `/email/*` routes refuse a cross-site request first
(`403 auth/cross-site-request`, #439): moving the address is what every
later reset mail points at.

## Step-up re-authentication and roles (#912)

`/authorize` honours the two OpenID Connect Core (section 3.1.2.1) requests
that ask for a fresh sign-in:

- `prompt=login` shows the chooser even with a live session, and `max_age=0`
  does the same. Each makes a **step-up transaction**: a single-use record
  bound to the account and the client, valid for ten minutes, whose value
  the chooser carries through the login as `step_up`. A session satisfies
  the demand only if a passkey or an email link created it after the
  transaction began, no more than 120 seconds before the request returns,
  and only once: the check that accepts it spends the transaction. A
  session from before the demand, a later unrelated login, a federated or
  SSO sign-in, and a password sign-in do not satisfy it. Federated and SSO
  sign-ins are not forwarded to the upstream IdP for a step-up; the chooser
  is shown instead, so the person can use a passkey or an email link.
- `max_age=N` (N > 0) is an age check against the session's creation. It
  records nothing, so a failed check sends the person to the chooser and
  leaves no demand behind.
- `prompt=none` never shows a page: it answers `login_required` when no
  session is live or a step-up is due. It records nothing.

A malformed `prompt` or `max_age` (an unknown prompt value, `none` alongside
another, a negative or non-numeric age) and a `nonce` over 512 bytes are
refused as `invalid_request` to the registered URI, as the other parameter
errors are. Without a session the chooser's login is itself the ceremony,
so `prompt` and `max_age` are not carried back with it.

**Tokens.** The access token (`typ: at+jwt`) carries `auth_time` (epoch
seconds) and `amr` beside `email` and `email_verified`. A request with
`scope` including `openid` also gets an `id_token` (`typ: JWT`, ES256, the
same key) with `iss`, `sub`, `aud`, `azp`, `sid`, `auth_time`, `amr`,
`nonce` when the request sent one, and `roles` when the client asks for
them. A request without `openid` gets no ID token. The refresh grant never
answers an ID token. `amr` values are the ones the login methods record:
`passkey` with `user` (and `mfa` when the authenticator verified the user),
`email`, `pwd`, `federated`, `sso`. Only `passkey` and `email` satisfy a
step-up.

**Roles.** `users.role` is `owner`, `admin` or `member` (every account starts
as `member`), set by `POST /admin/users/{sub}/role` under the admin bearer
token and audited in `user_role_audit`. A client gets a `roles` claim,
`["owner"]` or the one role it has, only when it is registered with
`roles_claim: true` (off by default). A role that cannot be read fails the
token request rather than being guessed. Nothing a client sends can set a
role: the role is read from the account, never from the request. A role
change reaches new tokens at once; a token already minted keeps its role
until it expires, at most `ACCESS_TOKEN_SECS` later.

Discovery advertises `prompt_values_supported` (`none`, `login`, `consent`,
`select_account`), `scopes_supported` (`openid`), and the claims above in
`claims_supported`.

Relying parties must check freshness themselves: `cratefield-auth-client`
exposes `authenticated_within`.

## The email change (#648)

`POST /email/change` answers `202` and one body whether the address is
free, another account's, or this account's own. A taken address gets no
token and no mail, so only the caller can tell and they learn nothing. The
old address is always mailed `auth-core/email-change-notice`, naming the
address the change would move to and a "this was not you" line, because its
owner is the only one who can act on a change somebody else started.

A free address gets `auth-core/email-change-confirm`: a single-use
`email_change` token, an hour long, carrying the address in the token row's
`payload` (migration `0011`; `payload` is already redacted in
`personal_data`, so a pending address never reaches an export). Issuing
retires the account's earlier unconsumed tokens.

**Recent sign-in is required.** A session under `RECENT_SECS` (ten
minutes) stands for itself; an older one must re-enter the password, and an
account with no password credential has nothing to re-enter. A wrong
password and an expired window are one answer
(`403 auth/reauthentication-required`), because a caller who can tell them
apart learns something. Legacy bcrypt hashes count, for the reason they
count at login (`AUTH_LEGACY_HASHES`, #650).

`POST /email/confirm` needs no session and spends the token atomically.
It reads JSON or form-encoded bytes, whichever the `Content-Type` names, so
the GET page's button works; a browser gets a page, an API client a problem
document. Missing, expired, used, never issued, of another kind, and an
address another account took meanwhile — as `users.primary_email` or as a
`password` identity subject — are all `400 auth/email-token-refused`. On
success it moves that identity first, then sets `primary_email` and marks it
verified, revokes the account's other sessions (keeping the one that carried
the confirm), and emits `auth-core.email_changed` with `{"user_id": …}`, ids
only.

## The account switch (#854)

`POST /admin/users/{sub}/disable` (admin bearer token) is the kill switch
for one account. It sets `users.status = 'disabled'` — which alone refuses
every new sign-in, because magic-link, passkey and every other login method
funnel through the session issuer, which reads the flag — and then revokes
every live session and retires every live refresh token (unspent and
unexpired; an expired one is dead already). It answers
`200` with `{"sub", "status", "sessions_revoked", "refresh_tokens_revoked"}`;
an unknown `sub` is a `404`. The call is idempotent: repeating it answers
the same shape with zero counts, and every call writes a `user_admin_audit`
row (migration `0012`), enable included.

`POST /admin/users/{sub}/enable` undoes the flag. It restores nothing:
sessions stay revoked and retired refresh tokens stay spent, so the person
signs in again as normal.

`GET /admin/users/{sub}/passkeys` (same admin bearer token) answers
`{"passkeys": <count>}`: how many passkeys the account holds that can still
sign in (one flagged by a counter regression is not counted). It is for an
app that keeps its own sign-in policy, such as asking for the passkey once
the member has one, and returns a number only: no credential ids and no
public keys. An unknown `sub` is a `404`. Being a read, it writes no audit
row.

**What disable does not stop instantly is the current access token.** It
is a JWT valid for `ACCESS_TOKEN_SECS` (ten minutes), self-contained and
verified by resource servers against the JWKS without a call back — so it
keeps working until it expires, at most ten minutes after the disable.
Refresh is refused the moment the flag moves, and the session dies with
it. If that window is too wide for an incident, shorten
`ACCESS_TOKEN_SECS`; there is no introspection endpoint that could see the
flag earlier.

## Mail, events and limits

Both mails resolve `{id}@{locale}` before `{id}` through the venture's
registry, falling back to `default_templates()`; the locale comes from
`users.locale` and `Accept-Language`. `Mailer` is **optional**: without it,
or without `AUTH_CORE_PUBLIC_BASE` and `AUTH_CORE_MAIL_FROM`, the answer is
still `202` and nothing is sent. Both go through
`scope.defer.wait_until`, so their timing reveals nothing and a failure is
swallowed. `RateLimiter` is optional too, consulted under `auth-core:{key}`
keyed on the caller and the address; it fails open, since the backstops
behind it are the credential's own lockout and the token's guarded consume.

## Migrations and tests

`0001`–`0012`, applied per dialect. `0011` widens the `single_use_tokens`
kind CHECK with `email_change` by rebuilding the table — SQLite cannot alter
a CHECK, and Postgres takes the same rebuild so both end on one shape (the
reason is in the Postgres file's header).

`cargo test -p cratefield-auth-core`. `tests/email.rs` runs on SQLite in
memory always and on Postgres when `FZ_TEST_POSTGRES_URL` names a server.