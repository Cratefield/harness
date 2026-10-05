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
| `POST /token` | Access tokens, refresh tokens, reuse detection |
| `GET /jwks.json`, `GET /openid-configuration` | The JWKS and discovery document |
| `POST /admin/clients`, `GET /admin/clients`, `PATCH /admin/clients/{id}` | Register, list, rename or switch a client |
| `POST /admin/clients/{id}/rotate-secret` | Rotate a confidential client's secret, with an overlap window |
| `POST /admin/users/import`, `GET /admin/users/by-external-id` | `fz auth import`'s server half |
| `POST /sso/connections`, `GET /sso/connections` | An organization's own identity provider (#627) |
| `POST /email/change` | `{ new_email, current_password? }`, signed in. Always `202`, always the same body |
| `GET /email/confirm?token=…` | The page an email-change link opens. Never reads or spends the token |
| `POST /email/confirm` | `{ token }` as JSON, or form-encoded from the page's button. Sets `primary_email`, verified. `200`, or one refusal |

Both `/email/*` routes refuse a cross-site request first
(`403 auth/cross-site-request`, #439): moving the address is what every
later reset mail points at.

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

`0001`–`0011`, applied per dialect. `0011` widens the `single_use_tokens`
kind CHECK with `email_change` by rebuilding the table — SQLite cannot alter
a CHECK, and Postgres takes the same rebuild so both end on one shape (the
reason is in the Postgres file's header).

`cargo test -p cratefield-auth-core`. `tests/email.rs` runs on SQLite in
memory always and on Postgres when `FZ_TEST_POSTGRES_URL` names a server.