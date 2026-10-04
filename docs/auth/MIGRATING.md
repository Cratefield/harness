# Migrating an existing userbase into auth-core

A venture that already has users elsewhere should not have to ask them all
to reset their password. This runbook moves them in: an export, a dry run, a
report you keep, and the one config key that keeps a legacy password
verifier working until it is upgraded. The example is Supabase; the format,
limits and security notes are the same for any source.

Users move into **the app's own auth instance** (one per app, issue #777;
see [MANAGED-INSTANCES.md](MANAGED-INSTANCES.md)), never into another app's.
`--target` below is that instance's origin, `https://auth.<app-domain>`.

`fz auth import` (issue #650) reads a JSONL file of user objects and sends
them to a running `auth-core` at `POST /v1/auth-core/admin/users/import`,
behind `Authorization: Bearer <ADMIN_TOKEN>`. Only the email, its verified
flag and the password verifier (if any) move — the rest stays behind (see
[What is not carried](#what-is-not-carried)).

## From Supabase

Supabase keeps accounts in `auth.users`. `encrypted_password` is a bcrypt
`$2a$10$` hash; a user who signed up only through an OAuth provider has it
empty or null, and gets no password on this side either.

**1. Export.** With `psql` pointed at the project's Postgres connection
string:

```sh
psql "$SUPABASE_DB_URL" -At -c "
SELECT json_build_object(
  'external_provider', 'supabase',
  'external_id',       id::text,
  'email',             email,
  'email_verified',    email_confirmed_at IS NOT NULL,
  'password_hash',     nullif(encrypted_password, ''),
  'created_at',        created_at
)
FROM auth.users
WHERE email IS NOT NULL
ORDER BY created_at;
" > users.jsonl
```

`-A` (unaligned) and `-t` (tuples only) make it one JSON object per line,
with no header. Keep `users.jsonl` where only the operator can read it: it
holds every address and every hash.

**2. Let login verify the bcrypt hashes.** Set `AUTH_LEGACY_HASHES=bcrypt`
on the auth service — the deployment's config (a Worker var or secret, or a
local `.env`). The key is unprefixed and comma-separated; unset, empty or
blank means no legacy formats. Set it **before** the import and leave it on
until the hashes are upgraded: with it unset the import refuses every bcrypt
hash and reports it `invalid`.

**3. Dry run.**

```sh
fz auth import --target https://auth.example.com --admin-token-env ADMIN_TOKEN users.jsonl
```

A run is a dry run unless `--apply` is given: the server validates every
user and reports a verdict, writing nothing. The report lands at
`users.jsonl.report.jsonl` (`--report PATH` to move it). The `fz` must be
built with the feature (`cargo install cratefield-cli --features
auth-import`); a build without it refuses.

**4. Review the report.** One line per user — `external_provider`,
`external_id`, `status`, `sub`, `reason`, and no email or hash. Two statuses
need a decision:

- `conflict` — the email matches an account already in `auth-core`. Re-run
  with `--merge-by-email` to fold the import into that account (becoming
  `merged`), or resolve it by hand.
- `invalid` — the user was refused; `reason` says why.

**5. Apply.** `--apply` is the only thing that writes; add
`--merge-by-email` if step 4 decided to.

```sh
fz auth import --target https://auth.example.com --admin-token-env ADMIN_TOKEN \
  --apply users.jsonl
```

**6. Keep the report, hand over the ids.** The report's `sub` is the new
account id, so the file is the old → new map for a venture's foreign keys;
the same answer is available one user at a time from
`GET /v1/auth-core/admin/users/by-external-id?provider=supabase&external_id=<uuid>`.

Token claims are unchanged in shape. From here people sign in as before:
their existing password, verified against the imported bcrypt hash and
rehashed to argon2id on the first successful login.

## What is not carried

- **OAuth identities.** A link the source already holds is carried only when
  listed as `identities`; anything else re-forms on first sign-in. Linking
  (`crates/auth-core/src/linking.rs`) auto-links a provider to an existing
  account when it reports the same email **and both sides are verified**,
  refuses rather than guess otherwise, and never matches an Apple relay
  address, so a returning provider login lands on the imported account.
- **MFA factors** are not imported; anyone with a second factor re-enrols.
- **Sessions and refresh tokens** are not carried, by design — everyone
  signs in again.
- **App data** is out of scope: only the account moves, and a venture's own
  tables stay its own (a separate runbook, `docs/DATA-MOVE.md`).
- **User metadata** — display names, `app_metadata`, `locale` and other
  profile fields. Only the email, its verified flag, the password verifier
  and the source `created_at` travel.

## The JSONL format

One JSON object per line; blank lines are skipped. Required fields must be
present and non-empty; unknown fields are ignored.

| Field | | Meaning |
|---|---|---|
| `external_provider` | required | The source system, e.g. `supabase`. |
| `external_id` | required | The user's id in that system. |
| `email` | required | The address; compared on its normalised form. |
| `email_verified` | required | Whether the source vouched for the address. |
| `password_hash` | optional | A verifier — bcrypt or argon2id. Omit for a passwordless user. |
| `created_at` | optional | RFC 3339; the account's creation time (defaults to import time). |
| `identities` | optional | OAuth links to pre-attach, e.g. `[{"provider":"google","subject":"<sub>"}]`. `provider` is `google`, `apple` or `meta`, and `subject` is that provider's OIDC `sub`, stored verbatim. A subject already linked to another account makes the user `conflict`/`identity-taken`. |
| `locale` | optional | Accepted and ignored — an imported account starts with no stored locale, and mail resolves one per request (issue #649). |

`(external_provider, external_id)` is the key: importing the same pair twice
is `unchanged`, never a second account. A pair repeated inside one file, or a
missing required field, is refused locally. Each user becomes an identity of
provider `import` with subject `<external_provider>:<external_id>`.

## Statuses

| Status | Meaning |
|---|---|
| `created` | A new account and its imported identity were written. `sub` is its id. |
| `unchanged` | This `(external_provider, external_id)` was imported before; nothing changed. |
| `merged` | Folded into an existing account sharing the email (with `--merge-by-email`); an account that already has a password keeps it. |
| `conflict` | The email matches an existing account and merging was not allowed (`email-exists`), or an `identities` subject is already linked to another account (`identity-taken`). |
| `invalid` | The user was refused — a malformed or over-cost hash, an unsupported format, or a value the server cannot use. |

In a dry run a `created` row carries no `sub`; the apply is where the ids
appear.

## Limits

- **1000 users per request.** The server refuses more; the CLI batches at
  500 by default (`--batch-size N`, max 1000).
- **bcrypt cost ≤ 14**, and only while `AUTH_LEGACY_HASHES` names `bcrypt`.
  A higher cost, or a bcrypt hash with the flag off, is refused at import and
  never verified at login: one login must not be a way to burn the CPU budget
  (ADR 0200's addendum has the numbers).
- **Admin rate limit.** Every `/admin/*` route is limited by client IP at
  the harness layer and fails closed; the import inherits it. A whole-file
  import is many requests, so pace it.

## Security notes

- The report holds **no PII** — `external_provider`, `external_id`, `status`,
  `sub`, `reason`, never an email or a hash. The file you import is the only
  place those appear, and the admin token is never printed.
- `AUTH_LEGACY_HASHES` only affects stored values that are **not** argon2id.
  Argon2id verifies identically whether the flag is on or off, so it cannot
  weaken a hash written now, and every successful bcrypt login is rehashed
  to argon2id.
- **Turning the flag off again.** Once every imported account has signed in
  once its hash is argon2id — but nothing records which accounts have not,
  so no tool can say when that is done. Leave the flag on long enough for
  dormant accounts to return, then remove it; ending it early only means an
  account that has not yet signed in fails its next password login.

## Auth0 and Firebase

- **Auth0** exports bcrypt the same way (cost 10 by default). Map Auth0's
  `user_id` to `external_id`, set `AUTH_LEGACY_HASHES=bcrypt`, and the steps
  above apply unchanged — check the cost is ≤ 14 first.
- **Firebase** does not: its `passwordHash` is a *modified* scrypt with a
  `firebase` version marker that this service does not verify. Those users
  need a password reset; they can still be imported with their email and
  verified flag and no `password_hash`.
