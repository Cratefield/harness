# Privacy: what the harness stores, where, and for how long

This document is the data map required by architecture section 11 and
issue #13. It covers the two M1 modules: `cratefield-module-email-signup`
and `cratefield-module-waitlist`, and the telemetry module
(`cratefield-module-telemetry`, issue #413).

**A deployment's own map is a route, not this file.** Since
`cratefield-module-privacy`, each module declares what it holds next to the
table that holds it (`Module::personal_data()`), and
`GET /v1/privacy/manifest` publishes that for the modules a venture actually
composed — with what erasure does to each table, and which columns an export
will not copy. A page generated from the declarations cannot drift from them;
a page written beside them always eventually does, which is what happened to
the notifications module's own privacy section (issues #244, #248). The two
modules below predated the declaration and now carry one (issue #265), as do
`auth-core`, `cms` and `linkedin`; what follows is the column-level detail
behind what that route publishes, not a second source of truth.

## Principles

- **PII minimalism.** The harness stores an email address, its
  normalized form, timestamps, a free-form `source` label, and (signup
  only) a locale tag. Nothing else.
- **No IP addresses, no user agents in the database.** The client IP is
  used in memory for rate-limit keys (`ip:<address>`) and never written
  to a table. Logs hash IPs; they never store the raw address.
- **Logs never contain addresses.** The tracing redaction layer
  (`cratefield_core::logging`) replaces email-ish fields with a 12-hex
  truncated SHA-256 `subject_hash` and drops secret-named fields
  entirely; a CI test asserts no emitted log line contains an `@`.
- **Admin delete is a hard delete.** There is no soft-delete flag and no
  tombstone; deletion requests remove the row immediately.

## Data map

### `subscribers` (module-email-signup)

| Column | Kind | Purpose |
|---|---|---|
| `id` | ULID, generated | Row identity; the subject of signed links |
| `email` | PII (address) | The address as entered (trimmed) |
| `email_normalized` | PII (address) | Trim + NFC + lowercase; uniqueness key |
| `status` | state | `pending` \| `confirmed` \| `unsubscribed` |
| `source` | label | Free-form signup source (`<launch>`, `waitlist:<product>`) |
| `locale` | label | Mail template locale hint (`en`, …) |
| `unsubscribe_token` | bearer capability | The revocable per-subscription unsubscribe token (issue #137). Whoever holds the value can unsubscribe that subscription, so `GET /v1/privacy/export` **names the column and does not copy it** — `[redacted]` for a value, which says "held, not handed over" rather than "not held" |
| `confirmed_at`, `unsubscribed_at`, `created_at`, `updated_at` | timestamps | State transitions; `updated_at` also drives the one-mail-per-hour throttle and the retention purge |

Retention: `pending` rows whose `updated_at` is older than
`retention_days_pending` (default 30 days; `EMAIL_SIGNUP_RETENTION_DAYS_PENDING`,
purged by the module's scheduled handler). Confirmed rows are kept until
the subscriber unsubscribes or requests deletion. Unsubscribed rows are
kept (status only) so repeated signups are recognized and not re-mailed
within the throttle window.

### `waitlist_entries` (module-waitlist)

| Column | Kind | Purpose |
|---|---|---|
| `id` | ULID, generated | Row identity; the subject of signed links, and of export and erasure |
| `email`, `email_normalized` | PII (address) | As above; unique per `(email_normalized, product)`. Nullable since `0005`, because erasure **anonymises** this row rather than deleting it: `position` is a dense join order that is never recomputed and `referrals` is a credit already granted, so removing the row would change numbers other people can see |
| `product` | label | Which waitlist |
| `status` | state | `pending` \| `confirmed` |
| `position` | counter | Dense per-product join order at confirm time; never recomputed |
| `referral_code` | random id | 8-char Crockford base32 (random part of a ULID) |
| `referred_by`, `referrals` | counters | Referral graph and credit count |
| `answers` | answers JSON | Free-form; validated by the venture's schema fn |
| `created_at`, `confirmed_at` | timestamps | `created_at` doubles as last-join-request time and drives the retention purge |

Retention: `pending` entries untouched for `retention_days_pending`
(default 30 days; `WAITLIST_RETENTION_DAYS_PENDING`) are purged by the
scheduled handler. Confirmed entries are kept while the waitlist runs.

### `waitlist_send_cooldown` (module-waitlist)

One row per `(address, product)` pair and the moment the last mail went out,
which is what enforces one mail per address per window. **The address is
inside the primary key** rather than in a column of its own, so
`… WHERE <column> = ?` cannot reach it and an erasure request does not: the
table is declared `PersonalDataSet::none` with that stated as its published
reason. It is the shape issue #266 describes for `Outbox`, with one
difference worth knowing — a cooldown row is renewed rather than expired, so
unlike a queued job it is not gone within the hour.

Retention: none. The row is written on the first mail and updated on every
later one; only a failed send releases it.

### `telemetry_events` (module-telemetry)

Aggregate usage counters, one row per bucket, never one row per event
([TELEMETRY.md](TELEMETRY.md)). A bucket is one install's accumulated counts
for one event name under one combination of the closed-vocabulary values —
which is why every descriptive column below is a label from a fixed list and
none is free text.

| Column | Kind | Purpose |
|---|---|---|
| `bucket_key` | primary key | One accumulation bucket: the dimension tuple joined with `\|`, day first, then install, client shape, event name, outcome, error class, duration bucket — the day is part of the key, so a bucket is one install's counts for one day. The event name is venture-chosen and could in principle carry a `\|`; the nine components around it cannot, and a declared name that does is refused at build time, so the tuple still splits uniquely |
| `day` | date | The UTC day the bucket was first written — the anchor the retention purge compares |
| `install_id` | pseudonymous id | The 32-hex install id the payload carried. Pseudonymous, not anonymous: the person's own client prints it (`fz telemetry status`), so an erasure request that supplies it reaches exactly these rows. Nothing stores a link from it to a person, and it rotates every 30 days, so an erasure reaches everything written under the id it names and nothing under the ids before it — the trade [TELEMETRY.md](TELEMETRY.md) states in full |
| `client_kind`, `client_version`, `platform`, `arch` | labels | The client shape that reported, each from its closed vocabulary |
| `event` | label | The event name, from the venture's declared vocabulary |
| `outcome`, `error_kind`, `duration_bucket` | labels | The closed-vocabulary outcome, error class and duration bucket |
| `events` | counter | How many runs accumulated into the bucket over its lifetime |
| `first_seen_at`, `last_seen_at` | timestamps | First and most recent touch of the bucket |

Retention: rows whose `day` is older than `TELEMETRY_RETENTION_DAYS` (default
180 days) are deleted by the module's scheduled handler. No column here is an
IP address or a user agent — the client IP touches the route only as an
in-memory rate-limit key, per the principles above, and is never written.

### `telemetry_modules` (module-telemetry)

The payload's `modules` list, flattened: one row per module a given install
reported on a given day, so the venture can see which composed modules its
reporting clients actually run.

| Column | Kind | Purpose |
|---|---|---|
| `install_id` | pseudonymous id | As above; the column erasure matches |
| `day` | date | The UTC day |
| `module` | label | A module name from the payload's `modules` list; the three columns together are the composite primary key |

Retention: rows whose `day` is older than `TELEMETRY_RETENTION_DAYS` (default
180 days) go in the same scheduled purge as `telemetry_events`.

## Signed links

Confirm and unsubscribe links are HMAC-SHA256 tokens (ADR 0006) carrying
`{ purpose, subject, exp?, kid }` where `subject` is the row id. Tokens
contain no PII beyond an opaque ULID; confirm tokens expire (7-day
default); unsubscribe tokens do not. Tokens are single-use by row state,
not by storage: nothing about links is stored server-side.

**The unsubscribe link confirms; the POST behind it acts** (issue #243).
Microsoft Defender Safe Links, Proofpoint URL Defense and most scanning mail
gateways fetch every link in a message before the recipient sees it, so a
`GET` that applied the unsubscribe opted out every subscriber at any such
company without a click. The `GET` now renders a one-button form with no
`action`, which posts back to the URL it was fetched from — so the token
stays out of the markup and only a submitted form changes anything. The
`POST` still acts immediately, which is what RFC 8058 one-click requires, and
still accepts `{"token":…}` as a JSON body for API callers.

## Subject access and erasure

- `GET /v1/<module>/admin/export.csv` (Bearer `ADMIN_TOKEN`) exports
  every stored column for the subject's records.
- `DELETE /v1/email-signup/admin/subscribers/{id}` hard-deletes the
  subscriber row. The path carries the opaque row id, never the email
  (issue #135): URLs outlive requests in access logs, proxies and
  browser history. Waitlist rows are removed by direct database access or
  a scheduled purge; an admin route for waitlist deletion is future work
  (see PROGRESS.md, deviations).
- Deletion invalidates outstanding links (tokens name the deleted row
  id; confirmation then redirects to the expired page).
