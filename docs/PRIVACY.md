# Privacy: what the harness stores, where, and for how long

This document is the data map required by architecture section 11 and
issue #13. It covers the two M1 modules: `cratefield-module-email-signup`
and `cratefield-module-waitlist`.

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
| `id` | ULID, generated | Row identity; the subject of signed links |
| `email`, `email_normalized` | PII (address) | As above; unique per `(email_normalized, product)` |
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

## Signed links

Confirm and unsubscribe links are HMAC-SHA256 tokens (ADR 0006) carrying
`{ purpose, subject, exp?, kid }` where `subject` is the row id. Tokens
contain no PII beyond an opaque ULID; confirm tokens expire (7-day
default); unsubscribe tokens do not. Tokens are single-use by row state,
not by storage: nothing about links is stored server-side.

## Subject access and erasure

- `GET /v1/<module>/admin/export.csv` (Bearer `ADMIN_TOKEN`) exports
  every stored column for the subject's records.
- `DELETE /v1/email-signup/admin/subscribers/{email}` hard-deletes the
  subscriber row. Waitlist rows are removed by direct database access or
  a scheduled purge; an admin route for waitlist deletion is future work
  (see PROGRESS.md, deviations).
- Deletion invalidates outstanding links (tokens name the deleted row
  id; confirmation then redirects to the expired page).
