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
table is declared `PersonalDataSet::unreachable`, so
`GET /v1/privacy/manifest` lists it under `unreachable`, with what it holds
and why erasure cannot match it, rather than under `not_personal`. It is the
shape issue #266 describes for `Outbox`, with one difference worth knowing —
a cooldown row is renewed on every later mail rather than written once, so
it lasts as long as the address keeps being mailed, not one window.

Retention: the row is written on the first mail and updated on every later
one. The module's scheduled handler deletes it once `last_sent_at` is more
than two hours old (twice the one-hour send window), so it goes on the first
scheduled run after two hours without a mail; a failed send releases it at
once.

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

### `crm_contacts` (module-crm)

One person or lead, keyed on `email_normalized` so filing the same address
twice updates one row rather than duplicating it. The column erasure matches
is `id`, not the address: a request naming a subject reaches the rows whose
`id` it carries.

| Column | Kind | Purpose |
|---|---|---|
| `id` | ULID, generated | Row identity; the subject of an access request and of erasure |
| `email`, `email_normalized` | PII (address) | The address as filed, and the trim + NFC + lowercase uniqueness key. Nullable — a contact may be filed with a name only |
| `name`, `phone` | PII | What the venture knows about the person |
| `locale` | label | Locale hint, as in `subscribers` |
| `organisation_id` | id | The organization they belong to; `ON DELETE SET NULL`, so removing an organization orphans the link rather than the person |
| `source` | label | Where the record came from |
| `data` | JSON | Whatever structured fields the venture keeps alongside the person |
| `created_at`, `updated_at` | timestamps | |
| `generation` | counter | The optimistic-concurrency guard; a PATCH must carry the value it read, so a stale edit is refused rather than overwriting a newer one |

### `crm_organisations` (module-crm)

The companies the venture deals with — a business record rather than a
person's. Declared `PersonalDataSet::none`, so `GET /v1/privacy/manifest`
publishes it as retained, and **erasure does not reach these rows**: deleting
one would take every contact linked to it with it. Review that before
relying on it. `email` and `phone` may hold an individual's details rather
than a shared switchboard, and a sole trader's record is a person's data in
practice. The rest is `id`, `name`, `domain` (the natural key the upsert uses),
`website`, `postal address`, `data`, the two timestamps and `generation`.

### `crm_tags` (module-crm)

The labels a venture files its records under — a name and a colour, and
nothing that names a person. Not personal; no erasure reaches it, and a tag
outliving every record it labelled is the point.

### `crm_taggings` (module-crm)

Which labels are filed against which record. `subject_id` is polymorphic
(`subject_type` is `contact`, `organisation` or `item`), so there is no
foreign key to match on and the declaration reaches these rows through
`subject_via` `crm_contacts` instead: it matches a contact id in
`subject_id` whatever the type says. That is safe only because ids are
ULIDs no other table's row shares. These rows are erased with the contact
they name; the tables are declared parent-first because the privacy module
erases in reverse catalog order, and `crm_taggings` is declared last for
exactly that reason.

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

`cratefield-module-privacy` answers all four questions over whatever the
venture composed. Three of its routes are admin-guarded through the
deployment's `ADMIN_TOKEN` (`cratefield_core::require_admin`): an unset
token leaves them disabled rather than open.

- `GET /v1/privacy/manifest` — unauthenticated. Per table: the kind, what
  erasure would do (`erase` | `anonymise` | `retain`, with a retained
  table's reason), and the columns an export names but does not copy.
- `GET /v1/privacy/export?subject=<id>` — every row every module holds for
  one subject; a column declared `redacted` is named but printed
  `[redacted]`. A table contributing more than 10 000 rows is truncated, and
  says so (`truncated`).
- `POST /v1/privacy/erase` — the preview: per table the action and the rows
  it matches (retained tables included, with their reasons), plus a signed
  `confirm_token` that lives 15 minutes. Writes nothing.
- `POST /v1/privacy/erase/confirm` — carries out the previewed erasure: the
  local statements run in one atomic batch (`batch_atomic`), then every
  `erase` table is re-counted and a non-zero count fails the request rather
  than report a success it did not achieve. The subject comes from the
  token, never the body.

The modules that predate it keep their own admin routes (issue #265):
`GET /v1/<module>/admin/export.csv` (Bearer `ADMIN_TOKEN`) exports every
stored column, and `DELETE /v1/email-signup/admin/subscribers/{id}`
hard-deletes the subscriber row. That path carries the opaque row id, never
the email (issue #135), because URLs outlive requests in access logs, proxies
and browser history; deletion invalidates outstanding links. Waitlist rows
are removed by direct database access or a scheduled purge — an admin route
for waitlist deletion is future work (see PROGRESS.md, deviations).

## External providers

Everything above reaches what the composed modules declared. An app also
holds personal data the harness never sees — its own Postgres, a CRM — and an
access request that stops at the harness is a partial answer. A **provider**
lets the same three routes cover that data (issue #653):

```rust
Privacy::new().provider(
    HttpProvider::new("app-db", "https://app.example.com/privacy")
        // The variable holding the shared HMAC secret, read via the
        // deployment's config; the value never lives in code.
        .secret_env("PRIVACY_PROVIDER_SECRET"),
)
```

`.timeout(Duration)` is the per-call timeout (default 10 s, capped by the
harness's 30 s outbound maximum); `.max_response_bytes(usize)` caps the body
(default 1 MiB, capped at 4 MiB) — an over-long one is `invalid_response`.

**The calls.** The module POSTs `{url}/export`, `{url}/erase/plan` or
`{url}/erase/apply` with `Content-Type: application/json` and a body
`{"subject": "<subject>", "request_id": "<id>"}`, and

```
Cratefield-Signature: t=<unix seconds>,v1=<lowercase hex HMAC-SHA256(secret, "<t>.<raw body>")>
```

the scheme the webhooks engine signs deliveries with
(`cratefield-module-webhooks`). A provider must verify it in constant time
and reject a `t` more than 300 s from now; the timestamp is bound into the
MAC, so a captured call cannot be replayed under a fresh one. The module
never forwards a provider's body or status text to the caller — only an
error kind.

**What a provider returns.** `export` and `erase/plan` answer 2xx with a
`sections` array; `erase/apply` answers any 2xx, which means applied.

- `export`: `{"sections":[{"name":"orders","description":"…","data": <any JSON>}]}`.
- `erase/plan`: `{"sections":[{"name":"orders","action":"delete" | "anonymise"
  | "retain","reason":"…"}]}` — `reason` required for `retain`.
- `erase/apply`: must be **idempotent on `request_id`** — repeated calls with
  the same id neither fail nor apply twice.

**`request_id`.** For erasure it is derived from the confirm token, so a plan
and every apply attempt for one confirmation carry the same id — what makes
a retry safe. Export gets an `export_…` id derived from the subject and the
moment it ran.

**What the routes return.** Each carries the local answer unchanged, plus
the providers':

- export: `{subject, tables}` as before, plus `"providers":[{"provider":
  "app-db","status":"ok","sections":[…]}, {"provider":"crm","status":
  "failed","error":"unavailable"}]` and `"complete": bool` (200).
- erase plan: the existing fields, plus `"request_id"` and a `providers`
  array of that `ok`/`failed` shape.
- confirm: local erasure runs first, atomically and verified as before, then
  each provider's apply. Adds `"request_id"`, `"providers":[{"provider",
  "status":"applied"} | {"provider","status":"pending","error"}]` and
  `"complete"`. **200** when every provider applied, **202** when any is
  pending. Pending providers are retried in the background (the request's
  `Defer`/`wait_until`), and re-POSTing confirm with the same token inside
  its 15 minutes retries them idempotently; after it expires, start a new
  erase plan — apply is idempotent, so applying again is safe. A failure is
  reported, never silently dropped.

**Error kinds** (`error`, never a provider's own words): `unavailable`
(network error, timeout, 5xx), `rejected` (4xx — a bad signature, a refused
subject), `invalid_response` (too large, malformed, wrong schema) and
`not_configured` (the secret variable is missing). Serving this protocol
*from* another harness deployment is out of scope here and tracked as CF14;
`FakePrivacyProvider` in `cratefield-testing` stands in for a real provider
in tests.

### A reference provider (TypeScript)

A Worker or Node 18+ fetch handler; fill in the three data-access stubs.
`applied` — a durable record of ids — is what makes `apply` idempotent.

```ts
const encoder = new TextEncoder();
const hexToBytes = (hex: string) =>
  new Uint8Array((hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));

async function verify(secret: string, header: string | null, raw: string) {
  const parts = Object.fromEntries(
    (header ?? "").split(",").map((p) => {
      const i = p.indexOf("=");
      return [p.slice(0, i), p.slice(i + 1)];
    }),
  );
  const t = Number(parts.t);
  if (!Number.isFinite(t) || Math.abs(Date.now() / 1000 - t) > 300) return false;
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
  );
  // crypto.subtle.verify is the constant-time MAC check.
  return crypto.subtle.verify(
    "HMAC", key, hexToBytes(parts.v1 ?? ""), encoder.encode(`${t}.${raw}`),
  );
}

export async function handle(
  request: Request, secret: string, applied: Set<string>,
): Promise<Response> {
  const raw = await request.text();
  if (!(await verify(secret, request.headers.get("Cratefield-Signature"), raw))) {
    return new Response("bad signature", { status: 401 });
  }
  const { subject, request_id } = JSON.parse(raw);
  const path = new URL(request.url).pathname;
  if (path.endsWith("/export")) return Response.json({ sections: await exportSections(subject) });
  if (path.endsWith("/erase/plan")) return Response.json({ sections: await planErasure(subject) });
  if (path.endsWith("/erase/apply")) {
    if (!applied.has(request_id)) { // idempotent on request_id
      await applyErasure(subject);
      applied.add(request_id); // a table, in production
    }
    return new Response(null, { status: 204 });
  }
  return new Response("not found", { status: 404 });
}

// The venture fills these in against its own store.
async function exportSections(_subject: string) { return []; }
async function planErasure(_subject: string) { return [{ name: "orders", action: "delete" }]; }
async function applyErasure(_subject: string) { /* delete or anonymise */ }
```
