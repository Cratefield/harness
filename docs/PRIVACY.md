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

## Serving the protocol

The provider contract has two ends, and until now only one of them was a
product. `Privacy::provider` is this deployment reaching a warehouse or a CRM.
`Privacy::serve_provider` is the other: a deployment that holds such a system
of its own, or that *is* the system another deployment reaches, answering the
same three signed POSTs over the same declarations
(`crates/module-privacy/src/provider_server.rs`).

```rust
Privacy::new().serve_provider("PRIVACY_PROVIDER_SECRET")
```

The harness nests a module's routes under its name, so the three paths are
`POST /v1/privacy/provider/export`, `POST /v1/privacy/provider/erase/plan` and
`POST /v1/privacy/provider/erase/apply`.

**Opt-in, because the routes are a public door.** A deployment that never
calls `serve_provider` has no such routes at all — they are not mounted to
answer 404, they are absent from the router. Between the reference provider
above and this, there are two ways to close the other end of the protocol, and
a deployment that only ever calls out needs neither.

### Where the answers come from

Not from a hand-written list, which is the failure mode the whole catalogue
exists to avoid. `export` calls the same `handlers::subject_tables` the local
`/v1/privacy/export` route renders, so a signed caller and an operator reading
the admin route are shown one catalog read by one piece of code: a deployment
cannot answer a signed caller differently from an operator.

| Route | Answers |
|---|---|
| `provider/export` | one section per declared table that is not `none`: `{name, description?, data: {module, kind, rows, truncated}}` |
| `provider/erase/plan` | one section per table: `{name, action: "delete" \| "anonymise" \| "retain", reason?, columns?, rows}`; writes nothing |
| `provider/erase/apply` | `{"applied": true, "request_id": …, "subject": …}` once the batch ran and the verification found nothing left |

Everything the local export does carries over: a column the declaration names
in `redacted` appears with the value replaced by `[redacted]` (ADR 0015), a
table contributing more rows than the per-table cap is `truncated`, and a table
keyed one hop away is reached through `SubjectVia` — `deletion_jobs` is keyed on
`provider_subject` and is found through `identities.user_id`, the same join an
erasure takes. `rows` is not part of the contract — the calling module drops
it — but it is counted anyway, because an operator debugging a provider
deployment with `curl` reads a plan that says how many rows each action
matches, not one that only says what kind of action it is.

**Two vocabularies for the same act.** A plan section says `delete`, not
`erase`: the protocol's word for what a provider will do to rows is `delete`,
where the local preview describes what this deployment's own erasure does.
And a `retain` **must** carry a `reason` — the calling module rejects a plan
that keeps something silently, because "we are keeping this" without a reason
is the one thing a subject is most entitled to be told. A declaration that
keeps a table with no reason is refused by `HarnessBuilder::build`, so the case
the route guards against is a declaration written in a shape the build does not
check; should one exist anyway, the plan fails rather than produce an answer the
caller would discard.

**`Unreachable` is a `retain`, and the reason is why.** `Disposition::Unreachable`
is a table no equality predicate on the subject can reach — `auth-passkeys`'
challenge budget, keyed `email:<address>` or `ip:<address>`, is the case — and it
holds personal data, which is why the subject-facing manifest gives it its own
bucket rather than filing it as `none`.

The protocol has no fourth action, so it plans as `retain`, carrying the
declaration's reason verbatim. That is the honest mapping rather than a
convenient one: the rows stay — `Disposition::keeps_row` counts it — so `delete`
and `anonymise` would each be a claim about rows the deployment never touched,
while `retain` says only what is true. The reason is what keeps the answer
faithful to the declaration, because the two read very differently to a subject:
*we keep these because the law requires it* is not *we keep these because no
predicate can find them*.

Two things follow, and both are load-bearing. An `erase/apply` emits no
statement for a table its own plan retained, so a plan cannot promise an
erasure the apply then performs or skips. And a reason that is blank still
fails the plan: `validate` checks the reason on a `Retain` and on a
blank-subject `Unreachable`, but a `Unreachable` written as a struct literal
with a real subject column — which is the shape `auth-passkeys` uses, and the
only way one reaches `subject_sets` at all — is checked as an ordinary
declaration and its reason is not looked at. The client would discard the whole
plan over that one line.

A deployment holding such a table therefore has a working plan, a working
export and a working apply. `AuthWorker::builder` mounts passkeys always, so
this is not an edge case there: `crates/auth-worker/tests/privacy_provider.rs`
asserts the section, its action and its reason.

### The signature is the authorisation

Not `ADMIN_TOKEN`, deliberately. A caller on another deployment has no account
here and no admin token to present, so an admin guard would refuse every
legitimate call while authorising nothing this protocol lacks. The HMAC over
the raw body *is* the authorisation: "this deployment asked for this subject's
data".

It is the same layout the webhooks engine signs deliveries with, checked by the
same receiver — core's `WebhookVerifier` over `StripeStyle { header:
SIGNATURE_HEADER }` — in constant time, at the same 300 s tolerance in both
directions, and over the exact raw bytes received **before** the body is
parsed. Re-serialising parsed JSON would verify a string the caller never
signed. One implementation covering both senders and receivers is what stops
the two from drifting apart.

Every way a call fails to prove itself is one answer: a missing header, a wrong
secret, a timestamp outside the window and a tampered body all get the same
`401 privacy-provider-unverified`, so a caller probing the endpoint learns
whether it signed correctly and nothing about how the deployment is configured.
A deployment with the routes mounted but no secret configured is the one case
that answers differently — `503 not_ready`, logging which variable to set —
because the operator has to be able to tell a missing secret from a bad
signature. Opening the door instead, treating an absent secret as matching
everything, would serve every subject's data to anyone who found the URL.

The secret's **name** is taken at build; its value is read through the config
port at request time, as an outbound `HttpProvider::secret_env` does. One build
therefore works in every environment, and rotating the secret is a config push
rather than a redeploy.

**No second confirmation here.** Erasure elsewhere is two calls with a
confirmation token because an erasure cannot be undone and one HTTP call is
not a moment to reconsider. That reconsideration happened at the *caller*:
`POST /v1/privacy/erase` previewed it and an admin confirmed the token, and
this route is reached only afterwards. Requiring a second confirmation from a
system that cannot show the operator the preview would make the protocol
impossible to complete honestly.

### The signature is a bearer credential in practice

The HMAC covers the timestamp and the raw body and nothing else — not the
route, not the HTTP method, not the caller. All three routes take the same
`{subject, request_id}` shape, so a signature captured for `provider/export`
verifies unchanged on `provider/erase/apply`. This is a known limitation of
the protocol's signing scheme, tracked separately, and mounting the server
does not change it.

The consequence is that a captured signed request is, for its 300 s window, a
credential somebody else can present, and there is no replay ledger: the same
request offered twice inside the window is honoured twice, and the erasure
route will run again.

So treat these routes as reachable only over transport an attacker cannot
observe, keep request bodies out of access logs, debug traces and error
reports at the edge — an erasure body carries the subject identifier — and
handle the signing secret with the care you would give a credential
transmitted on every call, because that is what it is. Binding the route into
the signed payload is the actual fix. It changes the wire format, so it has to
move in step with every deployed provider.

### Idempotence is the database's

`erase/apply` is idempotent on `request_id` because the SQL is. The statements
run in one atomic batch; every `erase` table is then re-counted, and a
non-zero count fails the request rather than report a success it did not
achieve. Run twice, the second pass matches nothing, counts nothing and
answers `200`.

There is deliberately no isolate-local "already applied" cache. Such a cache is
per-isolate, so it would claim an idempotence it cannot deliver across two
Workers, and a cache that answers "already applied" for a request that never
was is a lie with a status code on it. The `request_id` is echoed rather than
stored; a genuinely new id redoes the work, which is what a new erasure
should do.

## Ordering: the account provider goes last

Registration order is not the erasure order. `HttpProvider::account()` marks
the one provider holding the **identity itself** — the account row everything
else is keyed on — and marked providers are applied last, in all three loops
(export, plan and apply alike):

```rust
Privacy::new()
    .provider(
        HttpProvider::new("crm", "https://crm.example.com/privacy")
            .secret_env("PRIVACY_PROVIDER_SECRET"),
    )
    .provider(
        HttpProvider::new("mail", "https://mail.example.com/privacy")
            .secret_env("PRIVACY_PROVIDER_SECRET"),
    )
    // The venture's own auth Worker: it holds the account, so it goes last.
    .provider(
        HttpProvider::new("auth", "https://auth.example.com/v1/privacy/provider")
            .secret_env("PRIVACY_PROVIDER_SECRET")
            .account(),
    )
```

The reason is the whole point of the marking. Erasure identifies its subject by
a value, and every provider after the account provider is reached *through*
that value — a CRM holding only `account_id` might be asked to erase after the
accounts table is already gone, and a row keyed on a subject the calling
deployment no longer holds an identifier for cannot be found, let alone erased.
The row survives, and the erasure reports itself complete.

The ordering is a stable partition: unmarked providers in registration order,
then the account-marked ones also in registration order. It is applied
identically in all three loops because the order that finds a subject's rows
is the order that erases them — an export that read the account provider last
while an apply read it first would describe a deployment that does not exist.
A build is expected to mark at most one provider this way; marking several
breaks nothing, they simply go last in the order they were registered.

## The auth Worker as a provider

Google, Apple and Meta do not sign in as a user and do not hold this
deployment's `ADMIN_TOKEN`, which is exactly the caller the provider protocol
exists for. `AuthWorker::builder` composes `Privacy::new().serve_provider(..)`
when `PRIVACY_PROVIDER_SECRET` is set to a non-empty value; absent, empty or
whitespace, `Privacy` is not composed at all and those paths do not exist.
Mounting it in `builder` rather than in `build` is what makes it survive a
wrapper venture — a wrapper calls the same method, so it inherits the routes
with the instance's configuration, and one that clears the flag does not get
them.

The configuration keeps a **bool, never the secret** (`privacy_provider`). The
value is a binding secret the config does not need and must not hold: a
`Debug` of the struct says whether the feature is on and nothing about the
key, and the module re-reads the value itself at request time — which is what
makes rotation a config push rather than a redeploy.

**What one `erase/apply` removes from an auth deployment**, in one atomic
batch and then verified row by row:

- `credentials` — the password hashes and the passkeys
- `sessions` — every sign-in still valid
- `single_use_tokens` — one-time links and codes, and **refresh tokens**: there
  is no refresh-token table, a refresh token is a `single_use_tokens` row of
  kind `refresh_token` whose payload names the session, and only its SHA-256
  is stored
- `identities` — every way to sign in, every kind, including the `import`
  identities CF05 pre-links
- `users` — the account row itself, erased last among the tables it parents

`deletion_jobs` is **retained**, with the reason the declaration gives: a
deletion request and what was done about it is the record that the request was
honoured, and erasing it would destroy the only evidence the erasure happened
while breaking the status page the person is sent to.

A later sign-in with that subject fails, refused the same way a wrong password
is. `crates/auth-worker/tests/privacy_provider.rs` drives the whole property
through HTTP rather than by counting rows — login succeeds before the erasure,
is refused after, another account keeps its own session throughout — because a
row count would pass while the login path kept working off some other table.

**The subject is the harness subject id.** Every `auth-core` declaration keys
on `users.id`, and that is what the protocol's `subject` means. It is *not* the
identity provider's own id for the person, which is the value Google, Apple and
Meta actually send: an account provider holding only
`google-subject-alice-0001` is answered `200 {"applied": true}` while erasing
nothing. Resolving a provider's id to an account is the `identities` join
`auth-meta`'s deletion-job drain already performs, not this route's. That gap
is pinned by an assertion of what happens today, so a change that starts
resolving provider ids fails a test and gets a decision rather than passing
silently.
