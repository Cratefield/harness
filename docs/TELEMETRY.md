# Telemetry

`cratefield-module-telemetry` (issue #413) is how a venture learns what its
clients do without learning who is doing it. A client reports batches of
**counted** events, every field is validated against a closed grammar, and
the counts accumulate into buckets in the venture's own database. There is no
third-party analytics service, no vendor SDK and no cookies: the aggregate
lands next to the venture's other tables, under the same retention and
erasure rules as the rest of them ([PRIVACY.md](PRIVACY.md)).

## What it is

A module named `telemetry`, mounted at `/v1/telemetry`, with three routes and
two tables. A venture composes it like any other module and declares two
closed vocabularies — the event names it wants counted, and the composed
module names a client may report. Everything else in a payload is fixed by
the module.

It is not a product-analytics tool. There are no per-user funnels, no session
replay, no retention cohorts, and no field anywhere that could identify a
person across visits ([Out of scope](#out-of-scope)). That is not a missing
feature; it is what makes the consent story below short enough to be true.

The boundary in one line: the module counts what happened and cannot record
anything about whom it happened to — not by discipline, but because there is
no field to put it in. A payload that tries to carry a `prompt`, a path or a
note is rejected, not trimmed: unknown fields are a hard error, enforced by
`Batch::parse`, written by hand over `serde_json::Value` precisely so that a
rejection cannot echo the offending value the way serde's own error messages
would. No client smuggles free text through the one route that exists to be
safe to talk to.

## Wiring a venture

```rust,ignore
Harness::builder()
    .venture(Venture::new("acme", "acme.example.com")
        .public_url("https://acme.example.com"))
    .module(Waitlist::new().products(["kontinuum"]))
    .module(Telemetry::new()
        .events(["run", "report", "upgrade"])
        .modules(["telemetry", "waitlist"]))
    .build()?
```

Both builder lists are the whole vocabulary, and both are closed:

| Builder | Declares | Anything else |
|---|---|---|
| `.events([…])` | The event names a batch may count, `run` in the example below | An unknown event name is rejected, not recorded as a new series |
| `.modules([…])` | The composed module names a client may report | A name outside the list is rejected |

Closed at the route, not at read time: an aggregate that only ever holds the
series the venture asked about cannot surprise the privacy page that
describes it.

## Routes

| Route | Behaviour |
|---|---|
| `POST /v1/telemetry/events` | A batch of counted events, schema version 1 below. Answers `202 {"ok":true}`. Unauthenticated by design — the caller is a CLI, not a browser, and a captcha is unanswerable by a program — so the guards are the `RateLimiter` port, the batch cap and the closed grammar, never credentials. |
| `GET /v1/telemetry/notice` | The canonical machine-readable consent notice: the exact first-run text, the one-line command that turns reporting off, and every payload field with its permitted vocabulary. Also unauthenticated — a notice you must authenticate to read is not a notice. |
| `GET /v1/telemetry/admin/usage` | Admin. Aggregate rows only; no per-install rows. |

## The payload, version 1

```json
{
  "schema": 1,
  "install": "7b0a1f2c3d4e5f60718293a4b5c6d7e8",
  "client": {"kind": "cli", "version": "0.4.1", "platform": "linux", "arch": "aarch64"},
  "modules": ["telemetry", "waitlist"],
  "events": [
    {"name": "run", "outcome": "ok", "error": "none", "duration": "1s-10s", "count": 3},
    {"name": "run", "outcome": "error", "error": "network", "duration": "10s-1m", "count": 1}
  ]
}
```

Every field is an enum, a bounded count, a duration bucket, a fixed-width hex
id or a numeric version triple. There is no string anywhere a sentence could
fit.

| Field | Grammar | Why |
|---|---|---|
| `schema` | `1` | Any other value is rejected, not coerced. A schema bump is a new contract, not a hint |
| `install` | exactly 32 lowercase hex characters | Sixteen random bytes, hex-encoded ([Identity](#identity)) |
| `client.kind` | `cli` \| `desktop` \| `agent` \| `server` \| `browser` \| `other` | What kind of thing is reporting |
| `client.version` | `MAJOR.MINOR.PATCH`, each part 1–6 digits | No pre-release, no build metadata: those are free text wearing a semver costume, so a client rounds down to the release triple |
| `client.platform` | `linux` \| `macos` \| `windows` \| `other` | |
| `client.arch` | `x86-64` \| `aarch64` \| `other` | |
| `modules` | 0–32 entries, each from the venture's `.modules([…])` vocabulary, no duplicates | Which of the venture's modules the client composes |
| `events` | 1–64 entries | The batch cap; a client never flushes more |
| `events[].name` | from the venture's `.events([…])` vocabulary | |
| `events[].outcome` | `ok` \| `error` \| `cancelled` | |
| `events[].error` | `none` \| `network` \| `timeout` \| `auth` \| `config` \| `permission` \| `not-found` \| `conflict` \| `rate-limited` \| `unsupported` \| `internal` \| `other` | A class, never a message |
| `events[].duration` | `unknown` \| `under-100ms` \| `100ms-1s` \| `1s-10s` \| `10s-1m` \| `1m-10m` \| `over-10m` | A bucket, not a stopwatch |
| `events[].count` | 1–100000 | The batch is *counted*: one entry aggregates many runs |

Two rules span fields:

- **Unknown fields are a rejection**, at the top level and inside `client`
  and `events` alike. The guard is `Batch::parse`, written by hand over
  `serde_json::Value` rather than delegated to serde, because serde's error
  messages quote the offending value and a rejection body must never carry
  it; serde's `deny_unknown_fields` derives serve only the trusted status
  round trip, never the ingest route. A client that grows a `prompt` key in
  a later release fails to report rather than reporting it.
- **`error` is `none` exactly when `outcome` is not `error`.** A success with
  an error class, or a failure without one, is rejected — the pairing is
  redundant on purpose, because a field that is always consistent is one a
  reader never has to second-guess.

Rejection messages never echo the offending value. An error body that quoted
what the client sent would be the free-text channel the module exists to
close, one `Debug` print away from a log file.

## What is never in a payload

- No user identifiers, emails, account or organisation names.
- No IP address stored — the client IP touches the route only as an
  in-memory rate-limit key, honouring the standing rule in
  [PRIVACY.md](PRIVACY.md).
- No repository, branch, file path or file contents.
- No prompts, model output, commit messages or issue text.
- No free text of any kind — there is no field that could hold it, and an
  unexpected one is a rejection.

## Consent

Reporting is optional, on by default, and the default only survives because
it is obvious and reversible. The module ships the consent model as pure,
tested primitives — `consent::decide`, `consent::notice`, `consent::status`
and the 30-day rotation predicate — and none of the wiring: nothing in this
crate reads the environment in production, prints anything, persists an
opt-out flag, accumulates a pending batch or opens a connection. Each rule
below is therefore a requirement on the client (for this repository,
Colonizer), implemented on top of the primitives:

- **The first run prints exactly what will be sent, once, with the one-line
  command to turn it off.** The text is `consent::notice`'s — generated from
  the payload schema, so it cannot drift from what the parser enforces — and
  the same text is served by `GET /v1/telemetry/notice`, so a client shows
  what the server declares rather than its own paraphrase of it. Printing it
  once, on first run, is the client's work.
- **`DO_NOT_TRACK` and `CI` disable reporting with no further
  configuration.** `consent::decide` takes the environment as an input the
  caller supplies — `std::env::var` in production, a map in a test — and a
  variable counts as set when it is present, non-empty after trimming, and
  neither `0` nor `false` — so a vendor that exports `CI=false` switches
  nothing, and neither does an empty `DO_NOT_TRACK=` left in a dotfile.
- **`fz telemetry status` prints the payload that *would have been* sent,
  verbatim** — the same bytes the wire would carry, from the same
  serializer. The rendering is `consent::status`'s, given the pending batch;
  the command, the pending batch and the send it previews are the client's.
  The command is a builder setting (`.status_command(…)`); this is the
  default the notice prints.
- **Switching it off is local.** No network call, and honoured before the
  next batch: a client that opts out mid-session sends nothing further. The
  switch is the `opted_out` flag `consent::decide` reads; persisting it and
  wiring the `fz telemetry off` command are the client's work.

The precedence is fixed — it is what `consent::decide` implements — and each
rule beats the one under it:

| Priority | Input | Effect |
|---|---|---|
| 1 | The local opt-out | Off — the person's own switch beats the environment |
| 2 | `DO_NOT_TRACK` set | Off — a standing industry-wide opt-out is honoured verbatim |
| 3 | `CI` set | Off — an automated environment has not consented to anything |
| — | none of the above | On |

## Identity

The `install` field is an install-scoped random id: 16 random bytes the
caller supplies, hex-encoded to the 32 characters the grammar accepts. It is
**never derived** from the hostname, a MAC address, an account, or anything
else about the machine — deriving identity from hardware is how "random"
ids quietly become tracking ids.

The id rotates every 30 days. Rotation bounds how long any one id can
accumulate: after it, the same install reports under a new id, and nothing
anywhere stores the link between the two. That has a cost on the erasure
side, stated in [Privacy](#privacy) rather than buried: an erasure reaches
the rows of the id it names, and no further back.

## The client contract

A CLI, a desktop app or an agent harness must be able to report without the
Rust crate. The whole contract:

- **Endpoint:** `POST /v1/telemetry/events`, the JSON body above,
  `Content-Type: application/json`. `202` means accepted.
- **Batching:** accumulate locally; flush at most once per run or once per
  24 hours, whichever is sooner; never exceed 64 events in one batch.
- **Failure:** drop the batch on any non-2xx and move on. Retrying
  indefinitely turns a reporting feature into an outage amplifier; lost
  counts are the correct loss.
- **Never block the user's command on the send.** The flush happens out of
  the command's path, or after it has finished.
- **Offline:** the notice stays printable and the opt-out stays effective
  with no network. Consent that needs a round trip to be checked is not
  consent, it is telemetry with extra steps.
- **Rotation:** regenerate the install id every 30 days, from fresh random
  bytes, keeping no record of the previous id.

Colonizer, the automation that works on this repository, is exactly such a
client, and implements the contract as written — one more reason the body
above is a published promise rather than an internal shape.

## Storage and retention

Two tables in the venture's own database, and no row per event — counts
accumulate into a bucket:

- `telemetry_events` — the counters. `bucket_key` is the primary key: ten
  components joined with `|`, **day first** — the day, then the install id,
  then the client shape (`client_kind`, `client_version`, `platform`,
  `arch`), then the event's four dimensions (`event`, `outcome`,
  `error_kind`, `duration_bucket`). The day is part of the key, not a label
  on it: two writes on different days are different buckets, and a bucket is
  where one install's counts accumulate **for one day** — the same `day`
  column the retention purge compares. The value is that day's accumulated
  `events` count, with `first_seen_at` and `last_seen_at` for the bucket's
  own lifetime. The nine components around the event name are closed values
  that cannot carry `|`, and `validate_config` refuses a declared name that
  does, so the tuple splits uniquely despite the name being venture-chosen.
- `telemetry_modules` — the payload's `modules` list, flattened: `install_id`,
  `day` and `module`, unique together, so the venture can see which composed
  modules reporting clients actually run.

Retention is a scheduled purge: rows whose `day` is older than
`TELEMETRY_RETENTION_DAYS` (default 180 days) are deleted, from both tables.
Accepting a batch emits `telemetry.recorded` on the event bus, counts only,
so a venture can react to volume without scraping its own tables.

## Out of scope

Per-user funnels, session replay, retention cohorts, and anything that
identifies a person across visits. A venture that wants those should reach
for a product analytics tool and say so in its own privacy policy — the
honest version of that decision names the vendor, and this module cannot be
stretched into it without losing the property every section above leans on.

## Privacy

**The payload is pseudonymous, with no stored link to a person — and this
document does not call it anonymous.** "Anonymous" promises that nobody
*could* link the data back; the honest claim is that the harness holds no
link. The distinction is load-bearing for everything below.

Both tables are declared in `Module::personal_data()` with
`subject: "install_id"`, `DataKind::Usage` and `Disposition::Erase`. The
reasoning, in full:

- The payload carries nothing the venture can tie to a person, so the
  harness cannot look a subject up on its own — there is no email, no
  account id, nothing to match a request against.
- The install id *is* a key, and the person's own client prints it in
  `fz telemetry status`. So an erasure request that supplies the id deletes
  exactly their rows and nothing else — the same person can act on their own
  data without the venture ever learning who they are.

The honest cost, stated rather than buried: **rotation bounds what one
erasure reaches.** Rows written under an id that has already rotated away
cannot be reached from a later id, because no link between rotations is
stored — that is the price of the property above, and it is the right trade:
the alternative is a stored rotation chain, which is a lifetime identifier
with a conscience. The 30-day window means the unreachable tail of any
erasure is bounded by the retention purge on top of it, at most
`TELEMETRY_RETENTION_DAYS` further back.

- No IP address is stored anywhere in either table; the client IP is a
  rate-limit key in memory only, per [PRIVACY.md](PRIVACY.md).
- Rejection bodies never echo a value the client sent, so the error path is
  not a side channel around the closed grammar.
- Both tables appear in `fz data export` via `Module::tables()`, and in
  `GET /v1/privacy/manifest` via the declarations above, so a composed
  venture's privacy page describes them without this file being a second
  source of truth.

See [PRIVACY.md](PRIVACY.md) for the column-level data map entries.
