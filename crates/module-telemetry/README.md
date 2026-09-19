<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-module-telemetry.png" alt="cratefield-module-telemetry — What clients did, never who did it." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-module-telemetry"><img src="https://img.shields.io/crates/v/cratefield-module-telemetry.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-module-telemetry on crates.io"></a>
  <a href="https://docs.rs/cratefield-module-telemetry"><img src="https://img.shields.io/docsrs/cratefield-module-telemetry?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-module-telemetry documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-module-telemetry

Aggregate usage telemetry for a Cratefield venture: clients report
batches of **counted** events to `POST /v1/telemetry/events`, every field
is validated against a closed grammar — an unknown field or an undeclared
value is a rejection, never a truncation — and the counts accumulate into
buckets in the venture's own database. No third-party analytics service,
no vendor SDK, and no field anywhere a sentence could fit.

```rust
use cratefield_module_telemetry::Telemetry;

let module = Telemetry::new()
    .events(["run", "report", "upgrade"])
    .modules(["telemetry", "waitlist"])
    .retention_days(180)
    .max_events_per_batch(64)
    .opt_out_command("fz telemetry off")
    .status_command("fz telemetry status");
```

Both vocabularies default to **empty, which fails closed**: a venture
that forgets to declare them runs a collector that rejects every batch
naming an event or a module, not one that counts anything it is sent.

**Consent ships as a model, not as wiring**: `consent::decide` is the pure
decision over the local opt-out, `DO_NOT_TRACK` and `CI`;
`consent::notice` generates the first-run text from the payload schema, so
it cannot promise less or more than the parser enforces;
`consent::status` renders the exact bytes a sender would POST; and a
rotation predicate bounds the install id to 30 days. The crate performs
none of the doing — it does not read the environment in production, print
the notice, persist an opt-out switch, provide the `fz telemetry off` and
`fz telemetry status` commands, hold a pending batch, or send anything (it
never opens a connection). That half belongs to the client, which must
wire the primitives so reporting is off with no network and off before the
next batch. The install id is 16 random bytes the caller supplies, never
derived from anything about the machine — pseudonymous, with no stored
link to a person.

**Routes**: `POST /v1/telemetry/events` (public, unauthenticated — the
caller is a CLI; the guards are the `RateLimiter` port, the batch ceiling
and the closed grammar), `GET /v1/telemetry/notice` (the
machine-readable consent notice, unauthenticated like the privacy
manifest), and `GET /v1/telemetry/admin/usage` (admin-guarded aggregate
rows; the GROUP BY is the privacy control, so no per-install row exists
to leak).

**What is never sent**: identifiers or addresses, paths, repository or
branch names, prompts, model output, commit or issue text — free text of
any kind. Rejection bodies never echo what the client sent.

Emits `telemetry.recorded` after an accepted batch. Both tables are
declared in `personal_data()` with `subject: "install_id"` and
`Disposition::Erase`, so `cratefield-module-privacy` can erase exactly
one install's rows from the id its own client prints.

See `docs/TELEMETRY.md` for the payload contract, the consent model and
the client rules this crate implements.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
