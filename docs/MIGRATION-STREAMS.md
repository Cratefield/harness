# Two repositories, one database: how D1 migrations behave

Measured for issue #66, 2026-09-07, wrangler 4.129.0, `--local`. A
sidecar module owns tables in the **same** database as its host but ships
its migrations from its own repository, so two independent streams apply
to one database. Nobody had tried it. This is what happens.

Reproduce with two directories, each with its own `wrangler.toml` naming
the same `database_id` and its own `migrations_dir`, both applying with
`--persist-to` pointing at one state directory.

## 1. Two streams coexist

wrangler records **file names** in `d1_migrations` and tolerates rows it
did not write. Each repository's "unapplied" set is its own files minus
the names already in the table, so numbering restarting at `0001` in the
second repository is not a problem:

```
id  name
1   0001_email-signup_0001_init.sql   (host)
2   0002_waitlist_0001_init.sql       (host)
3   0001_acme-pricing_0001_init.sql   (sidecar)
```

Applying either stream again is a no-op. This is the answer the epic
needed: **the arrangement works.**

## 2. A name collision is skipped, and reported as success

Give the sidecar a file whose name the host has already applied, with
different SQL. wrangler answers:

```
✅ No migrations to apply!
```

and the SQL never runs. Nothing warns. In practice collected names are
`<NNNN>_<module>_<id>_<name>.sql`, a module lives in exactly one stream,
and a mount whose name collides with a compiled-in module is ignored at
runtime, so this needs two repositories shipping the same module name.
Unlikely, and invisible when it happens.

## 3. The real hazard: the same migration re-runs when a module moves

The `NNNN` prefix is the **repository's** global counter, pinned per
module migration in `.harness-lock.json`. It is stable within a
repository and meaningless across them. So when a module moves between
mounts — the migration path in [MOUNTING.md](MOUNTING.md) — its file
arrives under a different number:

```
sidecar:  0001_acme-pricing_0001_init.sql   (applied)
host:     0003_acme-pricing_0001_init.sql   (a name the database has never seen)
```

wrangler runs it again. Demonstrated: the same SQL under a new number
re-executed and failed on `UNIQUE constraint failed: acme_prices.id`.
`CREATE TABLE IF NOT EXISTS` hides this; an `ALTER`, an index, or any
seed data does not.

**The fix needs no code.** When the adopting repository collects the
module, give `.harness-lock.json` the file name the other stream already
used, so `fz migrations collect` writes that name and wrangler correctly
sees it as applied. The lockfile already pins `module/id -> file`; this
is one hand-edited entry, and it is the whole difference between a clean
move and a re-applied migration. Say so wherever the move is documented.

## 4. A failure stops the run and records nothing

A migration that errors is not written to `d1_migrations`, and no file
after it runs. Forward-only, halting at the first error, with nothing
half-recorded. Re-running retries from the failed file.

## 5. Do not apply two streams at once

Both applies started together, locally: one died with

```
✘ [ERROR] The Workers runtime failed to start.
```

and its six tables were missing, while the other completed. Loud rather
than silent, and easy to avoid.

This is a `--local` observation: it is contention over the local workerd
and its sqlite file, not evidence about remote D1, which applies over the
API and was not tested here. Either way the guidance is the same:
**serialize the two streams.** Apply the host's, then the sidecar's, and
never in parallel from CI.

## What this leaves open

Everything in #66 that depends on the host *knowing* the sidecar's
tables — the cross-boundary collision check, `fz doctor`, and including
sidecar tables in `fz data export` — still needs the sidecar to declare
them (#61). That is a separate question from whether the two streams can
share a database, which they can.
