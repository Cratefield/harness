# Rollback and recovery for forward-only migrations

Design for issue #35. Forward-only is decided (ADR 0004, `docs/MODULE-AUTHORING.md`
step 3): there is no `down`. What that decision owes an operator is a written
answer to every "undo" they will ask for, so nobody reaches for a hand-written
`DROP` at 2am.

Context: [RECONCILIATION.md](RECONCILIATION.md) (#29, the boot sequence and
its failure behaviour) and ADR
[0008](adr/0008-native-runtime-is-multi-tenant-database-per-tenant.md)
(one database per tenant, which is what makes every answer below a
single-database operation).

> **Status: proposed.** Not drilled. Runbook C has never been executed
> against a real database — see [§7](#7-what-has-not-been-drilled). Every
> command below is verified to exist and take the flags shown; none has
> been run in anger. Treat the timings as unknown, not as fast.

## 1. What forward-only costs, and what it buys

The cost is the whole of this document: an `undo` is an operator
procedure rather than a `migrate down` command.

What it buys is that the procedure is *possible*. A `down` migration is
code that runs rarely, is tested less than the `up`, and is written by
someone who has not yet seen the failure it is for. Every answer below
uses either a forward migration — ordinary code, reviewed and applied the
way everything else is — or a restore, which is the database vendor's
problem and is exercised by their customers constantly.

The four questions an operator actually asks, in the order they arrive:

| Question | Runbook |
|---|---|
| It failed halfway. What state am I in? | [A](#2-runbook-a-a-migration-failed-part-way) |
| It applied, and it was wrong. | [B](#3-runbook-b-a-migration-applied-and-is-wrong) |
| Put it back the way it was. | [C](#4-runbook-c-rewind-one-tenant-entirely) |
| The schema is fine; put the *old build* back. | [D](#5-runbook-d-rolling-the-code-back) |

## 2. Runbook A: a migration failed part-way

**First, establish which kind it was**, because the answer differs and
the two are not distinguishable by looking at the error.

A **transactional** migration cannot half-apply. Both adapters write the
migration and its `harness_migrations` tracking row in one transaction
(RECONCILIATION.md §4), so either both happened or neither did. There is
no partial state to clean up: fix the SQL and re-run.

A **non-transactional** one — the `CREATE INDEX CONCURRENTLY` case
Postgres refuses inside a transaction — runs alone, and its tracking row
is written only on success. So a crash between the two leaves the work
done and unrecorded, and the next reconcile runs it again.

**That is why idempotency is not optional for these**, and why
`MODULE-AUTHORING.md` now requires it. A non-idempotent
`no-transaction` migration is a migration that fails on its second run,
which is the run that happens after a crash — the worst possible moment
for a new error.

```bash
# What does the database think it has applied?
wrangler d1 execute <database> --remote \
  --command "SELECT id, applied_at FROM harness_migrations ORDER BY id"

# Postgres, through the harness's own runner:
fz migrations apply --dialect postgres --url "$DSN"   # idempotent; re-runs what is missing
```

If the id is present, the migration is recorded and Runbook B applies.
If it is absent, re-running is the fix — and if re-running fails because
the object already exists, the migration was not idempotent and that is
the bug to fix, in a **new** migration, not by editing the failed one.
Editing it is refused by CI (#34) and by both engines' checksum
comparison at boot.

A crash mid-`CREATE INDEX CONCURRENTLY` also leaves Postgres with an
invalid index, which the retry must drop before recreating. The runner
(#30) does that explicitly; until it exists, do it by hand:

```sql
SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid;
DROP INDEX CONCURRENTLY <name>;
```

## 3. Runbook B: a migration applied and is wrong

**Write a forward migration that corrects it.** This is the ordinary
case and it is deliberately boring: a new `NNNN_fix_whatever.sql`,
reviewed, applied like any other. The wrong migration stays in history
because that is what history is.

The additive rule means a wrong migration should not have destroyed
anything — new tables, new nullable columns, no drops. A **bad backfill**
is the exception that gets past it: the schema change was additive and
the `UPDATE` inside it was wrong.

If data was lost, the question is whether it can be recomputed. If it
can, the forward migration recomputes it and you are done. If it cannot,
you need a copy of the rows from before, and here the two paths differ
sharply.

### Postgres

Restore to a **scratch database** — a separate instance from the same
PITR window — then copy the affected rows across. The live database
keeps serving throughout, and no other tenant is involved because no
other tenant shares this database.

### D1: this is not available

`wrangler d1 time-travel restore` is **in-place only**. It has
`--timestamp` and `--bookmark` and no target parameter; there is no
subcommand that restores into a different database. The parent help text
mentions "restore, fork or copy"; the CLI implements `info` and
`restore`.

So on D1 there is no way to look at yesterday's rows while today's
database keeps serving. The options are both bad and it is better to know
that before 2am than during it:

1. `wrangler d1 export` the current state, `time-travel restore` to
   before the bad backfill — **losing every write since** — then replay
   what you exported. Feasible only if the tenant tolerates the window.
2. Accept the loss, and write the forward migration to recompute or to
   mark the affected rows as unknown.

**The requirement this produces:** for any migration containing a
backfill on the D1 path, export first. It is one command, it is cheap,
and it is the only copy that exists.

```bash
wrangler d1 export <database> --remote --output "pre-<migration-id>.sql"
```

## 4. Runbook C: rewind one tenant entirely

The expensive last resort, and cheap only by comparison with shared
storage: one tenant's database is restored and no other tenant is
touched, because no other tenant is in it.

Because the migration history lives **inside** the database, the restored
copy knows exactly where it stands — `harness_migrations` comes back with
it. Reconcile then applies what is missing and nothing else. This is the
property that makes the runbook short, and it is worth stating as the
reason the tracking table is not held centrally.

```bash
# 1. Find the restore point. Do this first: it is read-only and it tells
#    you whether the window even covers the incident.
wrangler d1 time-travel info <database> --timestamp "2026-09-09T22:00:00Z"

# 2. Take an export of the current state anyway. The restore discards it.
wrangler d1 export <database> --remote --output "before-restore.sql"

# 3. Restore. Destructive of everything after the timestamp.
wrangler d1 time-travel restore <database> --timestamp "2026-09-09T22:00:00Z"

# 4. Reconcile forward. The restored database reports what it has.
wrangler d1 migrations apply <database> --remote
```

The window is **30 days** on D1. Past that there is no restore point and
the answer is the nightly export, which is why §5 requires one.

On Postgres the shape is identical with the provider's PITR in place of
steps 1 and 3, and `fz migrations apply --dialect postgres --url "$DSN"`
in place of step 4.

## 5. Runbook D: rolling the *code* back

Every runbook above is about the database. This one is the other
direction: the schema is fine and the new Worker is not, so you want the
previous build back.

**The harness cannot tell you whether that is safe, and does not pretend
to.** Reverting the Worker does not revert the database. The old code
meets whatever schema is applied now, and whether it copes depends
entirely on what the migrations since it did:

| What the migrations since that build did | Old code against the new schema |
|---|---|
| Added tables, added nullable columns | Fine. It ignores what it does not know about |
| Added a `NOT NULL` column with no default | **Breaks.** Its inserts omit a column the database now demands |
| Renamed or dropped anything | **Breaks.** It reads a name that is gone |
| Backfilled or reinterpreted an existing column | **Silently wrong.** It reads the column and means something else by it |

The additive rule (§1) is what makes the first row the usual case, which
is why rolling the code back usually works. It is not a guarantee, and a
count of migrations cannot become one: "three migrations have applied
since" says nothing about whether any of them was the second or fourth
row of that table.

**So the check is a reading, not a command.** Before reverting a build,
read the migrations applied since it and decide which row you are in.
`fz plan --json` reports `migrations.collected` per module, and the
deploy record beside the manifest holds the same map as it was at the
deployment you are going back to; the difference is the list to read.

### Why `fz` will not do this for you

`fz deploy` recomputes the plan from the current inputs and refuses any
digest that does not match (`stale-plan`), so an old plan cannot be
deployed through it at all. That is deliberate: an approval is of a
destination, and the destination moved.

Reverting the build is therefore a `wrangler` operation, outside `fz`,
and it stays outside on purpose. A `fz rollback` that answered "safe"
from migration counts would be giving an assurance the data does not
support — and an operator who trusts a false "safe" is worse off than one
who was told to read the migrations.

### Expand and contract

The way to make a rollback safe *in advance* is to never be in rows two
to four when it matters:

1. **Expand.** Add the new column or table, nullable, defaulted. Deploy
   code that writes both old and new.
2. **Backfill.** A forward migration, separately, reviewed.
3. **Switch.** Deploy code that reads the new shape. **This is the last
   point at which a rollback is free**, and it stays free for as long as
   the old column is still written.
4. **Contract.** Drop the old column, in its own migration, once no
   deployed build reads it. After this a rollback past step 3 is not
   available, and that is the trade you are accepting by contracting.

Schema and Worker activation are not atomic and cannot be made so: D1
applies migrations through `wrangler d1 migrations apply` and the Worker
goes live separately. Expand/contract is how that gap stops mattering.

## 6. Backup and retention requirements

Handed to whoever owns the databases; this document specifies, it does
not implement (#35 is explicit that implementing backups is out of
scope). Filed as **issue #203** so it has an owner and a ticket.

| Requirement | Why |
|---|---|
| PITR enabled on every tenant database, retention **≥ 30 days** | Matches D1's Time Travel window so both paths have the same floor and one runbook |
| A **nightly logical export** per tenant, retained 90 days | The only answer past the PITR window; `wrangler d1 export` / `pg_dump` |
| Exports stored outside the database's own account | A restore is not a backup if losing the account loses both |
| A **quarterly restore drill** on one tenant, timed and recorded | An untested backup is a hypothesis. #43's SOC 2 mapping cites the record |
| Export before any migration containing a backfill | §3: on D1 it is the only pre-image that will exist |

## 7. What has not been drilled

#35 asks for a restore drill executed on a staging tenant with its timing
recorded. **It has not been done**, and this document does not pretend
otherwise:

- There are no tenant databases. The multi-tenant native runtime is #32
  and is unbuilt; the Postgres halves above are written against ADR 0008's
  shape, not against something running.
- The D1 halves are executable today against a real database, and
  Runbook C is destructive, so drilling it means doing it to
  `cratefield-waitlist` or to a throwaway created for the purpose. A
  throwaway is the right answer and it is a person's decision, not this
  document's.

Every command above was checked to exist and to accept the flags shown
against wrangler 4. None was run. The acceptance criterion stays open
until someone drills it and writes the timing here.
