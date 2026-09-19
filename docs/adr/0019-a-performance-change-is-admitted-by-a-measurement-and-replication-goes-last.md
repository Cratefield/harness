# ADR 0019: A performance change is admitted by a measurement, and replication goes last

Status: accepted, 2026-09-19. Issue #158, filed from the roadmap (appendix
entry A7). Sequenced behind the benchmarks of #156.

## Context

The roadmap filed the performance programme (#158) with an order already in
it, and an external assessment of cratefield.com had filed its own: read
replication first. The assessment was not careless. It was reasoning about
a different database, and the difference between the two databases is most
of this decision.

**Nothing measured stands behind the performance work yet.**
`docs/BENCHMARKS.md` publishes four numbers, and one of them is measured.
The write ceiling came out of `bench/write-ceiling`; the cold-start split
and the near/far warm read need a deployed venture — the near/far pair one
deployed in two regions — and the provisioning times need the deploy
pipeline of harness#141. None of that exists. The first three steps gate
on numbers 1 and 2, and step 2 gates on one figure more: the
share of a venture's reads that are immutable, which is not one of the
four and is not produced by a deployment either. That is why the
programme's first deliverable is a measurement and not a change.

**The harness's shape is one small database per venture.** ADR 0003 gives
each venture its own Worker and its own D1, and ADR 0008 carries the same
isolation onto the native runtime. The isolation that holds today is
between ventures: the read volume at a primary is one venture's traffic,
not the platform's, because there is no platform-sized database for read
volume to pile up against. Tenants within a venture do share its one
database — per-tenant databases arrive with harness#23, which is designed
today, not shipping — so a venture's own tenants' reads are exactly what
can bottleneck it. What no venture's primary answers is another venture's
reads.

**The assessment ranked replication first anyway.** For a single large
shared database that is the right answer, and section 6 of
`docs/control-plane/ROADMAP.md` records where that reasoning lands here:
pinning the primary's region and batching reads beat replication, so
replication goes last. Batching is not one of this programme's steps — it
is Tables scope, the batched endpoint of roadmap entry A1 that runs
several declared reads in one request — and this ADR orders only the four
steps that are. What the roadmap asserted, this ADR decides — and decides
with a gate, so that the order is enforceable rather than a matter of
taste.

## Decision

**A change is admitted by a number, not by an argument.** Each step names
the benchmark that admits it before any code is written, re-measures on the
same harness commit with the host and region stated, and is reverted when
the number does not move. "It should have helped" is not a measurement, and
a change kept on it is a guess that has learned nothing. The publishing
rules themselves are `docs/BENCHMARKS.md`'s; this ADR only makes them a
gate.

**The order is pinning, then immutable reads, then warmers, then
replication.** Ordered by architectural commitment, cheapest and most
reversible first — the costs are what the programme exists to measure, so
before them, commitment is the only axis an order can honestly be written
on. Pinning is a provisioning-time field; immutable reads route
existing machinery — the `KeyValue` port already exists on both runtimes —
in front of a read path; warmers spend money continuously for an
intermittent win; replication touches every read path and adds a
correctness surface. The further down the order a step sits, the more of
the architecture it commits.

**Replication goes last because the assessment that ranked it first was
reasoning about a different database.** A single large shared database is
bottlenecked by read volume at its primary, and replicas are how that
volume fans out; on that shape, the assessment's ranking is the correct
one. The harness's shape is one small database per venture, so the read
volume at a primary is one venture's, not the platform's. The
platform-sized volume replicas fan out is not in the picture, because
no primary on this shape answers another venture's reads; the cost that
is — round-trip distance to the primary — pinning removes directly, and
a replica does
nothing for writes, while the one number this repository has actually
measured is a write ceiling. Replication is also the one step that changes
every read path: the Sessions API's bookmark handling — Cloudflare's
contract, and one this repository has never exercised — is a real
read-your-writes surface, a correctness obligation carried in every read
rather than a choice made once at provisioning. Pinning is reversed by
re-provisioning; replication is paid
for on every request. Adopting the per-request cost before the distance is
measured is the exact optimise-what-is-easy-to-change failure this
programme exists to prevent, committed in the name of performance.

**The programme is written down separately.** `docs/PERFORMANCE.md` carries
the four steps, the benchmark that gates each one, the entry conditions and
the failure conditions. This ADR records the decision and the order; the
page is where the programme's standing is kept current as numbers arrive.
Decisions do not drift with measurements, so the two live apart.

## Rejected

**1. Replication first, as the external assessment ranked it.** The honest
alternative, and correct about the database it was reasoning about. It
loses here because it pays a per-request complexity across every read path
before the number that would justify it exists, and because the two steps
ahead of it remove the same cost — distance — for less commitment. If, once
pinning and immutable reads are measured, the distance cost is still there,
replication's gate opens on its own; the order is a sequence, not a
verdict.

**2. All four steps at once.** One release carrying pinning, caching,
warmers and replication. It loses because four changes landing together
leave no number attributable to any of them: the read benchmark could not
say what moved or why, and a gate that cannot attribute cannot revert. The
order exists so that each measurement belongs to one change.

**3. Shipping the pinning step now, on the intuition that nearer is
faster.** Nearer is certainly faster, and it loses anyway. The near/far gap
in benchmark 2 is the quantity pinning removes, and shipping before it is
measured means the step can never be checked against its own justification
— the number moves or it does not, and without the before-figure nobody can
say which. It also inverts the roadmap's split: the region field is B9's,
and building a second way to set it is two fields answering one question.

**4. Setting latency targets for the four steps now.** `docs/BENCHMARKS.md`
refuses to estimate the numbers it has not measured, and it is right to: a
target invented before a measurement is the same guess wearing a number,
and a published target is precisely the figure that gets quoted. The
latency targets this programme will hold are the ones its benchmarks
produce, after they have produced them. The rejection does not reach the
roadmap's provisioning targets: A3's ten and sixty seconds are durations on
a build pipeline, not read-path figures, and that entry publishes the real
numbers if the targets miss.

## Consequences

- Nothing ships here. This ADR records an order and a gate; the changes it
  orders are built, measured and reverted separately, each under
  `docs/PERFORMANCE.md`.
- The programme is blocked on measurement. Of the three unmeasured
  benchmarks, two need a deployed venture — the near/far pair one deployed
  in two regions — and the provisioning times need a deploy pipeline
  (harness#141); step 2 also gates on an immutable-read share that is not
  one of the four numbers at all. The first three steps gate on those two
  and on the share, so the first task is a measurement, and no step ships
  before its numbers exist.
- B9's region field and this programme's step 1 must agree on one field.
  The control plane chooses, records and shows the region; the harness
  programme chooses its value from where the venture's users are. Two
  fields for one fact would let the compliance answer and the latency
  answer disagree about where a venture's data lives.
- The write ceiling is unaffected by any of this. None of the four steps
  touches the audit chain, and the one measured number stays measured.

## References

Issue #158; issue #156 (the benchmarks this programme gates on);
`docs/BENCHMARKS.md`; `docs/PERFORMANCE.md`;
`docs/control-plane/ROADMAP.md` (appendix entry A7 files the programme,
section 6 records where the assessment is off, B9 scopes the compliance
half of region selection, A1 the batched reads the remedy also cites);
ADR 0003 (compile-time composition, one Worker
per venture); ADR 0008 (the native runtime serves many tenants, one
database each).
