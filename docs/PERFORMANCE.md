# The performance programme, and the measurement that admits each step

Issue #158. Performance work in this repository is gated, not planned. The
programme's rule is that a change is admitted only when a published number
shows the cost it removes, and kept only when the number moves. The failure
it prevents is the ordinary one: optimising what is easy to change rather
than what is slow, and calling the difference a win.

The numbers themselves live in `docs/BENCHMARKS.md`, and the rules for
producing them live there too — pin the harness commit, publish the script,
state the host and the region, never mix warm and cold in one figure. That
page is the prerequisite for this one, and its rules are not repeated here,
because a rule written in two places is two rules waiting to disagree. This
page is what the numbers gate, and in what order.

## The gate

- A step names the benchmark that admits it before any code is written.
  No number, no step.
- A step that ships without its number measured is a guess. The commit
  message does not change what it is.
- If the number does not move after the change, the change is reverted. It
  is not kept on the argument that it should have helped — that argument is
  the guess again, asking to be kept anyway.
- Re-measure on the same harness commit, and state the host and the region
  where a network is involved, as `docs/BENCHMARKS.md` already requires of
  any figure it publishes.

## The four steps

The benchmarks are named the way `docs/BENCHMARKS.md` numbers them.

### 1. Region-pin the venture's primary D1 near its users

Gated on number 2, the warm authenticated read measured from the D1
primary's region and from a distant one. The gap between the two figures is
the quantity pinning removes — it is not evidence for the step, it *is* the
step — and until it is measured there is no case, only a plausible one.

`examples/venture/wrangler.toml` declares no location hint today. The
compliance half of the choice is already scoped elsewhere: ROADMAP entry B9
(`docs/control-plane/ROADMAP.md`) passes a region through as the D1 location
hint, records what was actually granted rather than what was asked for, and
says outright that the latency half belongs to this programme. So the field
may already exist by the time this step runs. The step is choosing the
field's value from where the venture's users are, not adding the field.

Reversible by construction: re-provisioning moves the database, and nothing
on the read path changes at all. That is why this step goes first — the
cheapest and most reversible commitment on the list.

### 2. Serve immutable reads from KV or the Cache API

Gated on number 2 again, plus a figure that does not exist yet: the share of
a venture's reads that are actually immutable. That share is the gate, not
decoration. The read benchmark alone says the reads are slow; it says
nothing about whether any of them can be served twice from one answer.

The machinery already exists, in two forms. The `KeyValue` port is in
`crates/core/src/ports/kv.rs`, with a Workers KV adapter in the Cloudflare
runtime and a Redis adapter on the native one — a KV-fronted read is a
routing decision, not a new port, and
`crates/module-changelog/src/cache.rs` is the in-repo precedent: a
KeyValue-backed response cache whose entries die the moment a refresh
publishes a new generation, and by one TTL when that publish fails. The
Cache API is the other form: per-colo and needing no binding, so the
nothing-to-route-to objection does not reach it — but there is no
generation to publish either, only TTL and per-colo purge, and which form
fits is decided by the staleness budget the immutable-share measurement
forces into the open. The example venture declares no KV namespace binding
today, which is the honest state: until the immutable share is measured
there is nothing to route to.

The failure mode is stated before any code: a cache in front of a read path
that is mostly not cacheable buys a consistency problem and nothing else.
This step fails when the hit rate is low enough that the p99 does not move.

### 3. Durable Object warmers where cold start is shown to matter

Gated on number 1, the cold start to first byte against an evicted venture,
split into wasm instantiate and first D1 query. The split is what makes the
gate decidable, because a warmer addresses only one half of it: the D1 wake.
D1 sits on a Durable Object, so an idle venture pays a wake on its first
query. A warmer aimed at that Object removes the wake; it removes
instantiate only by firing often enough that nothing is ever evicted, in
which case there is no cold start left for the split to measure.

So the entry condition is not "cold start is slow". It is "the split
attributes the cost to the wake rather than to instantiate". A warmer
against an instantiate-dominated cold start is a standing bill for nothing,
and only the split can tell the two apart.

The bill is standing in the other sense too: a warmer costs money
continuously while its benefit is intermittent — paid every idle minute to
save the first request after the idleness. This is the one step whose cost
must be published next to the latency won, in the same figure, or not
shipped at all.

### 4. D1 read replication through the Sessions API — last, on purpose

The entry condition is the conjunction: steps 1 and 2 shipped, re-measured
on the same harness commit, and the distance cost still present. That is,
the venture genuinely has users far from any single primary *after* the two
changes that remove distance cheaply have had their turn. A residual cost
that is volume at the primary rather than distance does not open this
gate: step 2 has already moved the immutable share of that volume off the
primary, and the designed answers to per-venture scale are harness#23's
per-tenant databases and the Postgres promotion path of ROADMAP entry A6.

The reasoning is ADR 0019's and is not restated here — a rule written in
two places is two rules waiting to disagree, which is what this page
already says of `docs/BENCHMARKS.md`'s rules. What remains operational is
the failure condition, and it has two forms: the distance figure never
appears after steps 1 and 2, in which case the step is dead rather than
deferred; or the step ships, the far-region read does not move, and the
gate reverts it like any other.

## Where the programme stands

Whether each number exists is `docs/BENCHMARKS.md`'s to own, and this page
does not restate it — that line drifts, and a second copy would drift with
it. What this page owns: the gates of the first three steps read those
numbers, and step 2 reads one figure more, an immutable-read share nothing
yet exists to count. So the programme's first task is not a performance
change at all. It is what the numbers wait on: a deployed venture and, for
the provisioning figure, a deploy pipeline.

Nothing in this programme ships until then. The order is recorded, the
gates are named, and every one of them is shut.

A sequence whose first three gates are unmeasured is a plan, not a
programme. This page intends to become the other thing.
