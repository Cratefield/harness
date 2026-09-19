# Published numbers, and the rules they follow

Issue #156. Cratefield's speed claims should rest on evidence someone else can
check, so this page publishes the harness with the number, and publishes what
has **not** been measured with the same prominence.

The rules, which are part of the deliverable:

- pin the harness commit;
- publish the script, not just the result;
- state the host, and the region where a network is involved;
- never mix warm and cold in one figure;
- report the sample count;
- compare to another vendor only with an identical harness, or not at all.

## The four numbers, and where they stand

| # | Number | Status |
| --: | :--- | :--- |
| 1 | Cold start to first byte against an evicted venture, split into wasm instantiate and first D1 query | **unmeasured** — needs a deployed venture |
| 2 | Warm authenticated read p99 at 50 rps, from the D1 primary's region and a distant one | **unmeasured** — needs a deployed venture in two regions |
| 3 | Per-tenant write ceiling: single-row insert with the audit chain on | **measured**, below |
| 4 | Provisioning time for a config change and for a new venture, p50 and p99 | **unmeasured** end-to-end — needs a deploy pipeline (#141); the artifact step alone is measured, in `docs/control-plane/LINKER.md` |

Three of four are unmeasured because there is nowhere to run them: no venture
is deployed. They are not estimated here. A page of numbers where three are
guesses is worse than a page with one that is not, and the guesses would be
the ones quoted.

## 3. Per-tenant write ceiling

`bench/write-ceiling` — single-row secret writes through `SecretStore`, each
appending to the hash-chained audit log in the same database. The chain is why
this number is interesting: every write reads the previous row's hash, so
writes serialise and the ceiling is really the rate at which the chain
extends.

```
cargo run -p cratefield-bench-write-ceiling --release -- 2000
```

Host: Mac16,5, 14 cores, rustc 1.98.1, SQLite in memory. Four runs of 2000
samples, warm-up write excluded. The load average at the time of each run is
in the table because it matters:

| Run | Load | Throughput | p50 | p99 | max |
| --: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5.8 | 41 577 writes/s | 23.4 µs | 30.3 µs | 38.4 µs |
| 2 | 5.8 | 39 359 writes/s | 23.1 µs | 40.9 µs | 159.5 µs |
| 3 | 5.8 | 42 514 writes/s | 22.9 µs | 30.8 µs | 109.6 µs |
| 4 | 6.8 | 41 889 writes/s | 22.8 µs | 65.1 µs | 117.3 µs |

Run 4 is the point of publishing the load: a machine one point busier moved
p99 by a factor of two while p50 and throughput barely shifted. A p99 quoted
without the host's state is not a number.

**What this number is not.** It is an in-memory SQLite floor on one machine:
no network, no D1, no disk. A deployment writing to D1 from a Worker will be
slower by orders of magnitude, and that figure is number 1's and number 2's
business, not this one's. Quoting 40 000 writes/s as a product claim would be
exactly the favourable-number problem this page exists to avoid.

What it does establish: the audit chain is **not** the bottleneck anyone
feared. Hashing the previous row and appending costs ~23 µs at p50, so a
tenant hitting a write ceiling in production is hitting the database or the
network, not the chain.

## Reproducing

The harness is in this repository and the command is above. To compare
machines, state yours and its load — run 4 above, and the idle/loaded split in
`docs/control-plane/LINKER.md`, are both what happens when you do not.
