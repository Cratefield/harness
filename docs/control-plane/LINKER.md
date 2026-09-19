# The artifact linker: composing a venture without cargo (issue #159)

## What the two dependencies already give

**#59 — artifact identity.** `cratefield_manifest::build_key` computes the
content address of a composition: `sha256` over the sorted
`(slug, exact version, release digest)` list plus `harness_api`, the rustc
version and the profile. Its wire form is pinned by a golden test. Deliberate
exclusions — venture name, host, config, seed data, sidecar mounts — are
exactly what makes a *configuration-only change* a non-event for the artifact:
the key does not move, so the cached artifact is still correct. What #59 does
**not** provide is any store: where artifacts physically live and the hit/miss
paths were left as control-plane decisions.

**#139 — the reviewed catalog.** `Catalog::resolve` turns a selection into a
`ModuleSet` whose every entry is a pinned, reviewed `PinnedRelease`: an exact
`N.N.N` version plus a `sha256:` digest, with revoked and unpinned releases
refused at resolution. The published `CATALOG.json` carries the same pins and
is drift-checked against the crates in CI.

**Still missing, which #159 asks for:**

1. The per-module precompiled artifacts themselves. No module has a published
   release digest today — every pin in `CATALOG.json` carries the placeholder
   `sha256:000…0`. Until real releases are cut and digested, any linker runs
   on synthetic segments; that is a release-process gap, not a code gap.
2. A physical home for per-module segments and composed bundles. Still a
   control-plane decision (unchanged from #59). The linker defines the *ports*
   it needs — `PinSource`, `SegmentSource`, `ComposedStore` — and ships
   in-memory implementations for tests; those ports now have a caller, since
   provisioning's artifact step goes through them (see the wiring below).
   What nobody has built is the physical thing: where a published release is
   uploaded as a segment, and where a composed bundle persists between runs.

The third thing #159 asked for — the composition step itself, turning
per-module segments into one venture artifact deterministically without
invoking cargo — is no longer missing. It is the linker, and it is wired into
provisioning's artifact step, not just callable as a library.

## What the linker is — and is not

The linker composes a **venture artifact bundle**: a canonical header (the
sorted pins, the build-key inputs) followed by the per-module segments in slug
order, digest-verified against the catalog pins before use. The composed
bundle is stored under the #59 `build_key` of the set, so:

- a **configuration-only change** computes the same key, finds the cache hit,
  and never touches a segment or a compiler;
- two ventures on the same module set share the bundle, which is safe for the
  reasons `docs/ARTIFACT-CACHE.md` already states (stateless Worker, per-
  customer database/secrets/mounts);
- a segment whose bytes do not hash to its pinned digest is refused by name.

It is **not** a wasm-level link. Producing per-module wasm objects and linking
them (wasm-bindgen, wasm-opt) is toolchain work and the produced bundle is a
composition artifact, not a deployable `.wasm` — the runtime consumer of the
bundle is future work. The linker also does not decide where the store lives.

## The wiring: provisioning's artifact step runs through it

The linker is no longer only a library. `LinkedArtifacts` is a `Deployer`
implementation whose `build_artifact` — the artifact step of provisioning's
seven-step port — resolves the venture's module-set key through a
`PinSource` and composes the set when it can. The control plane passes it to
the provisioning engine at every provisioning call site
(`deployer::current()` in `crates/control-plane-dashboard`), so — once
segments are published and a real store is wired, neither of which holds
today ("What is still placeholder" below) — a set whose segments exist is
composed and never compiled, and a configuration-only change is a store hit
that never fetches a segment. The other six steps
delegate verbatim to the deployer underneath; this adapter exists for one
step and does not pretend otherwise.

**The fallback ladder.** The linker is an optimisation on the build path, so
it must never turn a set the build path could handle into a failed deploy.
Four things fall back to the inner build path, carrying the reason with
them: the pin source cannot pin the set (it does not resolve against the
control plane's catalog copy); a pin is still the all-zero placeholder
digest (no release has been stamped); the release is pinned but its
precompiled segment is not published; and a store *errors* — which is the
missing segment's situation reached from the other side, a store with no
answer at all instead of one that honestly answers no — so a store outage
degrades to a build rather than failing the deploy. The reason is recorded
in the provisioning ledger, where the operator reads it. This is the row a
real provisioning run records today, verbatim, from the dashboard test
`a_provisioning_run_records_the_linker_s_reason_and_the_unwired_build_path`:

```
artifact: `cms` release `0.1.1` is pinned to the all-zero placeholder digest the catalog ships until release stamping, so the artifact still needs a build. no deployer is wired: building the composed artifact needs an adapter that talks to Cloudflare, and the control plane has none yet. Nothing was changed.
```

Both halves are deliberate: why the linker could not compose, and what the
build path behind it then said. Either half alone would read as the whole
answer.

**What does not fall back.** A segment whose bytes fail their pinned digest,
and a cache hit whose bytes fail their recorded composition digest, are
refused outright — the deploy stops with the reason, and no build is
substituted. Both failures mean a store handed out bytes that are not what
they were pinned or recorded under; falling back to a build there would
paper over a store handing out the wrong bytes, and the build's bytes would
pass as someone's venture. So would a build key that will not compute
(`LinkError::Key`, a duplicate slug): the set is malformed, and building it
would be equally wrong. Those are the only refusals. A store that *errors*
is deliberately not one of them — it gave no answer at all, so it takes the
same rung as a missing segment and falls back with its message attached;
refusing would convert the optimisation's outage into a failed deploy.

**What is still placeholder.** The control plane passes `UnpublishedSegments`
— nothing has a stamped release digest, so there are no bytes to fetch — and
`NoStore` — composed bundles have no durable home, a #141 decision still
open. Together that means **every real set falls back to the build path
today**. The wiring is live; the segments are not. What runs on every
provisioning run now is the resolution-and-refusal path measured below, in
microseconds; what will run the day segments are published is the compose
path, also measured below.

## Numbers

Measured 2026-09-13 on this machine (Apple Silicon Mac, rustc 1.98.1,
harness at the `fix/issue-159` commit that introduced
`cratefield-linker`), `cargo test --release`, toolchain pinned to
`1.98.1-aarch64-apple-darwin`. The workload is the synthetic six-module
set from `crates/control-plane-linker/tests` — six segments of 4 KiB
deterministic pseudorandom bytes (24 KiB total) — because no real
digested releases exist yet. The linker's cost is dominated by hashing
those bytes, so these are a floor, not a scaling statement: nothing
larger has been measured.

| Path | Idle machine | Loaded machine |
| :--- | ---: | ---: |
| Cache hit (config-only change): key lookup + digest check | **28–35 µs** | **152–155 µs** |
| Compose six segments, cold (24 KiB) | **96–145 µs** | **327–367 µs** |

Both include the sha256 of every segment and of the bundle. Three runs per
column. The second column is the same test on the same machine while it was
running several other builds (load average ≈ 18), and it is there because a
single set of numbers with no stated conditions is not reproducible: a reader
who runs this on a busy machine and measures three times the published figure
has no way to tell whether the number was wrong or their machine was. Both
columns are microseconds, which is the claim that matters; contention moves
the constant, not the order of magnitude.

### Through the provisioning port, on a different host (2026-09-19)

Measured for this issue, 2026-09-19, at harness commit `bdf4e49` plus the
change this document describes (the wiring and the sampling below were
uncommitted in the working tree when measured). Host: a Linux microVM
container (`node:24-bookworm`), CPU `AMD EPYC`, 4 cores, rustc 1.98.1
(`x86_64-unknown-linux-gnu`) — **not** the Apple Silicon Mac above, so the
two tables are not one measurement and must not be read as one. **Release
mode** (`--release`), which is the only mode any figure in this document is
published in. The command:

```
cargo test -p cratefield-linker --release measured_ -- --nocapture --test-threads=1
```

No figure below is a single sample. Each path is timed 100 times (cold
compose; a fresh store per sample, so every sample really is cold) or 200
times (cache hit, placeholder fallback), after one untimed warm-up call,
and the test prints min / p50 / p99 / max with the sample count — the
reporting rules are `docs/BENCHMARKS.md`'s, which require the sample count.
The whole command ran three times on an otherwise idle machine; the 1-minute
load average in the table is from `/proc/loadavg` at each run (the
container's ambient level — the host runs other tenants, which is exactly
why the load is published). Same workload as the table above: six synthetic
segments of 4 KiB (24 KiB total), bundle 25 474 bytes. Every figure is the
test's printed value, verbatim — no averaging:

| Path | Run | Load | min | p50 | p99 | max |
| :--- | --: | ---: | ---: | ---: | ---: | ---: |
| Bare `link()`: cold compose, 24 KiB (n=100) | 1 | 0.26 | 31.86 µs | 32.22 µs | 53.53 µs | 61.02 µs |
| Bare `link()`: cold compose, 24 KiB (n=100) | 2 | 0.20 | 30.62 µs | 30.81 µs | 69.52 µs | 80.94 µs |
| Bare `link()`: cold compose, 24 KiB (n=100) | 3 | 0.20 | 30.67 µs | 30.90 µs | 58.11 µs | 70.03 µs |
| Bare `link()`: cache hit (n=200) | 1 | 0.26 | 15.26 µs | 15.53 µs | 33.39 µs | 53.28 µs |
| Bare `link()`: cache hit (n=200) | 2 | 0.20 | 14.70 µs | 14.88 µs | 22.41 µs | 30.99 µs |
| Bare `link()`: cache hit (n=200) | 3 | 0.20 | 14.70 µs | 14.87 µs | 22.31 µs | 46.47 µs |
| Through the port: cold compose (n=100) | 1 | 0.26 | 35.29 µs | 35.81 µs | 53.05 µs | 54.00 µs |
| Through the port: cold compose (n=100) | 2 | 0.20 | 33.98 µs | 34.61 µs | 67.10 µs | 77.88 µs |
| Through the port: cold compose (n=100) | 3 | 0.20 | 36.00 µs | 36.66 µs | 76.84 µs | 80.48 µs |
| Through the port: cache hit (n=200) | 1 | 0.26 | 18.70 µs | 18.98 µs | 31.51 µs | 36.69 µs |
| Through the port: cache hit (n=200) | 2 | 0.20 | 17.94 µs | 18.25 µs | 32.28 µs | 44.16 µs |
| Through the port: cache hit (n=200) | 3 | 0.20 | 18.99 µs | 19.41 µs | 32.76 µs | 35.83 µs |
| Placeholder-pin fallback to the build path (n=200) | 1 | 0.26 | 1.94 µs | 2.22 µs | 2.64 µs | 3.63 µs |
| Placeholder-pin fallback to the build path (n=200) | 2 | 0.20 | 1.38 µs | 1.45 µs | 1.76 µs | 2.65 µs |
| Placeholder-pin fallback to the build path (n=200) | 3 | 0.20 | 1.39 µs | 1.46 µs | 1.86 µs | 2.77 µs |

The first four paths are the same two paths as the Mac table, measured twice
each: once as the bare `link()` call, once through `LinkedArtifacts` — where
provisioning actually calls it. An earlier version of this table published
one sample per cell, read the port's cold figures (77–120 µs there) sitting
above the bare call's (42–58 µs) as the price of the port re-resolving the
module-set key against the catalog, and that attribution was not supported
by its own numbers: the hit path pays the same resolution yet sat on top of
the bare hit, the placeholder row bounded resolution at single-digit
microseconds, and a fluctuating 20–60 µs delta cannot be pinned on a
µs-scale cause at one sample per cell. With distributions, the reading is
plainer:

- **Resolution is bounded directly, and it is single-digit.** The
  placeholder row — resolution, the placeholder check, reason formatting and
  the handoff to the inner deployer, which is the path every real set takes
  today — is 1.4–2.2 µs at p50, and its set is smaller than the measured
  six-module one.
- **The port's whole premium is a few microseconds, on both paths.** At p50
  the port runs 3.6–5.8 µs above the bare call on the cold compose and
  3.4–4.5 µs above it on the hit, stable in sign across all three runs —
  larger than the run-to-run spread of the p50s themselves (0.7–2 µs across
  these runs), so it is a real cost and not noise. It does not scale with
  the workload — it is the same on the hit path, which fetches and hashes
  nothing, as on the cold path, which hashes 24 KiB — which is the shape of
  a fixed per-call cost, and the one fixed per-call cost the port adds is
  the `PinSource::pins` resolution the bare call skips: the price of taking
  the set as the content key the control plane carries instead of a
  resolved `ModuleSet`. The data supports that attribution and no larger
  one; a few µs is not 20–60.
- **A one-sample table could show a gap several times the real one.** The
  p99s of a single run reach 53–77 µs, so a lone sample landing on a tail
  reproduces the old 77–120 µs figures without any cause behind them.

The placeholder row is the path the control plane actually takes today: a
set whose pins are the catalog's all-zero placeholders, which the adapter
refuses to link and hands to the build path with the reason attached (the
recorded reason is 307 bytes). The inner deployer there is the test's
refusing fake, so this is the linker's half of the fallback, not the ledger
write after it.

Against the issue's targets, honestly:

- **"Configuration change live in under 10 s."** The artifact step of that
  path is now measured **through the provisioning port** — where the control
  plane actually calls it, not only as a library call: once segments are
  published and a real store is wired (neither of which holds today), a
  configuration-only change through `LinkedArtifacts` is a store hit, and on
  the host above that costs 18.3–19.4 µs at p50 — five orders of magnitude
  inside the target. That is still only the artifact step of "live". The
  rest of it — deploying the Worker, applying schema, binding the route, the
  health check — is the other `Deployer` steps, and no adapter that talks to
  Cloudflare exists yet (#141), so the end-to-end number for this target
  remains unmeasured and no part of this document claims the target is met.
- **"A new venture live in under 60 s."** Still unmeasured, plainly. The
  compose step through the port is 34.6–36.7 µs at p50 cold on the host
  above, but the dominant cost of a *new* module set is producing the
  segments in the first place — and per `docs/BUILD-COST.md` (issue #58's
  measurements) that is 26.7 s cold or 5.3 s warm per module-set change,
  most of it wasm-bindgen/wasm-opt. Until release digests are stamped, every
  new venture pays that build, so the linker does not yet remove it in
  production — the control plane's own provisioning runs fall back to the
  build path on every real set today (the placeholder row above). **The 60 s
  end-to-end target is unmeasured**: no deploy pipeline exists to run it
  against, and this document will not publish a number for a path nobody has
  executed.

The measured claim this crate stands behind: resolution and composition now
sit on provisioning's artifact path, do not go through cargo, and cost
microseconds, not seconds — the compile is what they avoid. Neither target
is claimed as met; both still wait on the deploy pipeline that does not
exist.
