# What a build actually costs

Measured for issue #58, 2026-09-06. The question behind it: does a managed
control plane have to avoid compiling per customer? The answer is no.

Host: Mac16,5, 14 cores, rustc 1.98.1, `examples/venture` (core, Cloudflare
runtime, Resend adapter, `email-signup`, `waitlist`, one sample module).

| Case | Wall clock | wasm |
| :--- | ---: | ---: |
| Cold, no cache at all | 26.7 s | 2.66 MB |
| Warm, nothing changed | 3.2 s | 2.66 MB |
| Warm, composition file touched (a module toggled) | 4.2 s | 2.66 MB |
| **Warm, one new module crate added** | **5.3 s** | 2.69 MB |
| Warm, `codegen-units = 16` + `opt-level = "s"` | 17.3 s † | 1.86 MB |

† Confounded, and not comparable to the rows above. Changing a profile
invalidates every artifact, so this number contains a full recompile caused by
the measurement itself. The useful figure in that row is the **size**:
`opt-level = "s"` takes 2.66 MB down to 1.86 MB, a 30% cut. Re-measure the time
on a second run before drawing any conclusion about it.

## The finding

**Adding one module to a warm build costs about five seconds.** A cold build,
with nothing cached at all, is under thirty. Compilation is not a reason to
avoid anything.

**Post-processing dominates, not cargo.** With a warm cache, `cargo build
--release --target wasm32-unknown-unknown` is 1.0 s unchanged and 1.3 s with a
new module crate. The rest of the 4.2 s and 5.3 s is `wasm-bindgen` plus
`wasm-opt` inside `worker-build`, and neither benefits from cargo caching. Any
future effort to make builds faster belongs there, not in the compiler.

## What this means for the epic (#56)

- **#59, caching the artifact on the module set, is an optimisation and not a
  prerequisite.** It saves seconds, not minutes. Build it when there is a
  measured reason, not on principle. The reason to key artifacts on the module
  set instead of the customer remains good design; it is no longer urgent.
- **Sidecar modules (#60 and after) are justified by confidentiality alone.**
  "It avoids a rebuild" is not an argument worth making at five seconds, and no
  documentation or site copy should make it. The argument is that a customer can
  run a module we never see.
- The 1 s startup budget is not at risk: 2.66 MB parses well inside it, and
  `opt-level = "s"` is in reserve if a large module set ever pushes on it.

## Recipe

Reproduce with a throwaway module crate, so the measurement is "one more
module" and not "one more line":

1. `crates/module-spike-probe/` — a crate implementing `Module` with `requires()`
   empty, `Migrations::EMPTY`, and a router with one `GET /ping`. Nothing else;
   the point is to measure linking a crate, not compiling a feature.
2. `cargo clean`, then `worker-build --release` in `examples/venture` for the
   cold row.
3. Re-run untouched for the warm row; `touch src/lib.rs` for the toggle row.
4. Add the probe crate as a path dependency and `.module(SpikeProbe::new())` to
   the composition for the new-module row.
5. Time `cargo build --release --target wasm32-unknown-unknown -p venture`
   separately to split compilation from `wasm-bindgen` and `wasm-opt`.

Use the rustup toolchain explicitly (`~/.cargo/bin/cargo`). A Homebrew rustc on
`PATH` shadows it and is too old for this workspace's edition.
