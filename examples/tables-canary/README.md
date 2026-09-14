# tables-canary

**Generated. Do not edit by hand.**

A venture produced by the harness's own generator from
[`venture.json`](venture.json), committed so that CI compiles and composes
it.

## Why it exists

Nothing compiled a generated venture. `examples/venture` next door is
hand-written, so the generator could emit source that does not build —
and did emit source that builds and then panics at boot: a module
requiring `Port::Auth` beside a runtime that provided none (#371), and a
manifest with no CORS origin, which the harness refuses and the manifest
did not.

Both were found by composing this crate. Neither was reachable by any
test over generated *text*.

## The three legs

| leg | what it catches |
|---|---|
| a workspace member | generated source that does not compile |
| `tests/boots.rs` | a composition the harness refuses |
| `crates/manifest/tests/canary_is_current.rs` | a committed copy that has drifted from the generator |

The drift test runs the generator's output through `rustfmt` before
comparing, because this crate is a workspace member and `cargo fmt --all`
formats it. Without that the comparison fails on rewrapping nobody did —
and hand-matching rustfmt inside the generator's string literals was
wrong three times in a row before this was written.

The third matters as much as the others: a stale canary keeps compiling
and keeps booting while the real output does neither.

## Regenerating

```
cargo run -p cratefield-manifest --example write-venture -- \
    examples/tables-canary/venture.json examples/tables-canary
```

`tests/` and this README are not generated and are left alone.

## What it declares

Two tables, on purpose one of each kind: `note` is `owner` — every row
belongs to the caller named in its `author` column — and `tier` is
`public-read` reference data holding nobody. A canary whose tables were
all public would compile and boot without ever exercising the verifier
wiring, which is the part that was broken.
