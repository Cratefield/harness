# ADR 0102: The crypto crate is RustCrypto's `chacha20poly1305`

Status: accepted, 2026-09-06

## Context

Issue #38: the secrets design (#37) needs one AEAD implementation to trust
for years, usable behind the future port (#40). Candidates named:
`aws-lc-rs`, `ring`, the RustCrypto AEADs (`chacha20poly1305`,
`aes-gcm`) — and `age`, expected to be eliminated. The spike
(`spikes/crypto/`, this PR) implements the design's encrypt/decrypt path —
envelope wrap/unwrap, AAD context binding, DEK cache with zeroisation —
against each candidate and scores them.

One criterion is decisive, as it was in the auth spike (ADR 0006's pure
Rust choice): **the AEAD layer must build for `wasm32-unknown-unknown`**.
Not because the native-only stores ship to wasm (ADR 0008) — because the
primitive is shared code that must stay out of the native-only ghetto, or
every future consumer either drags a C toolchain into the wasm graph or
forks the primitive. `factory0-core`'s dependency boundary forbids C
toolchains outright.

## Decision

**XChaCha20-Poly1305 via RustCrypto `chacha20poly1305` (0.11, `alloc` +
`zeroize` features), with a fresh random 24-byte nonce per encryption.**
`zeroize` keys on drop. DEKs are 256-bit, from the OS RNG, wrapped under
the KMS KEK; the AAD is the design's context binding
(`docs/SECRETS-DESIGN.md` §5).

If a contractual FIPS requirement ever lands, the same port seam takes an
`aws-lc-rs` AES-256-GCM backend on the **native runtime only**, with the
design's fallback nonce policy (12 random bytes, ≤ 2²⁰ encryptions per
DEK, §4). The cipher is pinned per key id, so a backend swap is a DEK
rotation, never a mixed-cipher store.

**`age` is eliminated** — it is a file-encryption format built on X25519
recipients with no caller-supplied AAD, so it cannot bind a ciphertext to
its store, name, version and key id; the spike demonstrates decryption
succeeding under a swapped context (`age_tests`), which is the exact
control the design requires and age cannot provide.

## Scoring

All commands run on this branch, macOS aarch64, Rust 1.98.1. Full
transcript in `spikes/crypto/README.md` and PROGRESS.md.

| Criterion | `aws-lc-rs` 1.18.1 | `ring` 0.17.14 | RustCrypto 0.11 | `age` 0.11.5 |
|---|---|---|---|---|
| **wasm32-unknown-unknown** (decisive) | **fails** — aws-lc-sys compiles C for the target | **builds*** | **builds** | builds |
| AEAD-with-AAD API | clean (ring-style) | clean (ring-style) | clean (`Payload { msg, aad }`) | **no AAD parameter exists** |
| Algorithms exposed | AES-256-GCM, ChaCha20-Poly1305 | AES-256-GCM, ChaCha20-Poly1305 | **XChaCha20-Poly1305**, AES-256-GCM, ChaCha20-Poly1305 | format, not primitive |
| Key zeroisation | internal best-effort, not caller-visible | **none** (no `zeroize` dep; maintainer rejects Drop-based zeroisation, issues #15/#566) | **`zeroize` feature, keys zeroise on drop** | internal only |
| Build complexity | aws-lc-sys: C/C++ compiler (cmake for FIPS builds) | C compiler; on macOS a clang with a wasm backend (Apple clang has none) | **pure Rust, nothing else** | pure Rust |
| FIPS | **yes** — `fips` feature → aws-lc-fips-sys, FIPS 140-3 L1 certs #5298/#5314 (v3.1; the 4.x module current builds bind is still in NIST review) | no | no | no |
| Audit history | no published third-party audit; formal verification (aws-lc-verification, SAW/Coq in CI) + FIPS lab validation | Cure53 2020 audit of ring-core as part of the rustls audit (0.16-era code) | NCC Group 2019 implementation review of aes-gcm + chacha20poly1305 (0.3.x-era; no significant findings) | audited for rage's use, moot here |
| Maintenance | AWS-backed, frequent releases; rustls's default provider since 0.23.0 (Feb 2024) | sole maintainer; ~3.3-year 0.16→0.17 gap; last release 2025-03-11 | org-maintained; chacha20poly1305 0.11.0 (2026-06), aes-gcm 0.11.1 (2026-08) | active (str4d) |
| Binary size (release example, over 432,656 B baseline) | **+749,776 B** | +93,760 B | **+45,904 B** (both AEADs) | +684,800 B |
| Round-trip + full AAD-binding matrix | pass | pass | pass | **fails by design** (no AAD) |

\* with `CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang` —
Apple clang cannot target wasm32 at all; ring compiles C for every
target.

### The decisive proofs (commands and outcomes)

```
$ cd spikes/crypto
$ cargo build --target wasm32-unknown-unknown --features rustcrypto
    Finished `dev` profile … in 5.08s                       # ok
$ cargo build --target wasm32-unknown-unknown --features ring-backend   # with Homebrew llvm clang
    Finished `dev` profile … in 6.12s                       # ok
$ cargo build --target wasm32-unknown-unknown --features aws-lc-backend
    error: failed to run custom build command for `aws-lc-sys v0.45.0`
    … cc-rs: command did not execute successfully: "clang" "--target=wasm32-unknown-unknown" … err_data.c
                                                             # fails — C cross-build, unsupported
$ cargo test --features all
    7 passed (per-candidate conformance + age demo); 5 passed (store)  # ok
```

Sizes: `cargo build --release --example size [--features X]` then
`stat -f%z target/release/examples/size` — baseline 432,656;
rustcrypto 478,560; ring 526,416; aws-lc-rs 1,182,432; age 1,117,456.

### Notes per candidate

- **`aws-lc-rs`** — excellent API and the only FIPS story, but the
  heaviest artefact (+750 KiB), and empirically it exposes **no
  XChaCha20-Poly1305** (only 96-bit-nonce AEADs), same as ring; and it
  cannot build for wasm32. Keep it as the native-only FIPS fallback.
- **`ring`** — builds for wasm only with a non-Apple clang for its C
  code, offers no zeroisation and no XChaCha, and its maintenance story
  (single maintainer, 3.3-year 0.16→0.17 gap, nothing since 2025-03) is
  the weakest of the three. rustls, its flagship consumer, switched its
  default provider to aws-lc-rs in 0.23.0 (Feb 2024).
- **RustCrypto** — the only candidate that is simultaneously pure Rust
  (no toolchain on any CI runner), zeroising, XChaCha-capable, smallest,
  and wasm-proven. Assurance caveat: the NCC Group audit (2019, funded by
  MobileCoin) covers 0.3.x-era code; the 0.11 line has evolved since.
  Acceptable because the AEAD constructions are standard, the crates are
  the most-deployed pure-Rust AEADs (age itself sits on them), and the
  port seam (#40) keeps the backend swappable.
- **`age`** — eliminated (see Decision). Scored once so the question does
  not return.

## Consequences

- The secrets store (native) and any shared crypto helper use
  `chacha20poly1305` with `zeroize`; nothing links `ring` or `aws-lc-rs`
  in this repo today.
- Random 192-bit nonces per encryption; no nonce storage or counter
  coordination anywhere.
- A FIPS requirement would arrive as an `aws-lc-rs` backend behind the
  #40 port on the native runtime plus a DEK rotation — not a redesign.
- Audit staleness on the RustCrypto line is noted here; if a deeper
  assurance need appears, commission a fresh audit of the pinned version
  rather than assuming the 2019 report transfers.
