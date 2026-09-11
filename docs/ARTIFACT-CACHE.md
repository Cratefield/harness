# The artifact cache's identity: build keys (issue #59)

A managed deployment should not compile per customer. The artifact is a pure
function of the module set and their exact versions, so it can be cached once
and reused by every customer who picks the same set. This document states what
the address is, what it deliberately excludes, and the guarantee that makes
sharing an artifact safe.

*Measured caveat (issue #58, `docs/BUILD-COST.md`):* adding a module crate to a
warm build costs **5.3 s**, of which `cargo build` is only 1.3 s — the rest is
`wasm-bindgen` and `wasm-opt`, which no cargo-level cache touches. Caching the
final artifact therefore saves seconds, not minutes. The key exists because
artifact *identity* is right regardless of speed: it is what provenance binds,
what lets one wasm serve customers with and without sidecars, and what the
control plane will look its builds up by when it exists. Nothing blocks on the
cache itself.

## The key

```
build_key = sha256(
    sorted [(module slug, exact version, release digest)] for every module,
    + harness_api,
    + rustc --version,
    + build profile ("release")
)
```

Computed by [`cratefield_manifest::build_key`], printed by
[`cratefield_cli::build_key`]:

```sh
fz build-key venture.json            # or venture.toml
fz build-key venture.json --catalog catalog.json
```

It prints the `sha256:…` key and the canonical JSON of the inputs that produced
it. It runs no cargo and writes nothing.

### Why each input is in

- **Slug + exact version + digest.** The issue's formula stops at (crate,
  exact version), but two publications can carry the same version number with
  different bytes; a content address that collided on those would hand one
  customer another's artifact. The pinned release digest (issue #142) is the
  content address of the release, so it is hashed too. Provenance records the
  same digests, so the key and the paper trail agree.
- **`harness_api`.** A module compiled against a different harness contract is
  a different artifact.
- **rustc version.** The wasm output is a function of the compiler.
- **Profile.** The only profile any deploy path invokes today is
  `worker-build --release`, so `release` is the constant
  `cratefield_manifest::BUILD_PROFILE`. A second profile becomes a caller
  input, not a hidden constant.

### What is deliberately not an input

The venture name, host, public URL, CORS origins, config, seed data, and the
sidecar mount table. Those are **per-customer deployment configuration**, not
artifact content:

- Two manifests naming the same modules with different names, hosts and config
  produce the **same key** and share the artifact.
- Two compositions differing only in their sidecar mounts produce the **same
  key** and the same artifact. This is the amended acceptance criterion of
  #59, and it only holds because the mount table is runtime configuration
  (`HARNESS_SIDECARS` / `fz --sidecars`, ADR 0009 as amended) rather than
  compiled in — `.sidecar(...)` in compiled code would make a customer's
  mounts invisible to the key and either serve a stale artifact or force a
  per-customer compile, the exact cost the cache exists to remove.

## The sharing guarantee

**Two customers sharing an artifact share no runtime state.** The artifact is
a *pure function*: the same wasm bytes, and nothing else. Every piece of
customer state enters at deployment or at runtime, never at compile:

| Concern | Where it lives | Shared? |
|---|---|---|
| Code (the `.wasm`) | the cached artifact | yes — that is the point |
| Worker | one deployment per customer | no |
| Database (D1) | one namespace per customer's Worker | no |
| Secrets | per-customer environment/secrets | no |
| Config, seed data | per-customer manifest/config | no |
| Sidecar mounts | `HARNESS_SIDECARS` on the customer's Worker | no |
| In-memory state | none: the Worker is stateless and request-scoped | no |

The deployment shape is the standard one: each customer gets their own
`wrangler deploy` of the shared wasm against their own D1 binding, their own
secrets and (when they have one) their own sidecar mount table. The harness is
stateless and request-scoped — the concurrent-request conformance tests prove
no state crosses requests — so sharing code cannot share state.

## What is not built here

Where the cache physically lives, the miss path, and the hit path that uploads
a stored `.wasm` without invoking cargo are control-plane decisions and
**out of scope** for #59. What exists today is the identity half: the key is
computable, stable, order-independent, and inspectable outside CI. A cache
service should store artifacts under this key and refuse anything whose
provenance (issue #142) does not verify against the recorded releases.
