<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-manifest.png" alt="cratefield-manifest — What a backend is." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-manifest"><img src="https://img.shields.io/crates/v/cratefield-manifest.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-manifest on crates.io"></a>
  <a href="https://docs.rs/cratefield-manifest"><img src="https://img.shields.io/docsrs/cratefield-manifest?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-manifest documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-manifest

The Cratefield **venture manifest** and **deterministic composition
generator** (issue #138).

A manifest is the small declarative document that says what a backend *is*:

```json
{
  "name": "acme-signups",
  "host": "acme.factory0.dev",
  "modules": ["waitlist", "email-signup"],
  "config": { "brand": "Acme" }
}
```

It is the **shared contract** of "Build Anywhere":

- the native **compile engine** (`fz build`) generates a Cloudflare venture
  crate from it and compiles it;
- the wasm **compose engine** (later) mounts the same module set in the
  browser.

The same manifest promotes to Cloudflare unchanged, so what you build in the
browser and what you deploy are the same module set by construction.

## Three concerns

- `catalog` — the module catalog and dependency resolution. This is the
  wasm-clean canonical home of the resolver control-plane's
  `cratefield_catalog` currently carries a copy of; the two are kept
  semantically identical (same ordering, same `content_key`) so control-plane,
  which already takes its module list from `builtin()`, can later drop its
  copy of the types and resolver. The list of modules is not copied: it lives
  in this crate's codegen registry, `builtin()` is built from it, and
  control-plane's `curated()` is derived from `builtin()`, adding the
  per-module detail the wizard shows. A module `fz add` offers is therefore
  one `fz build` can compose.
- `manifest` — the `VentureManifest` format and parsing.
- `generate` — the deterministic Rust composition generator: manifest →
  `Cargo.toml` + `src/lib.rs` + `src/fz_main.rs` + `wrangler.toml`. Pure
  function of the inputs; the same manifest always generates byte-identical
  files. It stops at source — turning the crate into a deployable wasm is
  `worker-build`, which the desktop app and the Docker image package.

The crate depends only on `serde`/`serde_json`/`sha2`, so it compiles to
wasm for the compose engine. TOML manifest parsing lives in the CLI.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
