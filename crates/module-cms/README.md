<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-module-cms"><img src="https://img.shields.io/crates/v/cratefield-module-cms.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-module-cms on crates.io"></a>
  <a href="https://docs.rs/cratefield-module-cms"><img src="https://img.shields.io/docsrs/cratefield-module-cms?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-module-cms documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-module-cms

A small content store with an editor, as a Factory Zero module. Content is a
titled body plus a JSON `data` object addressed by `(collection, slug)`, kept
in the venture's own database. Every publish appends an immutable revision, so
items are versioned and the history of what was public is recoverable.

Public routes are reads (`GET /v1/cms/{collection}` and
`/v1/cms/{collection}/{slug}` serve published content); every write is an admin
action behind the `ADMIN_TOKEN` bearer, so there is no public write endpoint.
The look comes from the venture's `UI_SPEC`, not from here — this is a content
store, not a page builder.

```rust
use cratefield_module_cms::Cms;

let module = Cms::new().collections(["pages", "posts"]);
```
