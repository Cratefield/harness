# factory0-module-cms

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
use factory0_module_cms::Cms;

let module = Cms::new().collections(["pages", "posts"]);
```
