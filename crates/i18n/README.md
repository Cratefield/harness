# cratefield-i18n

Server-side localisation for a Factory Zero venture: [Project
Fluent](https://projectfluent.org) catalogs, BCP 47 negotiation, and the text
direction `unic-langid` does not carry.

Nothing in it is notification-specific. A `Catalog` answers "render message
`booking-confirmed`, attribute `.title`, in `id-ID`"; what the caller does with
the answer is the caller's business.

```rust
use cratefield_i18n::{Args, FluentCatalog, TITLE, localize};

let catalog = FluentCatalog::builder()
    .default_locale("en")
    .locale("en", include_str!("../locales/en.ftl"))
    .locale("id", include_str!("../locales/id.ftl"))
    .build()?;

let rendered = localize(&catalog, &"id-ID".parse()?, "booking-confirmed", TITLE, &Args::new());
assert_eq!(rendered.text, "Pesanan dikonfirmasi");
# Ok::<(), Box<dyn std::error::Error>>(())
```

`include_str!`, not a file read: a Worker isolate has no filesystem, and a
catalog built at cold start from data already in the binary costs one parse per
isolate.

## Three things it exists to get right

**It is `Send + Sync`.** The `FluentBundle` every example uses is built on
`Rc`/`RefCell` and is neither. `SendWrapper` does not fix that — it grants
`Send` alone and panics if the value is dropped off-thread. This crate uses the
concurrent memoizer and a static assertion pins it, so undoing that is a
compile error.

**Direction is an explicit list.** `unic-langid` parses tags and carries no
directionality data at all. `direction()` answers from a script list (`Arab`,
`Hebr`, `Thaa`, `Nkoo`, `Adlm`) and a language list (`ar`, `he`, `fa`, `ur`,
`ps`, `sd`, `yi`, `dv`, `ckb`), script first, and is tested both ways.

**A missing key is visible.** `localize` falls back per message — a
half-translated locale stays useful — and when no locale has the key at all it
renders the key itself and says so. An empty body looks delivered;
`booking-confirmed.body` is a bug report that names what to add.

`missing_messages()` is the same question asked before a deployment sends
anything, and it lists identifiers only.

## What a caller must not do

Argument values are personal data — a name, a place, a booking reference — so a
rendered string is too. Nothing here puts one in an error, and a caller must
keep it out of logs, events and columns as well.
