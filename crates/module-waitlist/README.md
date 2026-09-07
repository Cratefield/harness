<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-module-waitlist"><img src="https://img.shields.io/crates/v/cratefield-module-waitlist.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-module-waitlist on crates.io"></a>
  <a href="https://docs.rs/cratefield-module-waitlist"><img src="https://img.shields.io/docsrs/cratefield-module-waitlist?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-module-waitlist documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-module-waitlist

Per-product waitlist for a Factory Zero venture: `POST /v1/waitlist`
joins, a signed confirmation link assigns a dense per-product position,
referral codes credit the referrer, and a status endpoint shows the
entry's place and share link.

```rust
use cratefield_module_waitlist::Waitlist;

let module = Waitlist::new()
    .products(["kontinuum", "undercover-rockstars"])
    .confirm_ttl_days(7)
    .referrals(true);
```

**Position semantics**: positions are per product, assigned densely at
confirm time as `1 + max(position)` inside one atomic `Database::batch`
that opens with a per-product lock statement (`UPDATE … SET referrals =
referrals WHERE product = ?` — value-neutral), so concurrent confirms of
the same product serialize on every engine (D1, SQLite, Postgres) and
never share a position. Positions are never recomputed when rows are
deleted.

Register the default mail templates in `harness.rs`:

```rust
use cratefield_core::Harness;
use cratefield_module_waitlist::default_templates;

let builder = Harness::builder().templates(default_templates());
```

Emits `waitlist.joined` and `waitlist.confirmed`; pair with
`cratefield-module-email-signup`'s
`.subscribe_on_waitlist_confirm(true)` to mirror confirmed addresses
into the signup list — no crate dependency between the modules.

See `docs/ARCHITECTURE.md` section 6 (Waitlist) and section 11.
