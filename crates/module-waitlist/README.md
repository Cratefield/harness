# factory0-module-waitlist

Per-product waitlist for a Factory Zero venture: `POST /v1/waitlist`
joins, a signed confirmation link assigns a dense per-product position,
referral codes credit the referrer, and a status endpoint shows the
entry's place and share link.

```rust
use factory0_module_waitlist::Waitlist;

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
use factory0_core::Harness;
use factory0_module_waitlist::default_templates;

let builder = Harness::builder().templates(default_templates());
```

Emits `waitlist.joined` and `waitlist.confirmed`; pair with
`factory0-module-email-signup`'s
`.subscribe_on_waitlist_confirm(true)` to mirror confirmed addresses
into the signup list — no crate dependency between the modules.

See `docs/ARCHITECTURE.md` section 6 (Waitlist) and section 11.
