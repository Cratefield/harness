<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-module-waitlist.png" alt="cratefield-module-waitlist — A place in the queue." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-module-waitlist"><img src="https://img.shields.io/crates/v/cratefield-module-waitlist.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-module-waitlist on crates.io"></a>
  <a href="https://docs.rs/cratefield-module-waitlist"><img src="https://img.shields.io/docsrs/cratefield-module-waitlist?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-module-waitlist documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-module-waitlist

Per-product waitlist for a Cratefield venture: `POST /v1/waitlist`
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

Joins may carry a free-form `answers` JSON object: `.answers_schema(|answers| ..)`
validates it whenever answers are present, `.require_answers(true)` rejects
joins without them, and the admin export carries the stored answers as a
quoted CSV column.

**Position semantics**: positions are per product, assigned densely at
confirm time from a per-product counter on `waitlist_position_lock` that
the lock-taking UPDATE increments, inside one all-or-nothing
`Database::batch_atomic`, so concurrent confirms of the same product
serialize on every engine (D1, SQLite, Postgres) and never share a
position; a UNIQUE(product, position) index backstops the allocation.
Positions are never recomputed when rows are deleted.

**Confirmation mail is deferred, and the join never depends on it.**
`POST /v1/waitlist` answers `202 {"ok":true}` for every accepted join,
whatever the mailer does — deliberately, so the answer leaks nothing about
whether the address was already on the list (`docs/SECURITY.md`). The
confirmation mail is built on the request path but sent after the response
returns, through the request's `Defer` port. With no mailer configured
(`RESEND_API_KEY` unset, or an unverified sending domain) the join still
succeeds: the entry is recorded `pending`, no mail goes out, and the
`NotConfigured` is only logged. There is no `503` on this path. A send
failure releases the hour-long send claim, so a later join retries the
mail. A form that has to offer a fallback address when mail is unreliable
must get it from somewhere other than the join response.

Register the mail templates in the venture's `src/lib.rs`, in the
venture's own style: they render through `cratefield-mail-templates`
(ADR 0028) with the `MailTheme` you give them. `default_templates()` renders
in a theme built from the venture's core `Brand` and its `MAIL_THEME` config
instead; either way, venture overrides registered later win.

```rust
use cratefield_core::Harness;
use cratefield_mail_templates::{MailTheme, Palette};
use cratefield_module_waitlist::themed_templates;

let theme = MailTheme::new("Acme", "https://acme.test")
    .logo("https://acme.test/assets/email/logo-64.png", "Acme")
    .light(Palette::neutral_light().button("#0E1526"));
let builder = Harness::builder().templates(themed_templates(&theme));
```

Emits `waitlist.joined` and `waitlist.confirmed`; pair with
`cratefield-module-email-signup`'s
`.subscribe_on_waitlist_confirm(true)` to mirror confirmed addresses
into the signup list — no crate dependency between the modules.

See `docs/ARCHITECTURE.md` section 6 (Waitlist) and section 11.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
