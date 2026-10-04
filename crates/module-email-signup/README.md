<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-module-email-signup.png" alt="cratefield-module-email-signup — Confirmed, or not on the list." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-module-email-signup"><img src="https://img.shields.io/crates/v/cratefield-module-email-signup.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-module-email-signup on crates.io"></a>
  <a href="https://docs.rs/cratefield-module-email-signup"><img src="https://img.shields.io/docsrs/cratefield-module-email-signup?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-module-email-signup documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-module-email-signup

Email signup for a Cratefield venture: `POST /v1/email-signup` collects
an address, double opt-in via a signed confirmation link, one-click
unsubscribe, admin CSV export and hard delete.

```rust
use cratefield_module_email_signup::EmailSignup;

let module = EmailSignup::new()
    .double_opt_in(true)
    .confirm_ttl_days(7)
    .retention_days_pending(30);
```

Composable with `cratefield-module-waitlist`:

```rust
use cratefield_module_email_signup::EmailSignup;

let module = EmailSignup::new().subscribe_on_waitlist_confirm(true);
```

adds confirmed waitlist addresses to the signup list through the
`waitlist.confirmed` event — no crate dependency between the modules.

Register the mail templates in the venture's `src/lib.rs`, in the
venture's own style: they render through `cratefield-mail-templates`
(ADR 0028) with the `MailTheme` you give them. `default_templates()` renders
in a theme built from the venture's core `Brand` and its `MAIL_THEME` config
instead; either way, venture overrides registered later win.

```rust
use cratefield_core::Harness;
use cratefield_mail_templates::{MailTheme, Palette};
use cratefield_module_email_signup::themed_templates;

let theme = MailTheme::new("Acme", "https://acme.test")
    .logo("https://acme.test/assets/email/logo-64.png", "Acme")
    .light(Palette::neutral_light().button("#0E1526"));
let builder = Harness::builder().templates(themed_templates(&theme));
```

See `docs/ARCHITECTURE.md` section 6 (Email signup) and section 11
(no enumeration, tokens, admin auth, retention).

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
