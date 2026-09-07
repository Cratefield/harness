# cratefield-module-email-signup

Email signup for a Factory Zero venture: `POST /v1/email-signup` collects
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

Register the default mail templates in `harness.rs`:

```rust
use cratefield_core::Harness;
use cratefield_module_email_signup::default_templates;

// module defaults; venture overrides registered later win
let builder = Harness::builder().templates(default_templates());
```

See `docs/ARCHITECTURE.md` section 6 (Email signup) and section 11
(no enumeration, tokens, admin auth, retention).
