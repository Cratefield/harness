# factory0-module-email-signup

Email signup for a Factory Zero venture: `POST /v1/email-signup` collects
an address, double opt-in via a signed confirmation link, one-click
unsubscribe, admin CSV export and hard delete.

```rust
EmailSignup::new()
    .double_opt_in(true)
    .confirm_ttl_days(7)
    .retention_days_pending(30)
```

Composable with `factory0-module-waitlist`:

```rust
EmailSignup::new().subscribe_on_waitlist_confirm(true)
```

adds confirmed waitlist addresses to the signup list through the
`waitlist.confirmed` event — no crate dependency between the modules.

Register the default mail templates in `harness.rs`:

```rust
Harness::builder()
    .templates(EmailSignup::default_templates())
    // overrides registered later win
```

See `docs/ARCHITECTURE.md` section 6 (Email signup) and section 11
(no enumeration, tokens, admin auth, retention).
