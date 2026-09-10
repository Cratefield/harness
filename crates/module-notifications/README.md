# cratefield-module-notifications

Push notifications for a Factory Zero venture: device and browser
subscriptions, per-account per-category preferences, a fan-out API other
modules call, and a drain that delivers through the `Push` port, prunes
dead subscriptions, retries transient failures and dead-letters permanent
ones.

Mounted at `/v1/notifications`. Requires the `Database`, `Push`, `Clock`
and `IdGen` ports; uses `Defer` and `HttpClient` when present.

## Compose it

```rust,ignore
use cratefield_module_notifications::{Category, Notifications};

let notifications = Notifications::new()
    .category(Category::new("booking"))
    .category(Category::new("coach_notes").default_enabled(false))
    .category(Category::new("room_starting").badge(true));

// Hand this to the modules that send. It starts working when the harness
// builds this module's router.
let notifier = notifications.notifier();

let harness = Harness::builder()
    .venture(venture)
    .module(notifications)
    .module(MyBookingModule::new(notifier))
    .runtime(runtime)
    .build()?;
```

## Send one

`notify` writes nothing. It hands back the outbox `INSERT`s so they commit
in **your** batch, with the state change that caused them:

```rust,ignore
let enqueued = notifier
    .notify(&*db, &account_id, "booking", Notification::new("Booked", "See you Tuesday"))
    .await?;

let mut statements = vec![my_booking_insert];
statements.extend(enqueued.into_statements());
db.batch(&statements).await?;      // the notification is now durable

notifier.deliver_now(&scope);      // and now it is attempted
```

If the isolate dies before `deliver_now` runs, nothing is lost: the
venture's scheduled entry point drains the rows on the next tick.

A caller with no state change of its own uses `notify_now`, which does the
batch and the defer itself. A module that cannot take a crate dependency
on this one emits `notifications.requested` on the event bus instead:

```json
{ "account_id": "acct-1", "category": "booking",
  "notification": { "title": "Booked", "body": "See you Tuesday" } }
```

## Routes

Every route is authenticated. The account comes from the token's `sub`,
never from a body field, and a subscription that belongs to another
account answers `404` — a `403` would confirm the id exists.

| Method | Path | What |
|---|---|---|
| `PUT` | `/v1/notifications/subscriptions` | Register a device; re-registering the same one is an upsert |
| `GET` | `/v1/notifications/subscriptions` | The account's own, recipients redacted to a prefix |
| `DELETE` | `/v1/notifications/subscriptions/{id}` | Sign-out |
| `GET` | `/v1/notifications/preferences` | Every declared category, with the values that apply |
| `PUT` | `/v1/notifications/preferences` | Change some of them; an unknown category is `400` |

```http
PUT /v1/notifications/subscriptions
Authorization: Bearer <access token>

{ "transport": "apns",
  "recipient": { "apns": { "device_token": "…" } },
  "app_id": "com.example.app", "app_version": "2.1.0" }
```

The `recipient` object is the `Push` port's own JSON form, so its Web Push
tag is `web_push` while the `transport` field and the stored column say
`webpush`. The two are checked against each other on every write.

## Delivery

| Outcome | What happens |
|---|---|
| `Delivered` | the row is deleted |
| `Unregistered` | the row **and the subscription** are deleted, and `notifications.subscription_pruned` is emitted |
| `Rejected` | dead-lettered, no retry: a bad payload does not fix itself |
| `NotConfigured` | dead-lettered with its own reason, so ops sees "mounted without the adapter" |
| `Transient` | retried with exponential backoff, never before the provider's `retry_after`, to `NOTIFICATIONS_MAX_ATTEMPTS` and then dead-lettered |

`Unregistered` is the **only** error that prunes. A wrongly-pruned Web
Push subscription cannot be recreated server-side at all (ADR 0015).

The preference is read in the drain, immediately before the send, so an
opt-out that arrives after the row was written still wins.

## Configuration

| Key | Default | What |
|---|---|---|
| `NOTIFICATIONS_AUTH_ISSUER` | — | The auth service's base URL, as it appears in `iss` |
| `NOTIFICATIONS_AUTH_CLIENT_ID` | — | This app's registered client id, which every token's `aud` must equal |
| `NOTIFICATIONS_MAX_ATTEMPTS` | `5` | Attempts before a transient failure is given up on |
| `NOTIFICATIONS_DRAIN_BATCH` | `50` | Rows one drain pass leases |

Without the two auth keys every route answers `401`: the module cannot
establish who is calling, and guessing is the one thing it must not do.
`validate_config` refuses a production deployment that sets neither.

It also refuses a production deployment that wired no push transport — but
only when the venture hands it the verdict, because the push environment
has exactly one reader (issue #191) and this module is not it:

```rust,ignore
Notifications::new()
    .transport_probe(|cfg| cratefield::push_wiring::inspect_push(cfg).any_routed())
```

## Tables

`notifications_subscriptions`, `notifications_preferences`,
`notifications_outbox` (the core `Outbox`) and
`notifications_dead_letters`. All four are declared, so `fz data export`
sees them.
