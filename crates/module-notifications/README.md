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

The account comes from the token's `sub`, never from a body field, and a
subscription that belongs to another account answers `404` — a `403`
would confirm the id exists.

| Method | Path | What |
|---|---|---|
| `PUT` | `/v1/notifications/subscriptions` | Register a device; re-registering the same one is an upsert |
| `GET` | `/v1/notifications/subscriptions` | The account's own, recipients redacted to a prefix |
| `DELETE` | `/v1/notifications/subscriptions/{id}` | Sign-out |
| `GET` | `/v1/notifications/preferences` | Every declared category, with the values that apply |
| `PUT` | `/v1/notifications/preferences` | Change some of them, and the account's `locale`; an unknown category is `400` |
| `PUT` | `/v1/notifications/email` | The address this account is mailed at; verified only when the token's own `email_verified` claim covers it |

Two routes are **not** authenticated, because neither caller can hold a
session. Each carries its own proof instead, and the module declares that
with `public_writes` + `public_write_policy` so the production check can
see them:

| Method | Path | Proof |
|---|---|---|
| `GET`/`POST` | `/v1/notifications/email/unsubscribe?token=` | An HMAC token signed for `(account, category)` — RFC 8058 one-click |
| `POST` | `/v1/notifications/email/webhook` | The provider's Svix signature over the raw body |

**Only the `POST` acts.** The `GET` renders the choice as a form that
posts back to the same URL and changes nothing until it is submitted.
Microsoft Defender Safe Links, Proofpoint URL Defense and most scanning
gateways fetch every link in a message before the recipient sees it, so a
`GET` that applied the unsubscribe opted out every member at any such
company without a click — with no signal to them or to the venture, and
indistinguishable from a delivery failure from the venture's side. RFC
8058 exists precisely so the POST is the acting verb; a scanner fetches,
it does not submit forms.

The `List-Unsubscribe` and `List-Unsubscribe-Post` headers ship **only
when a `Signer` is wired**. `Signer` is optional here, and without one
the link falls back to a venture front-end path this module does not
serve — which either 404s or hits a single-page app that answers the POST
with `200 HTML`, reading as success while doing nothing. A mail with no
one-click header is compliant; one whose header names a URI that cannot
honour it is not, and it fails silently at Gmail and Yahoo. The footer
link, which only ever promised a person somewhere to go, still points at
the account's settings.

The webhook takes Resend's `email.bounced` and `email.complained` and
suppresses the address for **every** account that holds it — the provider
reports a mailbox, not an account, and two people can share one. Only a
`Permanent` bounce suppresses: a soft bounce is a full mailbox, not a
dead address. Anything it does not act on still answers `200`, because a
provider retries until it gets one.
| `GET` | `/v1/notifications/vapid-public-key` | None needed — the value is public by construction (see below) |

The key route is the exception because the value is public by
construction: it is the derived public half of the VAPID pair and is
handed to every browser that subscribes, and a site has to be able to put
"turn notifications on" in front of a visitor who has not signed in.
It answers `404 webpush-not-configured` unless the venture wired
`Notifications::vapid_public_key` — with the key derived by
`cratefield-push-wiring`, which is the one crate that reads the push
environment, so the served key cannot drift from the one sends are
signed with:

```rust,ignore
Notifications::new()
    .vapid_public_key(cratefield::push_wiring::vapid_public_key)
```

The browser half that consumes it — `cf.push.subscribe()` and the
reference service worker — is `cratefield-ui` (issue #183); the client
contract, the iOS matrix and the `pushsubscriptionchange` repair are in
`docs/UI.md`.

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

## A device that changes hands

A subscription is identified by `(transport, recipient_hash)`, so a device
that signs into a second account **re-homes** onto it rather than
delivering both accounts' mail. That is the behaviour a shared tablet
needs, and it is the one write in the module that acts on a push token
alone — and a push token is not an authenticator. It leaks through client
logs, crash reports and third-party SDKs, and whoever holds one can present
it with their own valid bearer.

So a take-over is bounded, recorded and recoverable rather than silent:

- at most `NOTIFICATIONS_REHOME_MAX_PER_HOUR` devices per account per hour,
  and `429 device-rehome-limit` past that. `0` refuses cross-account
  re-homing outright, for a venture whose devices are never shared;
- every one of them emits `notifications.subscription_rehomed`
  (`subscription_id`, `account_id`, `previous_account_id`, `transport`,
  `at` — and no recipient), so the venture can tell the previous owner;
- a notification queued for the previous owner is **dropped**, never
  delivered to the new one: the drain checks that the row's account and
  the job's account still agree;
- the budget is the caller's, not the row's, so the account that lost a
  device takes it straight back on the next app launch.

Signing out (`DELETE /subscriptions/{id}`) deletes the row instead of
moving it, so it frees the device for the next account with no budget spent
at all. What the module cannot do alone is prove the caller is holding the
device; that needs a client-side confirmation this child does not ship.

## Delivery

| Outcome | What happens |
|---|---|
| `Delivered` | the row is deleted |
| `Unregistered` | the row **and the subscription** are deleted, and `notifications.subscription_pruned` is emitted |
| `Rejected` | dead-lettered, no retry: a bad payload does not fix itself |
| `NotConfigured` | dead-lettered with its own reason, so ops sees "mounted without the adapter" |
| `Transient` | retried with exponential backoff, never before the provider's `retry_after`, to `NOTIFICATIONS_MAX_ATTEMPTS` and then dead-lettered |

Mail takes the same five shapes over `Mailer`'s outcomes: `Sent`
completes the row and counts against the cooldown, `NotConfigured`
dead-letters with its own reason rather than passing for success,
`Unauthorized`/`DomainNotVerified`/`Invalid` dead-letter as `rejected`
because nothing about that message will ever be accepted, `RateLimited`
waits out the delay the provider named, and everything else retries to
the same bound.

`Unregistered` is the **only** error that prunes. A wrongly-pruned Web
Push subscription cannot be recreated server-side at all (ADR 0015).

`notifications_dead_letters.last_error` is **scrubbed where it is
bound**, not by the callers that pass it. What ends up there is the
provider's own words — a Resend `422` quotes the field it objected to,
which for a send is the recipient address — and the row outlives erasure
of `notifications_email_targets`. The log leg was already sanitized by
the tracing formatter, so a column stored raw was the half nobody would
look at (issue #235).

The preference is read in the drain, immediately before the send, so an
opt-out that arrives after the row was written still wins.

Mail the cooldown suppressed is not lost silently: each drop leaves a row,
and once the window has rolled the scheduled drain sends one summary —
"N new … notifications" — with the same re-checks and a once-per-window
idempotency key (issue #232).

A row whose own database call fails is counted in `DrainReport::failed` and
keeps its lease: the pass carries on, and that row is due again when the
lease expires. Rows go out `NOTIFICATIONS_DRAIN_CONCURRENCY` at a time —
one drain is one `wait_until` against a five-minute lease, and the rows
share nothing.

The venture's scheduled entry point drains through **the context it is
handed**. A cron invocation builds no router, so a module that reached for
one parked at router-build time recovered nothing at all on a cold isolate.

## Configuration

| Key | Default | What |
|---|---|---|
| `NOTIFICATIONS_AUTH_ISSUER` | — | The auth service's base URL, as it appears in `iss` |
| `NOTIFICATIONS_AUTH_CLIENT_ID` | — | This app's registered client id, which every token's `aud` must equal |
| `NOTIFICATIONS_MAX_ATTEMPTS` | `5` | Attempts before a transient failure is given up on |
| `NOTIFICATIONS_DRAIN_BATCH` | `50` | Rows one drain pass leases |
| `NOTIFICATIONS_DRAIN_CONCURRENCY` | `8` | Rows in flight at a time inside one pass |
| `NOTIFICATIONS_REHOME_MAX_PER_HOUR` | `3` | Devices one account may take over from other accounts in an hour; `0` refuses every take-over |
| `NOTIFICATIONS_RESEND_WEBHOOK_SECRET` | — | The endpoint secret (`whsec_…`) the provider's bounce webhook is signed with. Unset, that route refuses every delivery rather than trusting one |
| `NOTIFICATIONS_DEFAULT_LOCALE` | the catalog's own | The language a recipient who has expressed none is written to. A value that is not a BCP 47 tag is refused by `validate_config`, which names the variable and not the value |

Every one is read as a `u32`, and `validate_config` refuses a value the
runtime could not read — including one above `u32::MAX`, which used to
validate clean and then silently run the default.

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
`notifications_outbox` (the core `Outbox`), `notifications_dead_letters`,
`notifications_inbox`, `notifications_email_targets`,
`notifications_email_sends`, `notifications_locales` and
`notifications_email_suppressed` (#232). All nine are
declared, so `fz data export` sees them.

## Languages

A caller that passes a `Notification` gets exactly what it wrote, in every
channel, on every device — which is what a venture with one language wants
and costs it nothing.

A venture with more than one names a message instead, and the module
renders it **per recipient at delivery**: the subscription's locale, then
the account's, then the venture's default. The caller cannot choose,
because one account can have an English browser and a Bahasa phone.

```rust,ignore
notifier.notify_now(db, scope, account, "booking",
    Localizable::new("booking-confirmed")
        .arg("places", 2)          // a number, so the plural selector works
        .arg("coach", coach.name),
).await?;
```

The catalog is `cratefield-i18n` (Project Fluent), built once at cold
start from `.ftl` sources the venture embeds. A missing translation is
never silent: the notification carries the message id as its text and
`notifications.missing_translation` names the key, the attribute and the
locale — and nothing else, because a rendered string is built from the
caller's values about a person.

`Category::render` chooses who renders for a **token** transport:
`server` (the default), `native` (the app's own loc keys, with the
venture default text beside them) or `both`. Web Push has no loc-key
mechanism, so a browser is always server-rendered.

The whole chain, the `.ftl` example with plurals, and the honest note that
changing an account's locale does **not** rewrite its old inbox rows are in
[`docs/NOTIFICATIONS.md`](../../docs/NOTIFICATIONS.md).
