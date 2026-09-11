# Notifications

The `Push` port and `cratefield-module-notifications` (epic #192) are how a
venture reaches a person. One `notify()` call fans out to up to three
channels — push, an in-app inbox, and email — under one set of per-category
preferences.

Like every adapter, each push adapter speaks the provider's HTTP API over the
runtime's `HttpClient` port. No vendor server SDK, no `reqwest`, no OpenSSL,
so the same crate runs on Cloudflare Workers and on the native runtime.

## Which transport reaches which device

| Device | Transport | Adapter | OSS |
|---|---|---|---|
| iPhone, iPad | APNs | `cratefield-adapter-apns` | Apple's service; our client is ours |
| Android with Play services | FCM HTTP v1 | `cratefield-adapter-fcm` | Google's service. The only Google code involved is the Firebase client SDK in the app (Apache-2.0) |
| Android without Google (F-Droid, GrapheneOS, /e/OS) | UnifiedPush | `cratefield-adapter-webpush` | Fully OSS. A distributor (ntfy, NextPush, Sunup) speaks the *same* Web Push protocol |
| Browser, installed PWA | Web Push (RFC 8030/8291/8292) | `cratefield-adapter-webpush` | Standard; the push service is the browser vendor's |

One adapter covers the last two rows. That is the point of choosing Web Push:
a de-Googled Android phone and a desktop browser are the same protocol.

### What is proven, and what is not

Read this table before promising a customer anything.

| Transport | Proven in CI | Proven against the real vendor |
|---|---|---|
| Web Push | **Yes** — every release runs the encryption and VAPID paths against a real [ntfy](https://ntfy.sh) server (issue #181) | No |
| UnifiedPush | **Yes** — same adapter, same ntfy leg; ntfy *is* a UnifiedPush distributor | No |
| APNs | Unit tests and the conformance suite | No |
| FCM | Unit tests and the conformance suite | No |

**No transport has been exercised against a real device or a real vendor
account.** Each needs an Apple team, a Firebase project, or a physical phone.
That work is issue #186, and this table is updated when it closes — not before.

RFC 8291's Appendix A vector is the acceptance test for the Web Push
encryption. RFC 8292 publishes no vectors, so VAPID is proven by verifying our
own signature with `p256`'s verifier under a fixed key and clock, plus the
live ntfy leg.

## Wiring a venture

The environment variables per transport are in
[`PUSH-ENV.md`](PUSH-ENV.md) — one reader owns them
(`cratefield-push-wiring`), and a build guard fails if any other crate names
one in a string literal.

```rust,ignore
Harness::builder()
    .module(Notifications::new()
        .category(Category::new("booking"))
        .category(Category::new("coach_notes").default_enabled(false))
        .category(Category::new("room_starting").in_app(false).badge(true))
        .transport_probe(|cfg| cratefield::push_wiring::inspect_push(cfg).any_routed())
        .mailer_probe(|cfg| cfg.get("RESEND_API_KEY").is_some())
        .vapid_public_key(cratefield::push_wiring::vapid_public_key))
    .build()
```

A category is the vocabulary an account switches on and off, so the names are
the venture's. Each has three channel defaults:

| Builder | Default | Meaning |
|---|---|---|
| `default_enabled(bool)` | `true` | Push, for an account that never expressed a preference |
| `in_app(bool)` | `true` | Whether a `notify` keeps an inbox row |
| `email(bool)` | **`false`** | Whether it is emailed. Off by default: email is the most intrusive channel and the hardest to take back |
| `badge(bool)` | **`false`** | Off because a badge number the server cannot compute correctly is worse than none |

### VAPID

```
fz push vapid keygen --file ./vapid-private.key
```

Generates the P-256 pair Web Push identifies this application server by, and
writes the private half `0600`, refusing to overwrite without `--force`.

**Generate it once and keep it.** Rotating it invalidates every existing
browser subscription, and no server can recreate one — only the browser can,
by subscribing again.

### Checking the wiring

`fz doctor` refuses a production build that is half-wired: a transport with
some of its variables set and some unset is a transport that will answer
`NotConfigured` on every send while the doctor reports a healthy deployment.
Below production the same state is a warning, because wiring a transport one
variable at a time is what development looks like.

It also refuses production when a module requires `Push` and no transport is
routed at all, and when a category opts into email with no `Mailer` wired.

## Preferences

One switch per account, per category, per channel. The `Category` defaults
above are only what applies until the account says otherwise; a stored row
overrides them channel by channel.

| Route | Does |
|---|---|
| `GET /v1/notifications/preferences` | The **effective** answer: every declared category with the value in force, the account's row where it has one and the category's default where it does not |
| `PUT /v1/notifications/preferences` | A patch — `{"preferences": {"booking": {"push": false}}}`. An omitted channel keeps the value it had; a category this venture does not declare is refused `400 unknown-category` rather than stored |

Both are behind the account's own token, and both answer that same effective
view, so a client renders what the `PUT` returns without a second read. Both
also carry the account's `locale` and its `dir` — see
[Languages](#languages) — and the `PUT` takes a `locale` alongside
`preferences` to change it.

### A late opt-out wins

The preference that decides a send is the one read **at delivery**, not the one
in force when `notify()` wrote the row.

| Channel | Where it is decided |
|---|---|
| In-app | At `notify()`, because that is when the row is written. An account with no stored row keeps the record even for a category whose push is off by default — switching push off silences the interruption, not the history |
| Push | At `notify()` **and again in the drain**. Somebody who switches a category off while a notification is queued does not get it |
| Email | At `notify()` and again in the drain, which re-reads the verified address and the unsubscribe state too. All three can change after the row is written, and the later answer is the one that counts |

A preference row that will not decode fails the read with a `500` rather than
falling back to the default. Treating an unreadable row as absent would turn an
explicit opt-out into an opt-in, and mailing or pushing to somebody who
switched a category off is the worse failure.

## The failure contract

`Push::send` answers with `PushOutcome` or fails with `PushError`, and the
module does something different with each.

| Result | What it means | What the module does |
|---|---|---|
| `Delivered { id }` | Accepted, with the provider's id where it gives one | Completes the row |
| `NotConfigured` | The adapter has no key, or no adapter serves this recipient | **Dead-letters** with that reason. A venture that mounted the module without the transport it needs has a bug, not a quiet no-op |
| `Unregistered` | The recipient is gone (APNs `410`, Web Push `410`, FCM `UNREGISTERED`) | **Deletes the subscription and the row, in one batch** |
| `Rejected(msg)` | A `4xx` that is not `410`; not retryable without a change | Dead-letters with the message |
| `Transient { retry_after }` | Temporary | Retries with exponential backoff, **never before** the provider's own `retry_after`, to a bound, then dead-letters |

### `Unregistered` is a delete instruction

An adapter maps only a status whose *sole* meaning is "gone" onto it. Web Push
`404` is deliberately **not** one. RFC 8030 defines only `410`, and a `404` is
what a proxy that came back without its routes, an edited ingress rule or a
moved reverse proxy answers for **every** path — so pruning on it would delete
a venture's whole Web Push register in a single pass. That is unrecoverable
server-side: a subscription can only be recreated by the browser calling
`pushManager.subscribe()` again, which needs the person back on the site.

So `404` is retryable, and the trade is deliberate: a subscription that really
is gone behind a service that only ever answers `404` is retried until the
attempt budget gives up and then lingers in the register. Wasted sends against
lost subscribers is the price of not deleting live ones.

### The outbox

`notify()` returns statements rather than writing them, so the notification
becomes durable **exactly when the caller's own state change does**. A booking
that rolls back leaves no "your booking is confirmed" behind.

```rust,ignore
let enqueued = notifier.notify(db, account, "booking", notification).await?;
let mut batch = my_own_writes();
batch.extend_from_slice(enqueued.statements());
db.batch(&batch).await?;
notifier.deliver_now(scope);   // attempts delivery on this request's Defer
notifier.announce(scope, &enqueued).await;  // the live in-app event
```

Nothing is lost if the isolate dies before delivery: the venture's scheduled
entry point drains whatever the immediate attempt never reached. That
scheduled drain runs through the ports the runtime hands it, not a context
parked when a router was built — Cloudflare's scheduled path builds no router,
so a cold isolate would otherwise never run the recovery half at all.

## Client guides

Each of these sends the same request once the device has a token:

```
PUT /v1/notifications/subscriptions
Authorization: Bearer <the account's access token>

{ "transport": "apns" | "fcm" | "webpush", "recipient": { … } }
```

The recipient shape is the port's own: `{ "device_token": "…" }` for APNs,
`{ "registration_token": "…" }` for FCM, and the browser's subscription JSON
for Web Push.

> The Swift and Kotlin below are written against the vendor APIs as
> documented, and are **not compiled or run by CI** — unlike the Rust in this
> repository. Treat them as a starting point, and see issue #186 for the
> live-proof status of each transport.

### iOS (APNs)

Written against iOS 16 / `UserNotifications`.

```swift
// 1. Ask. Do it when the person has a reason to say yes, not at launch.
let granted = try await UNUserNotificationCenter.current()
    .requestAuthorization(options: [.alert, .sound, .badge])
guard granted else { return }

// 2. Register. This is what produces a device token.
await UIApplication.shared.registerForRemoteNotifications()

// 3. The token arrives here, as bytes. Send the hex.
func application(_ app: UIApplication,
                 didRegisterForRemoteNotificationsWithDeviceToken data: Data) {
    let token = data.map { String(format: "%02x", $0) }.joined()
    // PUT /v1/notifications/subscriptions { transport: "apns", recipient: { device_token: token } }
}
```

`apns-topic` is the app's bundle id. A debug build talks to the APNs sandbox
and a TestFlight or App Store build talks to production; a token from one is
not valid on the other, which is the most common reason a send that "works"
delivers nothing.

### Android with Play services (FCM)

Written against `firebase-messaging` 24.x (Apache-2.0).

```kotlin
// The current token.
FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
    // PUT /v1/notifications/subscriptions { transport: "fcm", recipient: { registration_token: token } }
}

// And every time it changes — it does, and a stale one silently stops working.
class Messaging : FirebaseMessagingService() {
    override fun onNewToken(token: String) { /* PUT it again */ }
}
```

Map each of the venture's `category` names onto an Android notification
channel, so the OS-level controls and the harness preferences describe the
same things.

### Android without Google (UnifiedPush)

Written against `org.unifiedpush.android:connector` 2.x (Apache-2.0).

The distributor hands back an endpoint URL and, in UnifiedPush v3, the
`p256dh` and `auth` keys — which is exactly a Web Push subscription, so it
goes up as `transport: "webpush"`.

If the person has no distributor installed there is nothing to register with;
the app should say so and point at one (ntfy is on F-Droid). This is the case
that has no equivalent on iOS, and an app that treats it as an error rather
than a choice will confuse people who deliberately have no Google services.

### Browser

With `cf.js`:

```js
cf.auth = () => myApp.accessToken();   // the one auth seam
await cf.push.subscribe();             // asks, subscribes, and PUTs
```

Without it, the raw path is `navigator.serviceWorker.register`, then
`registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey })`
where the key comes from `GET /v1/notifications/vapid-public-key` — an
unauthenticated route, deliberately, so a site can offer the button before
anybody has signed in. Then PUT `subscription.toJSON()`.

Safari supports Web Push from 16.4, **only for a PWA the person has added to
the Home Screen**. A tab cannot subscribe.

## In-app

Every `notify` writes an inbox row for a category that declares `in_app` —
including for an account with **no device at all**, and one whose *push*
preference is off. Those switch off the interruption, not the record. It is
the only channel that needs no permission and the only one a person can
scroll back through.

| Route | Does |
|---|---|
| `GET /v1/notifications` | One page, newest first. `?cursor=&unread=&limit=` |
| `GET /v1/notifications/unread-count` | A count the client asked for and renders itself — not an OS badge |
| `POST /v1/notifications/{id}/read` | Idempotent; reading twice keeps the first timestamp |
| `POST /v1/notifications/read-all` | Answers how many moved |
| `DELETE /v1/notifications/{id}` | Archive, soft — the row stays for `fz data export` |

All behind the account's own token. **Another account's id answers `404`, not
`403`**, so the route cannot be used to discover that an id exists.

### The cursor

Paging is keyset over `(created_at, id)`, and the cursor is opaque — pass back
what the previous page returned. It is deliberately not the id alone: ids come
from the `IdGen` port, whose ULIDs read the real clock and randomise their
tail, so two minted in the same millisecond have no defined order and neither
matches the `Clock` the API reports.

### Live updates

When the venture wires `Realtime`, the module publishes to room
`notifications:<account_id>` after the inbox row commits. Nothing is published
that the row does not also hold, so a client that missed the event loses
nothing by reading the list.

Without `Realtime` a client polls `unread-count`. `<cf-notifications>` does
that only while the tab is visible — see [`UI.md`](UI.md).

### Tapping a push

The push payload's `data.notification_id` is the inbox row's fan-out id, so:

1. `POST /v1/notifications/{id}/read`
2. open the notification's `url`

A client that already rendered the in-app item can dedupe the push that
follows it by the same id.

## Email

The third channel, over `Port::Mailer`, for a category that opted in with
`email(true)`.

The address cannot come from a token at send time — `notify()` runs inside
another module's batch or off a bus event, where there are no claims — so it
is set on an authenticated route (`PUT /v1/notifications/email`) and the drain
reads only that table. An address is marked verified only when the issuer's
own claims say that token's address is this address and is verified.

- **An unverified address is never mailed.** It is somebody else's mailbox
  until proven otherwise, and mailing it is what gets a sending domain
  blocked.
- A changed address starts unverified with its unsubscribe cleared: the
  previous address's answers were about a different mailbox.
- One email per notification per **account**, not per device.

Every mail carries RFC 8058 one-click unsubscribe — `List-Unsubscribe` and
`List-Unsubscribe-Post` — because Gmail and Yahoo have required it of bulk
senders since 2024, and a "click here" line in a footer is not what they
check for. The header link stops that category; the footer also offers every
category, so somebody who wants out entirely does not unsubscribe once per
category as they arrive.

A per-category cooldown caps how much mail one account can get in a window
(default 5 an hour). Over the cap the mail is **dropped, not deferred**:
deferring would deliver the backlog the moment the window rolled, which is the
flood the cap exists to prevent. Coalescing those into one summary mail is
issue #232.

A bounce or complaint from the provider suppresses the address (issue #233).

## Languages

**The language cannot be chosen when the caller queues a notification.** One
account can have an English browser and a Bahasa phone, and the module that
confirms a booking knows about neither. So a caller names a message instead of
writing one, and it is rendered **per recipient at delivery** (issue #190).

A venture with one language needs none of this and pays for none of it: pass a
rendered `Notification` and everything below is skipped — no catalog is built,
no locale is read, and the notification reaches the device exactly as written.

### The chain

The **subscription's** locale, then the **account's**, then the venture's
default.

| Channel | Uses | Why |
|---|---|---|
| Push | the subscription's locale | A device's own setting is the best signal there is: it is what the person holding the phone chose |
| In-app inbox | the account's | One inbox |
| Email | the account's | One mailbox |

A subscription's locale comes from the `locale` field of `PUT
/v1/notifications/subscriptions`, or from `Accept-Language` when the client
sends none — which is all a browser has. An account's comes from `locale` on
`PUT /v1/notifications/preferences`, and an account that has never had one is
seeded from `Accept-Language` on its first such call. The venture's default is
`NOTIFICATIONS_DEFAULT_LOCALE`, or the catalog's own.

Every one of those is parsed into a BCP 47 language identifier before it is
stored, and a value that is not one is dropped rather than kept. Only a
canonical tag ever reaches a column — and so a log, an export or a `lang`
attribute.

### The catalog

[Project Fluent](https://projectfluent.org), in `cratefield-i18n`. Pure Rust,
no I/O, reaches wasm32, and `.ftl` is what translators already know.

```ftl
# locales/en.ftl
booking-confirmed =
    .title = Booking confirmed
    .body = { $places ->
        [one] One place with { $coach }, on { $day }
       *[other] { $places } places with { $coach }, on { $day }
    }
    .subject = Your booking with { $coach }
```

```ftl
# locales/id.ftl — Indonesian has one plural form, so `[one]` never appears
booking-confirmed =
    .title = Pesanan dikonfirmasi
    .body = { $places } tempat bersama { $coach }, pada { $day }
```

`.title` and `.body` are required; `.subject` is read by mail only. The plural
selector is CLDR's, per locale, which is the reason to use Fluent rather than
a format string.

```rust,ignore
Notifications::new()
    .category(Category::new("booking"))
    .catalog(
        FluentCatalog::builder()
            .default_locale("en")
            .locale("en", include_str!("../locales/en.ftl"))
            .locale("id", include_str!("../locales/id.ftl"))
            .build()?,
    )
    .messages(["booking-confirmed"])
```

`include_str!`, not a file read: a Worker isolate has no filesystem, and the
bundles are built once per isolate at cold start.

Then the caller names the message:

```rust,ignore
notifier.notify_now(db, scope, account, "booking",
    Localizable::new("booking-confirmed")
        .arg("places", 2)          // a number, so the plural selector works
        .arg("coach", coach.name)
        .url(format!("/bookings/{id}")),
).await?;
```

**Money and dates are passed pre-formatted**, in `args`. Only the venture
knows the currency, the scale and how it rounds; Fluent's own number
formatting is not told any of that.

### Server, native, or both

An app that ships its own translations does not need the server's. Per
category:

| `render:` | APNs / FCM get | Web Push gets |
|---|---|---|
| `server` (default) | the recipient's language, no loc keys | the recipient's language |
| `native` | the app's loc keys, with the **venture default** text beside them as a fallback | the recipient's language |
| `both` | the app's loc keys **and** the recipient's language | the recipient's language |

The keys are the app's own (`Localizable::loc`), not catalog ids: only the app
knows what is in its `.strings` and its `strings.xml`. **Web Push has no
loc-key mechanism at all**, so a browser is always server-rendered — the
module never attaches keys for it, whatever the category says.

Pick `native` when the app owns every string and the server's text is only
there for an old build; `both` when the app is newer than its translations and
should fall back to ours; `server` for everything else, and for any venture
whose clients are browsers.

### When a translation is missing

It is **visible from both ends**, never silent. The notification is delivered
with the message id as its text — `booking-confirmed.title`, which is a bug
report from whoever receives it — and `notifications.missing_translation` is
emitted with the key, the attribute and the locale. That event carries no
rendered string and no argument: those are the caller's values about a person.

Before that: `.messages(..)` lists the ids a venture promises are translated
into every locale its catalog declares. Any gap fails `validate_config` — so
the module refuses to start — and `fz doctor` lists them, one per locale, under
the `module-self-check` code.

Fallback is per **message**, not per catalog: an `id` catalog that has
`booking-confirmed` and not `coach-notes` renders the first in Indonesian and
the second in the default locale. A half-translated locale stays useful.

### Direction

`unic-langid` parses language tags and carries no directionality data — there
is no `is_rtl()` to call, and no browser API answers it either. So
`cratefield-i18n` holds an explicit list: scripts `Arab`, `Hebr`, `Thaa`,
`Nkoo`, `Adlm`, and languages `ar`, `he`, `fa`, `ur`, `ps`, `sd`, `yi`, `dv`,
`ckb`, script first so `az-Arab` is right-to-left and `ku-Latn` is not.

Mail carries `Content-Language` and wraps its body in `lang`/`dir`. The inbox
API returns `locale` and `dir` per item, and `<cf-notifications>` sets both on
the item it renders — per item, because one list can hold an Indonesian
booking and an Arabic one. Relative times stay the browser's job
(`Intl.RelativeTimeFormat` against the page locale).

The locale reported is always the one the text was **actually** rendered in. A
request for `ar` that fell back to English is an English mail, and labelling it
`ar` would right-align it in every client that obeys.

### What this does not do

**Changing an account's locale does not rewrite its old inbox rows.** They
were rendered when they were written and they stay as they are. The row keeps
its `loc_key` and `loc_args` beside the rendered text, so a client that wants
to re-render can; the module never does it. Re-rendering stored rows is out of
scope, and so are machine translation and a translation-management UI.

## Testing

- **Module tests** use `FakePush` and `FakeMailer` from `cratefield-testing`:
  every outcome above is scripted, including the ones a real provider gives
  rarely.
- **CI** runs the Web Push encryption and VAPID paths against a real ntfy
  server on every release.
- **`fz push send --transport … --recipient …`** sends one notification
  through the adapters this venture's environment configures — the same
  construction `serve()` uses, so what it reaches is what the deployment
  reaches. The recipient is credential material and will be in your shell
  history.
- **Live proofs** per vendor are issue #186, and none is done.

## Privacy

A device token, an FCM registration token and a Web Push endpoint are all
**device identifiers**. The harness treats them accordingly:

- Signing out (`DELETE /v1/notifications/subscriptions/{id}`) deletes the row,
  scoped to its owner.
- `Unregistered` from the provider deletes it too — that is the whole reason
  the outcome is separated from the other failures.
- A subscription that changes account is **re-homed, bounded and recorded**: a
  push token is not an authenticator, so taking a device over needs no proof
  beyond holding the token. The budget bounds how many an account can claim in
  an hour, an event records it, and the previous owner's queued notifications
  are dropped rather than delivered to the new one. ADR 0016 states the
  residual risk plainly rather than hiding it.
- The listing route redacts the recipient; a send prints the `Recipient`'s
  fingerprinting `Debug`, never the token.
- Inbox rows are retained for `notifications.inbox_retention_days` (default
  90) and only once **read or archived** — an unread row is still waiting to
  be seen, however old.
- Provider error text is scrubbed twice: `MailError` and `PushError` scrub in
  their own `Display`, and `notifications_dead_letters.last_error` is scrubbed
  again at the one place the column is bound, whatever the caller passes. A
  provider `422` quoting the recipient address used to sit in plain text in a
  venture's own table while the log showed it correctly redacted (issue #235).
- Every table the module owns is declared in `Module::tables()`, so
  `fz data export` carries all seven. **Erasure does not reach them yet**:
  `cratefield-module-privacy` works from `Module::personal_data()`, which this
  module has never declared — so a subject-access or erasure request runs
  straight past the stored addresses, device tokens and inbox rows. That is
  issue #244, open. See [`PRIVACY.md`](PRIVACY.md).

Put no more in a payload than the category needs. A lock screen is a public
surface.
