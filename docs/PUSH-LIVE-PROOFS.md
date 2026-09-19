# Live push proofs

Runbook for issue #186. Four push transports need a vendor account, a
physical phone, or a real browser, and CI cannot reach any of those, so
their proofs are run by a person. This file is the execution half of that
issue: what to set up, the exact command to run, what the output must say
to count, and a table to fill in as you go. **Nothing here runs in CI, and
a green pipeline proves none of it.**

[NOTIFICATIONS.md](NOTIFICATIONS.md) explains what each transport is and
which one reaches which device; [PUSH-ENV.md](PUSH-ENV.md) has the exact
shape of every variable below. Budget about an hour per transport.

## Prepare the CLI once

`fz push send` needs the `push-send` cargo feature, which pulls in the
native runtime's HTTP client:

```sh
cargo install cratefield-cli --features push-send
```

The Docker image has it built in. Without the feature the command is a
stub that refuses with the same instruction — every other `fz push`
command, and `--dry-run`, work either way. Do not add the feature to a
venture's own dependency: it would drag the native runtime into the
venture's wasm Worker build.

Before each send, check the wiring:

```sh
fz doctor
```

The push rules only speak up when a transport is mis-wired, which is the
cheap catch for a mis-pasted key. A half-wired transport produces `… is
partially configured: APNS_KEY_P8 is set; APNS_KEY_ID is not. …` — which
variables are set, which are missing, and that every send over it would
answer `NotConfigured`; refused credentials produce `… is configured but
its credentials were refused: …`. Below production these are `fz:
warning:` lines on stderr; in production they fail the doctor. A
transport that is fully wired — or deliberately untouched — prints
nothing, so silence is good. The one-word verdicts themselves
(`configured`, `absent`, `partial`, `invalid`) are not doctor output:
they are what the `wiring:` line of a `fz push send` report shows. Either
way, fix a partial or refused transport before sending: it is left
unrouted, so the transport sends nothing and only says so afterwards.

A send report is three header lines — the transport, the recipient (a
fingerprint — never the token or endpoint itself) and the wiring verdict
(`configured`, `absent`, `partial` or `invalid`) — and then the
`result:` block, which is the one that matters:

- `result: DELIVERED` — the push service accepted the notification; when
  the service named an id (APNs does) it follows on the next line, and
  otherwise the line says so. The positive case.
- `result: FAILED` — the adapter reached the provider and was refused:
  the provider's reason, with this send's credential redacted, plus a
  one-line instruction. The negative case lives here.
- `result: NOT SENT` — nothing left the process; the `wiring:` verdict
  above says why.

One naming trap before you start. **`Unregistered` is not an outcome the
CLI ever prints.** `PushOutcome` is `Delivered` or `NotConfigured`;
`Unregistered` is a `PushError` variant, and it surfaces through the
`FAILED` line, rendered as `device token is no longer registered; delete
it`. So the evidence to record is: the `result: DELIVERED` line for a
positive case, and the whole `result: FAILED` block — error line plus the
advice line under it — for a negative one. Paste the whole report into
the issue either way.

## APNs

`cratefield-adapter-apns`. Sandbox first; production once a TestFlight
build exists.

### Prerequisites

- An Apple Developer Program team.
- A `.p8` key created with the Apple Push Notifications service (APNs)
  capability enabled. Note its **key id** and your **team id**.
- The app's bundle id — that string is the APNs topic.
- A debug build of the app on a physical device that logs its device
  token (simulators do not receive push). Capture the token before
  uninstalling anything; it survives the app. If the venture has no iOS
  app yet, any minimal app with the Push Notifications capability that
  registers for remote notifications and logs its token will do — the
  proof is of the adapter and the key, not of the app.

### Secrets

```sh
export APNS_KEY_P8="$(cat AuthKey_XXXXXXXXXX.p8)"   # the whole PEM
export APNS_KEY_ID=XXXXXXXXXX
export APNS_TEAM_ID=XXXXXXXXXX
export APNS_TOPIC=com.example.app
fz doctor
```

On Workers the same four go in with `wrangler secret put NAME --env
production` (the pattern is [VENTURE-GUIDE.md](VENTURE-GUIDE.md), section
6b); locally, process env or `.dev.vars`.

`APNS_HOST` selects `production` or `sandbox` and **defaults to
`sandbox`**. The sandbox leg below needs no override. The production leg
does — a development token sent to production fails every send, which is
why the default is the forgiving direction.

### Positive

```sh
fz push send --transport apns --recipient <device-token> \
  --title "proof" --body "APNs sandbox"
```

Expect the notification on the device and:

```
result: DELIVERED
  the push service accepted it: <apns-id>
```

APNs names the notification with its `apns-id` header on 200, and the
report shows it. Record that id.

### Negative

Uninstall the app from the device, then send again with the same token.
APNs answers 410 GONE, which the adapter maps to `PushError::Unregistered`:

```
result: FAILED
  device token is no longer registered; delete it
  this recipient is gone: …
```

That error line is the proof. A `FAILED` whose error says `provider token
rejected` is different: the `.p8`, key id or team id is wrong, and no
proof has been attempted.

Production leg: when a TestFlight build exists, repeat both sends with
`APNS_HOST=production` and that build's token, and add rows to the table.

## FCM

`cratefield-adapter-fcm`. Uses the v1 HTTP API, not the legacy one.

### Prerequisites

- A Firebase project — the free tier is enough — with the **Cloud
  Messaging API (v1)** enabled.
- A service account on that project. The adapter mints an OAuth token
  with the scope `https://www.googleapis.com/auth/firebase.messaging`;
  grant the service account whatever role currently confers that scope.
  **Read the role's current name off the IAM console** rather than
  copying one out of an older runbook — Google renames predefined roles,
  and the scope is the stable thing. Then create a JSON key for it — in
  the console, the service account's **Keys** tab, **Add key**, **JSON**
  — and keep the downloaded file as the `service-account.json` the next
  step reads.
- A device. The venture's own Android app does not exist yet, so build
  Firebase's quickstart-android messaging sample (Apache-2.0) with this
  project's `google-services.json`, on a real phone or an emulator image
  with Play services. The token it logs is the registration token.

### Secrets

```sh
export FCM_SERVICE_ACCOUNT_JSON="$(cat service-account.json)"
fz doctor
```

### Positive

```sh
fz push send --transport fcm --recipient <registration-token> \
  --title "proof" --body "FCM v1"
```

Expect the notification on the device and `result: DELIVERED`.

### Negative

Uninstall the app, send again with the same token. **The proof is the
JSON error code in the response body, not the HTTP status**: `map_error`
prunes only when the body carries `UNREGISTERED`. Expect:

```
result: FAILED
  device token is no longer registered; delete it
  this recipient is gone: …
```

A bare 404 with no `UNREGISTERED` code is a deviation, not a pass — see
[What counts as a deviation](#what-counts-as-a-deviation).

## Web Push

Three browsers, three push services, one adapter
(`cratefield-adapter-webpush`). CI already runs a Web Push leg against a
real ntfy server (job `webpush-ntfy`, test `ntfy_live`), but that leg
proves delivery and decryption only: ntfy signals "nobody is listening"
with 507, not 410, and no real push service produces a 410 on demand, so
the status mappings stay unproven there. That is what this section adds,
and the browser matrix matters because each browser's endpoint belongs to
a different push service with its own habits.

### Prerequisites

- A VAPID key pair, generated once:

  ```sh
  fz push vapid keygen --file vapid.key
  ```

  Configure the file's contents as `VAPID_PRIVATE_KEY` and a
  `mailto:` or `https:` contact as `VAPID_SUBJECT` (see
  [PUSH-ENV.md](PUSH-ENV.md)). Overwriting the key with `--force` is a
  rotation and kills every existing subscription — don't, mid-proof.
- The venture page reachable where you will subscribe: `wrangler dev`
  behind an HTTPS tunnel, or plain `localhost`, which browsers treat as a
  secure context. Subscribe with `cf.push.subscribe()`.
- Chrome, Firefox, and Safari on iOS 16.4 or later added to the home
  screen as an installed PWA — on iOS, web push does not exist for a
  page that is not installed.

### Positive, per browser

Subscribe in a browser, then send exactly the subscription JSON that
browser produced — nested (`{"endpoint":…,"keys":{…}}`) or flattened,
both are accepted:

```sh
fz push send --transport web-push --recipient '<subscription json>' \
  --title "proof" --body "Chrome"
```

`fz push inspect-subscription '<subscription json>'` validates the
subscription first and prints the `aud` the adapter will sign — worth
running when a send fails with a VAPID 401. Record the `aud` per browser:
**the endpoint's origin is what VAPID signs for**, and it is the one
thing that differs across the three:

| Browser | Endpoint origin (the `aud` you should record) |
| :--- | :--- |
| Chrome | Google's push service (`fcm.googleapis.com`) |
| Firefox | Mozilla autopush (`updates.push.services.mozilla.com`) |
| Safari, iOS 16.4+ PWA | Apple's push service |

Expect `result: DELIVERED` and the notification in each browser.

### Negative, per browser

Unsubscribe in that browser, send the same subscription again, and
**record the HTTP status the vendor actually returned**, from the error
line of the report:

- A vendor answering **410 GONE** produces the pass:
  `result: FAILED` with `device token is no longer registered; delete
  it`.
- A vendor answering **404** produces `push failed, retryable: … (a 404
  is not a dead subscription; only 410 is)`. That is the adapter's
  deliberate mapping, not a malfunction in your run: RFC 8030 defines
  only 410 as unambiguously gone, while 404 is also what a proxy that
  lost its routes, an edited ingress rule or a moved reverse proxy
  answers for *every* path — pruning on it could delete a venture's
  whole Web Push register, and a subscription can only be recreated by
  the user's browser. A vendor that returns 404 (or 403) for a genuinely
  gone subscription is precisely the deviation issue #186's second
  criterion wants filed — record it and file it (below), it is not a
  failed proof.

## UnifiedPush

Google-free Android: ntfy as the distributor, delivered through the same
Web Push adapter.

### Prerequisites

- An Android phone with **no Play services**.
- [ntfy](https://f-droid.org/packages/io.heckel.ntfy/) from F-Droid;
  ntfy itself is the distributor (the UP example app works too).
- The venture page as in the Web Push section, with ntfy installed.
  Subscribing through it yields a UnifiedPush endpoint, which is an
  ordinary Web Push subscription as far as everything downstream is
  concerned.

### Positive

Subscribe on the page with ntfy as distributor, then send the endpoint's
subscription JSON through the Web Push transport, exactly as above:

```sh
fz push send --transport web-push --recipient '<subscription json>' \
  --title "proof" --body "no Play services"
```

Expect `result: DELIVERED` and the notification arriving on the phone
with no Play services involved.

### Negative

Remove the subscriber (uninstall ntfy, or drop the topic) and send again.
ntfy answers **507** — it refuses to store a notification for a topic
with no active subscriber when `visitor-subscriber-rate-limiting` is on,
as the public `ntfy.sh` has it — and the adapter maps that to
`Rejected`:

```
result: FAILED
  push rejected: … (a push service refusing storage is an operator state, not load: …)
```

**There is no `Unregistered` proof on this row, and that is a known
limit, not a deviation**: ntfy does not answer 410 for an empty topic,
which is why the CI leg's test says explicitly that it does not prove the
mapping either. Record the 507 as the negative-case outcome.

## Results

Fill one row per proof run, in the issue. The columns are issue #186's
first acceptance criterion; versions below are the adapters at the time
of writing.

| Row | Adapter crate (version) | Date | Positive outcome | Negative-case outcome |
| :--- | :--- | :--- | :--- | :--- |
| APNs, sandbox | cratefield-adapter-apns 0.1.4 | | | |
| APNs, production | cratefield-adapter-apns 0.1.4 | | | |
| FCM | cratefield-adapter-fcm 0.1.3 | | | |
| Web Push — Chrome | cratefield-adapter-webpush 0.1.3 | | | |
| Web Push — Firefox | cratefield-adapter-webpush 0.1.3 | | | |
| Web Push — Safari, iOS 16.4+ PWA | cratefield-adapter-webpush 0.1.3 | | | |
| UnifiedPush | cratefield-adapter-webpush 0.1.3 | | | |

In the outcome columns, paste the `result:` line and the error line under
it, joined with `<br>` — a table cell cannot contain a raw newline, and a
line that breaks the row breaks the table — not a paraphrase. Anything
beyond those two lines goes in prose beneath the table.

## What counts as a deviation

Issue #186's second criterion: a place where a vendor's real behaviour
and the adapter's mapping disagree. The ones this runbook can surface:

- A Web Push push service answering 404 or 403 for a subscription that is
  genuinely gone — the adapter maps only 410, on purpose.
- FCM answering a bare 404 with no `UNREGISTERED` code for an
  uninstalled app — the adapter deliberately does not prune on the
  status alone, because the same 404 means a project that does not exist
  or a token from the wrong project.
- APNs answering anything other than 410 for an uninstalled app's token.

A deviation is not a failed proof and usually not a failed send. Record
what the vendor answered in the table, then file it against the adapter
crate (`crates/adapter-apns`, `crates/adapter-fcm`,
`crates/adapter-webpush`) quoting the error line — the mapping, not the
runbook, is what changes.

## When the table is done

The status table in [NOTIFICATIONS.md](NOTIFICATIONS.md) flips only when
all four transports are proven — when issue #186 closes, and not before.
Until then it keeps saying the live proofs are open, whatever this file's
table records.
