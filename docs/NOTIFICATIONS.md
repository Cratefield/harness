# Notifications: the push environment

Every environment variable the push adapters read, generated from
`cratefield-push-wiring`'s `PUSH_ENV` table by `cargo run -p
cratefield-push-wiring --example notifications-doc` and checked in CI for
drift (issue #191).

One function reads these names — `build_push` — so no two callers can
drift apart on a variable name. `serve()` reaches it through
`push_from_env()` on either runtime, and `fz doctor` through
`inspect_push`; `fz push` (issue #184) calls it directly when it lands.
`crates/cli-acceptance/tests/push_env_guard.rs` fails the build if any
other Rust source names one of them.

Keys are read through the `Config` port, so on Workers a secret and a
`[vars]` entry both work (a secret wins), and natively they are process
environment variables. A variable set to the empty string counts as unset.

## APNs (`apns`)

| Variable | Required | Secret | Purpose |
|---|---|---|---|
| `APNS_KEY_P8` | yes | yes | The `.p8` provider key from the Apple developer portal, PKCS#8 PEM, whole. |
| `APNS_KEY_ID` | yes | no | The key's 10-character id (the `.p8` filename suffix). |
| `APNS_TEAM_ID` | yes | no | The 10-character Apple team id; the provider JWT's issuer. |
| `APNS_TOPIC` | yes | no | The app's bundle id, sent as `apns-topic`. |
| `APNS_HOST` | no | no | `production` or `sandbox`. Optional; defaults to `sandbox`, because a development build's token is a sandbox token and sending it to production fails every time. |

## FCM (`fcm`)

| Variable | Required | Secret | Purpose |
|---|---|---|---|
| `FCM_SERVICE_ACCOUNT_JSON` | yes | yes | The Google service-account JSON Firebase hands over, whole. `client_email`, `private_key`, `project_id` and `token_uri` are read out of it, so there is no second variable to keep in step. |

## Web Push (`web_push`)

| Variable | Required | Secret | Purpose |
|---|---|---|---|
| `VAPID_PRIVATE_KEY` | yes | yes | The VAPID private key: a PKCS#8 PEM, or the bare 32-byte P-256 scalar base64url. The public key is derived, never configured. |
| `VAPID_SUBJECT` | yes | no | RFC 8292 §2.1 `sub`: a `mailto:` or `https:` contact URI a push service can reach the operator at. |

## Verdicts

`build_push` returns a `PushWiring` report next to the router, and each
runtime logs it once at cold start. Per transport:

| Verdict | When | Consequence |
|---|---|---|
| `configured` | every required variable is set and the adapter accepted them | the transport is routed |
| `absent` | not one of its variables is set | the transport is not routed; its recipients answer `NotConfigured`. A choice, not a defect |
| `partial` | some of its variables are set and some are not | the transport is **not** routed. An error in production, a warning elsewhere |
| `invalid` | all are set and the adapter refused them | the transport is **not** routed. An error in production, a warning elsewhere |

Partial is the case this exists for: a venture that meant to enable FCM and
mistyped one variable must not boot into a state where every Android send
silently answers `NotConfigured`. In production that fails `fz doctor` and
is logged at error; in development and staging it is a warning, because
wiring a transport one variable at a time is what development looks like.

The report holds variable **names** and verdicts only, never a value, so it
is safe to log whole.
