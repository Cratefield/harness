# The UI surface and its markup contract

ADR [0010](adr/0010-modules-declare-a-ui-surface.md) in practice. A module
declares a **surface** (actions and views, `Module::surface`); the harness
serves it as data at `GET /__surface` and, with `cratefield-ui` mounted,
renders it as HTML at `/ui`. This page is the contract a venture styles
against and a tool (or a prompt) generates for. Changing anything in the
tables below is a breaking change of the UI surface: bump `SURFACE_API`.

## Mounting

```rust
Harness::builder()
    // ...modules...
    .ui(cratefield_ui::Ui::new().theme_css("https://example.com/theme.css"))
```

Off unless called. Once mounted, modules default their landing redirects
(confirmed, expired, unsubscribed, status) to the `/ui` pages instead of
pages the venture site must provide; config keys and builder settings still
win.

| Route | Answer |
|---|---|
| `GET /ui/<module>/<action>` | Full page. For a `POST` action: the form; query parameters pre-fill and hide fields (`?product=kontinuum&ref=R1`). For a `GET` action: the action is dispatched with the same query and its answer rendered (a status page), or its redirect passed to the browser (a signed link). |
| `GET …?fragment=1` | The same markup without the page shell, for a static site to embed. No CSP header on a fragment. |
| `…&hide=<field,field>` | Renders the named pre-filled fields as hidden inputs instead of controls, on `GET` and on the re-render after a failed `POST`. |
| `POST /ui/<module>/<action>` | The form, as `application/x-www-form-urlencoded`. Becomes the JSON the module accepts and is dispatched **in-process** to `/v1/<module><path>` with the caller's request scope and `cf-connecting-ip`, `x-forwarded-for`, `authorization` forwarded. `2xx` renders the declared outcome; `3xx` is passed through; a `problem+json` re-renders the form with the error on its field (`422`); `429` and `5xx` become a form-level notice. `?fragment=1` applies. |
| `GET /ui/<module>/<action>/done`, `…/expired` | Landing pages for signed links. |
| `GET /ui/cf.css` | The base stylesheet. |
| `GET /ui/cf.js` | The embed, below. |

Admin actions are not served on the public routes; they answer `404` like
an unknown action there and live under `/ui/admin`, below.

## Sidecar modules

A module mounted as a sidecar (ADR 0009, `HARNESS_SIDECARS`) is not in the
build-time surface. `GET /__surface` and every `/ui` page read the surface
through a source that, when sidecars are mounted, fetches each sidecar's
own `/__surface` over its service binding on every call and merges the
**public** part in under the mount's name (a sidecar's admin routes take
its own token, which the host does not hold). No cache: a sidecar
redeploy is seen on the next request, and the binding runs on the same
thread. An unreachable sidecar contributes nothing and is logged; the
document still serves. With no sidecar mounted nothing is fetched and the
prerendered document answers, `ETag` and all. A sidecar module's form
posts through the same mount its API uses.

## Field rendering

Fields come from the action's input schema in **struct order**. Per field:

| Schema | Control |
|---|---|
| `x-cf-widget` set | That widget: `text`, `email`, `number`, `select`, `textarea`, `checkbox`, `hidden` |
| `x-cf-hidden: true`, or no scalar `type` (nested values) | Hidden: rendered only as `<input type="hidden">` when the page supplied a value |
| `enum` or `x-cf-options` | `<select>`, with an empty "Choose" option unless required and pre-filled |
| `type: boolean` | Checkbox |
| `type: integer` / `number` | `<input type="number">`; an unparsable value is forwarded as a string so the module's own validation answers |
| `format: email` | `<input type="email">` |
| anything else | `<input type="text">` |

`required` follows the schema's `required` list. `x-cf-label`,
`x-cf-placeholder` and `x-cf-help` are used verbatim; a missing label is
the humanized field name (`referral_code` → "Referral code"). A captcha
action renders the Turnstile widget when the `Captcha` port is configured
and `TURNSTILE_SITE_KEY` is set; its token is posted as `captchaToken` and
never re-posted after an error.

Error attribution: a problem's `detail` that starts with a field name
("email: …") or a slug that names one (`unknown-product`) lands on that
field, with the `field:` prefix dropped; anything else is a form-level
error above the fields.

## Markup contract

No shadow DOM, no inline styles, no ids except the `label`/control pair.
Every class starts with `cf-`; every element that maps to the surface
carries a `data-cf-*` attribute.

| Element | Classes | Attributes |
|---|---|---|
| `form` | `cf-form` | `data-cf-module`, `data-cf-action`, `method="post"`, `action="/ui/<module>/<action>"`, `novalidate` |
| form-level error `p` | `cf-error cf-error--form` | `role="alert"` |
| field wrapper `div` | `cf-field`, plus `cf-field--invalid`, `cf-field--captcha` | `data-cf-field` |
| `label` | `cf-label`, plus `cf-label--checkbox` | `for` |
| required marker `span` | `cf-required` | `aria-hidden` |
| control | `cf-input`, plus `cf-input--select`, `cf-input--textarea`, `cf-input--checkbox` | `id`, `name`, `required`, `placeholder`, `value` |
| help `p` | `cf-help` | |
| field error `p` | `cf-error` | `role="alert"` |
| Turnstile mount `div` | `cf-turnstile` | `data-sitekey` |
| actions row `div` | `cf-actions` | |
| submit `button` | `cf-submit` | `type="submit"` |
| notice `div` | `cf-notice`, plus `cf-notice--success`, `--warning`, `--error` | `data-cf-module`, `data-cf-action`, `role="status"` |
| notice parts | `cf-notice-title` (`h2`), `cf-notice-text` (`p`) | |
| status `dl` | `cf-status` | `data-cf-module`, `data-cf-action` |
| status row `div` | `cf-status-row` | `data-cf-field` |
| status parts | `cf-status-key` (`dt`), `cf-status-value` (`dd`) | |
| page | `cf-page` (`body`), `cf-main`, `cf-header`, `cf-venture`, `cf-title` | |

The snapshot `crates/ui/tests/snapshots/pages__waitlist_join_fragment.snap`
is this table rendered; it fails first when the contract changes.

## Styling

`cf.css` is under 6 KB (about 1.5 KB gzipped), sits entirely inside `@layer cf`, and uses only the
custom properties below. Any **unlayered** author rule beats it without
`!important`, whatever its specificity, because unlayered styles win over
layered ones. To restyle: set the properties on `:root`, add your own rules
against the classes, or leave `cf.css` out and write against the vocabulary
from scratch.

| Property | Default | Used for |
|---|---|---|
| `--cf-font` | system stack | Everything |
| `--cf-fg`, `--cf-bg` | near-black on white; inverted under `prefers-color-scheme: dark` | Text and page background |
| `--cf-muted` | grey | Help text, status keys, venture name |
| `--cf-border` | light grey | Inputs and notices |
| `--cf-accent`, `--cf-accent-fg` | blue on white | Submit button, focus ring, default notice edge |
| `--cf-error`, `--cf-success`, `--cf-warning` | red, green, amber | Errors, notice tones |
| `--cf-radius` | `6px` | Inputs, buttons, notices |
| `--cf-gap` | `1rem` | Vertical rhythm |
| `--cf-max-width` | `32rem` | Page column |

Full pages link `/ui/cf.css`, then the theme stylesheet from
`Ui::theme_css` if set, and carry a `Content-Security-Policy` that allows
only the API origin for styles (plus the theme's origin), no scripts except
Turnstile's when a widget is on the page, and `form-action 'self'`.

## `UiSpec`: copy, order and theme

Everything about the UI that is copy, layout or theme rather than code
lives in a `UiSpec`: JSON, schema at `crates/ui/schemas/ui-spec-v1.schema.json`
(generated from the Rust types; a test fails on drift, regenerate with
`UPDATE_SCHEMAS=1 cargo test -p cratefield-ui`). Per module a `title`; per
action `title`, `intro`, `submit`, `success`, per-field `label`,
`placeholder`, `help`, `hidden`, an `order`, and copy for the `done` and
`expired` landing pages; a `theme` of `--cf-*` token values and an
optional `css_url`. Unknown keys and unknown references (a module, action,
field or page that the surface does not have) are errors with their JSON
path, never ignored.

| Where | When it is checked |
|---|---|
| `Ui::from_spec(include_str!("../ui.json"))` in the venture's `harness.rs` | `Harness::build()`, alongside every other build error |
| `UI_SPEC` config value (the control plane, per venture, no rebuild) | The first request; a bad spec answers a problem naming the error on every `/ui` route until it is fixed, and replaces the built-in spec when valid |

The renderer applies it everywhere; the theme tokens are served as
`/ui/theme.css` (`:root { --cf-…: …; }`) and linked after `cf.css`, then the
spec's `css_url`. `GET /ui/spec.json` returns the effective spec and
`GET /__surface` carries the built-in one under `ui`. `docs/ui-llms.txt` is
the same contract written for a generator: what may change, what may not,
the tokens, the markup, and two worked examples.

## Admin pages

`/ui/admin` needs a session. `GET /ui/admin/login` takes the admin token
in a password field; a correct token (compared in constant time, rate
limited per IP when the `RateLimiter` port is configured) answers a `303`
to `/ui/admin` with a `cf_admin` cookie: `HttpOnly; Secure;
SameSite=Strict; Path=/ui/admin`, holding a `Signer`-signed session
(purpose `admin-session`, twelve hours, `kid`-rotated like every other
token). The token itself is never stored. Without a `Signer` or an
`ADMIN_TOKEN` the login page says admin is switched off, the same way the
admin routes are.

The session proves the token was presented once. On every admin dispatch
the harness attaches `Authorization: Bearer <ADMIN_TOKEN>` from its own
config, so the modules' `require_admin` sees the real credential. Dispatch
does not trust the surface to say who may run an action: before anything
is sent it re-checks any action that is admin-audience *or* served under
`/admin/` with the same `require_admin` the target route runs, so a
surface that arrives at runtime (a sidecar's, merged per request) cannot
misdeclare an admin path as public and be executed without the bearer.
Hiding an action from `/__surface` and from the public pages is
visibility, not authorization. Every admin `POST` must also carry an
`Origin` (or `Referer`) matching `Host`.

| Route | Answer |
|---|---|
| `GET /ui/admin` | Index: per module, its tables and its admin form actions. |
| `GET /ui/admin/<module>/<action>` | A `Table` view over the admin export named `action` (CSV parsed, columns from the view, `cf-table` markup), or the form of an admin `POST` action. |
| `POST /ui/admin/<module>/<action>` | An admin form dispatched as JSON; or a row action (an admin `DELETE` whose path parameter names a column): without `confirm=1` the confirm page, with it the `DELETE` and a `303` back to the table. Both are plain form posts. |
| `POST /ui/admin/logout` | Clears the cookie. |

Admin pages carry `Cache-Control: private, no-store` (a session-gated
response is never storable by a shared cache), `X-Frame-Options: DENY` and
the page CSP. Public rendered pages and fragments carry `no-store`: one
visitor's pre-filled values and dispatched results must not be served to
the next caller. The authenticated `/__surface` variant is likewise
`private, no-store` while the public one stays `no-cache`. Markup: `cf-nav`, `cf-nav-link`, `cf-logout`, `cf-table`,
`cf-table-head`, `cf-table-row`, `cf-table-cell`, `cf-table-actions`,
`cf-table-empty`, `cf-row-action`, `cf-submit--row`, `cf-submit--danger`,
`cf-cancel`, `cf-admin-index`, `cf-admin-module`, `cf-admin-links`,
`cf-admin-link`, and the `cf-form--confirm` notice.

This is the interim until an accounts module exists; the cookie scheme is
replaced then, not extended.

## The embed: `cf.js`

One dependency-free ES module, under 4 KB minified and gzipped (CI gate in
`tools/cfjs/size.mjs`), served at `/ui/cf.js`. It is an embed, not a
renderer: every byte of markup comes from the harness.

```html
<script type="module" src="https://api.example.com/ui/cf.js"></script>

<cf-form module="waitlist" action="join" product="kontinuum"></cf-form>
<cf-form module="email-signup" action="subscribe" source="footer"></cf-form>
<cf-status module="waitlist"></cf-status>
```

`<cf-form>` fetches `/ui/<module>/<action>?fragment=1` from the script's
own origin (or `base="…"`), inserts it into the light DOM, and turns the
submit into a `fetch` of the same `/ui` route, swapping the returned
fragment back in: the notice, or the form with its errors. Any other
attribute names a field: it is sent as `?field=value&hide=field`, so the
visitor sees it neither as a control nor as a choice. A Turnstile widget in
the fragment loads Turnstile's script once and renders. `<cf-status>` is a
`<cf-form>` whose action defaults to `status` and whose `token` comes from
the page URL. While loading, and if the fetch fails, the element holds a
plain link to the full `/ui` page.

Events on the element: `cf:loaded`, `cf:submitted` (`detail.status`),
`cf:error`. A redirect answer (a signed link) navigates the page.

The site's origin must be in the venture's `cors_origins`: fragments are
fetched cross-origin, and that is the same allowlist the API already needs.
`tools/cfjs/test.mjs` runs the embed in jsdom against `wrangler dev` in CI.

## Browser push: `cf.push` and the reference service worker

The second half of the embed (issue #183). It subscribes a browser to Web
Push and registers the subscription with
`cratefield-module-notifications`, which sends through
`cratefield-adapter-webpush`. [`NOTIFICATIONS.md`](NOTIFICATIONS.md) is the
server side — the transports, the wiring and the failure contract, with
[`PUSH-ENV.md`](PUSH-ENV.md) for the variables. This is the page's.

```html
<script>window.cf = { auth: () => session.accessToken };</script>
<script type="module" src="https://api.example.com/ui/cf.js"></script>

<cf-push label="Turn notifications on"></cf-push>
```

`<cf-push>` renders the button and the three states around it — every
string is an attribute (`label`, `off-label`, `on`, `intro`, `denied`,
`install`, `unsupported`, `error`), so the copy belongs to the page. It
emits `cf:push` (`detail.state`) and `cf:error`. The same thing by hand:

| Call | Does |
|---|---|
| `cf.push.supported()` | `{ supported: true }`, or `{ supported: false, reason }` — `insecure-context`, `ios-needs-homescreen`, `no-service-worker`, `no-push`, `no-notifications` |
| `cf.push.state()` | `granted` / `denied` / `default` / `unsupported` |
| `cf.push.subscribe({ swUrl, scope, appId, appVersion })` | Asks, subscribes, registers. Answers `{ id }` |
| `cf.push.unsubscribe()` | Both halves: the browser's subscription and the venture's row |
| `cf.push.sync()` | Re-registers the subscription the browser already holds. Never prompts |

### `cf.auth`, the one authenticated seam

`PUT /v1/notifications/subscriptions` is authenticated: the account comes
from a bearer token this venture's auth service signed, never from the
body. So `cf.auth` is the seam — an access token, or a function returning
one, which may be async. It is read once per request and never cached or
stored: refresh, storage and sign-out stay with the page, and the embed
holds no credential of its own. Without it, `subscribe()` throws rather
than sending a request whose only possible answer is a 401.

Cross-origin, that needs `PUT` and `Authorization` through CORS, which
the harness allows for every venture origin — with credentials **off**,
so no cookie ever rides along and the token is only ever one the page
deliberately handed over.

### The service worker

Notifications are shown by a service worker, and a worker may only be
registered from the origin of the page registering it — which is the
site, not the API. So `/ui/sw-push.js` is served to be **copied**:

```sh
curl https://api.example.com/ui/sw-push.js > /var/www/sw.js
```

`cf.push.subscribe()` registers `/sw.js` by default; `swUrl` and `scope`
override it. A venture that already has a worker pastes the listeners in
instead — they are independent of everything else a worker does. Serving
the copy from anywhere but the site root needs
`Service-Worker-Allowed: /` on it, which is what the harness sends for
its own copy.

The worker reads exactly the JSON the adapter sends: `title`, `body`,
`icon`, `url`, `tag`, `silent`, `data`. `notificationclick` focuses the
tab already showing the target, failing that navigates an open one, and
opens a window only when there is nothing to focus.

### The four traps

**Permission is asked on a gesture.** `subscribe()` calls
`Notification.requestPermission()` before its first `await`, so the click
that called it still counts as user activation. Calling `subscribe()` on
load prompts nobody and, in Safari, throws.

**`pushsubscriptionchange` must re-register.** A browser may replace a
subscription at any time; ignoring the event leaves every send going to an
endpoint that is gone, silently. The worker re-subscribes — the half only
it can do — and wakes any open page, whose `cf.push.sync()` does the
authenticated `PUT`. With no page open the next visit repairs it, and the
dead endpoint answers `410 Gone`, the one status that prunes the row.
Call `cf.push.sync()` on load for that reason.

**Unsubscribing has two halves.** `cf.push.unsubscribe()` deletes the
venture's row as well as the browser's subscription. It remembers the row
id in `localStorage`, and re-learns it with a `PUT` when storage was
cleared, so the row cannot be orphaned.

**A rotated VAPID key invalidates every subscription.** `subscribe()`
compares the key an existing subscription was made with against the one
the venture now serves and replaces it if they differ. Nothing about a
subscription made with a retired key looks wrong from the browser.

### Support

| Browser | Web Push | Notes |
|---|---|---|
| Chrome, Edge (desktop and Android) | yes | |
| Firefox (desktop and Android) | yes | |
| Safari, macOS 13+ | yes | An ordinary tab is enough |
| Safari, iOS/iPadOS 16.4+ | **installed web app only** | Add to Home Screen first; `manifest.json` with `"display": "standalone"`. `supported()` reports this as `ios-needs-homescreen`, not as a flat no |
| Any browser over plain `http` | no | Except `http://localhost`, which counts as a secure context |

`GET /v1/notifications/vapid-public-key` serves the application server
key, and is the one route in that module with no token — it is the public
half of a pair, handed to every browser that subscribes. A venture that
wired no VAPID key answers `404 webpush-not-configured`, and `<cf-push>`
renders its `error` copy rather than a button that cannot work.

Verification: `tools/cfjs/push.mjs` runs the client against stubbed push
APIs and `tools/cfjs/sw.mjs` runs the worker in a fake
`ServiceWorkerGlobalScope`, both in CI. Real browsers delivering real
pushes are the vendor-live leg, issue #186.

## Cost

Measured on the native router in release mode
(`cargo test -p cratefield-ui --release --test pages render_timing --
--ignored --nocapture`, 2026-09-07, M-series laptop): a full page
**6.7 µs**, a fragment **5.8 µs**, through the whole router including the
request-id and CORS layers. Under `wrangler dev` the round trip is about
3 ms, which is the process boundary, not the render.

## `<cf-notifications>` — the in-app notification centre

A bell with an unread count, and a panel listing this account's inbox
newest first (issue #188). It reads the routes `cratefield-module-notifications`
serves, so a venture that mounts that module gets the widget by adding one
element.

```html
<cf-notifications page-size="10" empty="Nothing here yet."></cf-notifications>
```

| Attribute | Meaning |
|---|---|
| `page-size` | Rows per page (default 20; the API caps at 100) |
| `empty` | What an empty inbox says |
| `account` | The account id, for the Realtime room. Optional |

### Auth

Every route behind this widget takes a bearer token, so the page must set
`cf.auth` — a token, or a function returning one:

```js
cf.auth = () => myApp.accessToken();
```

It is read per request and never cached or stored, so a page that rotates
its token needs to do nothing here. With no token the widget refuses
rather than fetching a 401.

### What it does on its own

- Reads the unread count on connect, then every 60 s **while the tab is
  visible**. A hidden tab polls nothing: a background request nobody can
  see is one nobody asked for. The count is re-read on the way back.
- Subscribes to `notifications:<account>` when the page exposes a Realtime
  client, so the count moves without waiting for a poll.
- Marks an item read when it is clicked, then follows its `url`.
- Leaves nothing behind when the element is removed: the poll and the
  `visibilitychange` listener that drives it both go with it.

### Accessibility

The bell is a `<button aria-haspopup="dialog">` whose accessible name
carries the count, the count itself is `aria-live="polite"`, and the panel
is a `<dialog>`: Escape closes it and focus returns to the bell however it
closed. Nothing sets `display` on the panel — an author rule beats the
UA's own hiding, and a closed dialog would stay painted.

### The same contract, for native apps

A native app does not use this widget but should behave the same way. The
five routes, the cursor rule and the Realtime room name are in
`docs/NOTIFICATIONS.md`; the sequence a push tap follows is: `POST
/v1/notifications/{id}/read`, then open the notification's `url`.
