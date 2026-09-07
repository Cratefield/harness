# The UI surface and its markup contract

ADR [0010](adr/0010-modules-declare-a-ui-surface.md) in practice. A module
declares a **surface** (actions and views, `Module::surface`); the harness
serves it as data at `GET /__surface` and, with `factory0-ui` mounted,
renders it as HTML at `/ui`. This page is the contract a venture styles
against and a tool (or a prompt) generates for. Changing anything in the
tables below is a breaking change of the UI surface: bump `SURFACE_API`.

## Mounting

```rust
Harness::builder()
    // ...modules...
    .ui(factory0_ui::Ui::new().theme_css("https://example.com/theme.css"))
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

Admin actions are not served by `/ui` until the admin UI (issue #74); they
answer `404` like an unknown action.

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

`cf.css` is under 4 KB, sits entirely inside `@layer cf`, and uses only the
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

## Cost

Measured on the native router in release mode
(`cargo test -p factory0-ui --release --test pages render_timing --
--ignored --nocapture`, 2026-09-07, M-series laptop): a full page
**6.7 µs**, a fragment **5.8 µs**, through the whole router including the
request-id and CORS layers. Under `wrangler dev` the round trip is about
3 ms, which is the process boundary, not the render.
