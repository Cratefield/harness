# cratefield-auth-worker

The deployable auth Worker: every auth module (`auth-core`, passkeys, OIDC
for Google and Apple, password, magic link, Meta) composed into one harness
venture, served on Cloudflare Workers with one D1 database.

It is deployed as **one branded instance per app** (issue #777), never as a
shared service. Each instance lives on the app's own domain
(`auth.<app-domain>`), with its own D1, secrets, passkey relying party,
cookies, sender and login copy. The configuration of each instance the
repository knows about is in [`instances/<app>/`](../../instances), and
[`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md) is
the runbook for adding one.

Nothing in `src/` names an app: `tests/literal_scope.rs` fails the build if
an app's name or domain appears there.

## Configuration

Every value is a Worker variable (`[vars]` in the instance's
`wrangler.toml`) or, where marked, a secret (`wrangler secret put`). The
whole set is validated together at boot and every problem is reported at
once; an invalid instance answers 500 and logs why, once.

### Identity (required)

| Key | Meaning |
|---|---|
| `AUTH_PUBLIC_URL` | The instance's origin, e.g. `https://auth.example.com`. Issuer, problem-type base, Turnstile hostname and default sender derive from it |
| `AUTH_VENTURE_NAME` | Kebab-case id, e.g. `example-auth` |
| `AUTH_CORS_ORIGINS` | The app's browser origins, comma-separated, exact. `*` is refused |
| `AUTH_BRAND_NAME` | Display name on every page and in every mail subject |

A missing one is refused with a message naming it. There is no fallback to
any other app's value.

### Branding (optional)

| Key | Meaning | When unset |
|---|---|---|
| `AUTH_BRAND_LOGO_URL` | Absolute `https` image URL | no logo |
| `AUTH_BRAND_ACCENT` | `#rgb` or `#rrggbb` | a neutral blue |
| `AUTH_BRAND_SUPPORT_EMAIL` | Help address, linked in the footer | no link |
| `AUTH_BRAND_FOOTER` | Footer line | `<host> · <display name>` |
| `AUTH_BRAND_PRIVACY_URL` | Privacy policy (Meta's app review needs it) | no link |
| `AUTH_BRAND_TERMS_URL` | Terms of service | no link |
| `AUTH_PASSKEYS_RP_NAME` | Name an authenticator shows | `AUTH_BRAND_NAME` |

### Page theme (optional, issue #840)

The hosted pages (the sign-in chooser, the magic-link form, confirm and
expired pages, sign-out) render through one shell themed by these keys.
An instance that sets none keeps the neutral dark pages. Each value is
validated at boot, because each is written into the pages' `<style>`.

| Key | Meaning | When unset |
|---|---|---|
| `AUTH_BRAND_BACKGROUND` | `#rgb`/`#rrggbb` page background | neutral near-black |
| `AUTH_BRAND_TEXT` | `#rgb`/`#rrggbb` text colour | neutral off-white |
| `AUTH_BRAND_ACCENT_TEXT` | Label colour on accent-filled buttons | black or white, whichever reads on the accent |
| `AUTH_BRAND_DANGER` | Field errors and error notices | a soft red |
| `AUTH_BRAND_SCHEME` | `dark` or `light` | from the background's lightness |
| `AUTH_BRAND_RADIUS` | Corner radius, `0` (square) to `32` pixels | `10` |
| `AUTH_BRAND_FONT_BODY` | Body font stack | the system stack |
| `AUTH_BRAND_FONT_DISPLAY` | Heading font stack | the body stack |
| `AUTH_BRAND_FONT_MONO` | Label and code font stack | the system monospace stack |
| `AUTH_BRAND_FONT_CSS_URL` | `https` stylesheet that loads those fonts (Google Fonts, say) | no web fonts |

Surfaces, borders and muted text are mixed from the background and text
colours, so a two-colour brand needs only those two. The sign-in mail is
themed separately by `MAIL_THEME` (see
[`cratefield-mail-templates`](../mail-templates)), which can give the logo
row a dark `header_bg` band and the button the accent.

Every hosted page answers with `Referrer-Policy: same-origin`, not the
`no-referrer` the harness stamps on `/v1/*`: under `no-referrer` a browser
sends `Origin: null` on the page's own form POST, and the login-CSRF guard
refuses that from any client that sends no `Sec-Fetch-Site` (Gmail's in-app
browser, other webviews, older Safari). `same-origin` still sends nothing
to any other site.

### Mail

Login mail (magic links, password verification and reset) goes through the
harness `Mailer` port. Which adapter backs it is configuration:

| `AUTH_MAILER` | Adapter | Needs |
|---|---|---|
| `owlpost` (recommended) | [`cratefield-adapter-owlpost`](../adapter-owlpost) | secret `OWLPOST_API_KEY`; optional `OWLPOST_BASE_URL` for a self-hosted Owlpost |
| `resend` | [`cratefield-adapter-resend`](../adapter-resend) | secret `RESEND_API_KEY` |
| `none` | captures nothing, sends nothing | refused when `ENV=production` |
| unset | the provider whose key is present, Owlpost first | both keys present is refused as ambiguous; no key in production is refused |

`MAIL_FROM` (default `no-reply@<host of AUTH_PUBLIC_URL>`) and
`MAIL_REPLY_TO` are the adapter-level sender. The magic-link module sends
from its own `AUTH_MAGIC_LINK_MAIL_FROM`, which wins on the wire. The sender
domain must be verified with the provider (for Owlpost, the instance's
sending domain).

### Everything else

| Key | Meaning |
|---|---|
| `ENV` | `development`, `staging` or `production`; production turns on the harness's production gates |
| `AUTH_TURNSTILE_HOSTNAME` | Hostname the Turnstile verdict must name; defaults to the instance's host. Secret `TURNSTILE_SECRET` turns the captcha on |
| `AUTH_PROBLEM_BASE` | Overrides the problem-type base (default `<AUTH_PUBLIC_URL>/problems/`, issue #557) |
| `AUTH_CORE_ISSUER` | Must equal `AUTH_PUBLIC_URL` when set |
| `AUTH_CORE_*`, `AUTH_OIDC_*`, `AUTH_PASSKEYS_*`, `AUTH_PASSWORD_*`, `AUTH_MAGIC_LINK_*`, `AUTH_META_*` | Each module's own keys; see its README |

Secrets every instance needs: `HARNESS_SECRET` (and
`HARNESS_SECRET_PREVIOUS` during rotation), the token signing keys (`AUTH_CORE_SIGNING_KEYS`, with `AUTH_CORE_SIGNING_KEY_ACTIVE` naming the active one), the mail
provider key, `TURNSTILE_SECRET`, and the client secrets of whichever OIDC
providers it enables.

## Wrapping it

A venture that wants extra templates or modules depends on this crate with
`default-features = false` (so the `entry` feature's `fetch`/`scheduled`
exports do not collide with its own), builds `AuthWorker::builder()`, and
serves through `serve_request`.

---

MIT. Part of the [Cratefield harness](https://github.com/Cratefield/harness).
