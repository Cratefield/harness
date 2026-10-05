# venture (example)

The smallest complete Factory Zero venture: `cratefield-core` +
`cratefield-runtime-cloudflare`, modules (`sample` row round-trip,
`email-signup`, `waitlist`, `orgs` — organizations, memberships, roles
and invitations, and `crm` — contacts, organizations and tags), one Worker,
one local D1.

`orgs` is mounted with the roles `owner`, `manager`, `staff` and a staff
organization; `src/admin.rs` adds `GET /v1/admin/ping` behind its staff guard
(a staff member, or a machine holding `ADMIN_TOKEN`).

`crm` is mounted with its defaults — it takes no settings, and every route
it declares is an admin action behind the same `ADMIN_TOKEN`.

CI builds it to wasm with `worker-build --release` so a native-only
dependency can never slip into a module, then boots it under
`wrangler dev --local` and curls `/__health`, `/__ready` and the sample
round-trip.

```text
bunx wrangler d1 migrations apply venture-example --local
printf 'HARNESS_SECRET=%s\n' "$(openssl rand -hex 32)" > .dev.vars
bunx wrangler dev --local --port 8792
curl -fsS http://127.0.0.1:8792/__health
curl -fsS http://127.0.0.1:8792/__ready
```

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full walkthrough and
[docs/VENTURE-GUIDE.md](../../docs/VENTURE-GUIDE.md) for the init-to-
production path this example mirrors. The guide-built module
[`cratefield-module-hello`](../module-hello/) is its documentation-focused
sibling.

## The UI

The example mounts `cratefield_ui::Ui`, so every module's forms are served
from the Worker (`docs/UI.md`):

```text
http://127.0.0.1:8787/ui/waitlist/join
http://127.0.0.1:8787/ui/email-signup/subscribe
```

and a static site on an allowed origin embeds them with one script
(`site/` is one, restyled with `site.css`; serve it next to the API with
`python3 -m http.server 8788 --directory site` and open it):

```html
<script type="module" src="http://127.0.0.1:8787/ui/cf.js"></script>
<cf-form module="waitlist" action="join" product="kontinuum"></cf-form>
```
