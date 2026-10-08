# fz-module-linkedin

Runs a LinkedIn Company Page from the Cratefield harness: connect a page once
over OAuth, then create, schedule, edit and delete posts, upload media, and
address showcase pages. Private (`fz-*`, never published, pinned git
dependency, harness ADR 0005) because it holds long-lived credentials for our
own pages.

Mounted at `/v1/linkedin`. Everything except the OAuth callback sits under
`/v1/linkedin/admin/*` behind `ADMIN_TOKEN`.

## Routes

| Route | What it does |
|---|---|
| `POST /v1/linkedin/admin/connect` | Returns an authorize URL and a single-use state |
| `GET /v1/linkedin/callback` | Public. Spends the state, exchanges the code, stores sealed tokens |
| `GET /v1/linkedin/admin/status` | Account, scopes, both expiries, today's request budget |
| `DELETE /v1/linkedin/admin/account` | Forgets the tokens; keeps the post history |
| `POST /v1/linkedin/admin/pages/sync` | Refreshes the page directory |
| `GET /v1/linkedin/admin/pages` | Pages and showcases, with roles. `?kind=showcase` filters |
| `POST /v1/linkedin/admin/pages/{org}/images` | Raw image body, returns an asset |
| `GET /v1/linkedin/admin/assets/{id}` | Asset upload status |
| `POST /v1/linkedin/admin/pages/{org}/posts` | Creates or schedules a post. Optional `source`: [fact check](#fact-check) first |
| `GET /v1/linkedin/admin/posts` | Local post records. `?page=`, `?state=`, `?limit=` |
| `PATCH /v1/linkedin/admin/posts/{id}` | Commentary, CTA label, landing page. Optional `source`: [fact check](#fact-check) first |
| `DELETE /v1/linkedin/admin/posts/{id}` | Deletes on LinkedIn, then locally |

`{org}` accepts a bare organization id, `urn:li:organization:{id}`, or the
legacy `urn:li:organizationBrand:{id}`; all three name the same page.

## Fact check

An agent drafting a post from release notes or an announcement can send that
text as `source` beside the commentary, on a create or an edit, and the module
checks the commentary kept its facts before anything is created, scheduled or
edited ([`cratefield-text-guard`](../text-guard)):

```http
POST /v1/linkedin/admin/pages/2414183/posts
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json

{
  "commentary": "Cold starts are down 38% in release 2.4, thanks to @[DevTestCo](urn:li:organization:2414183). https://example.com/releases/v2\\_4 {hashtag|\\#|launch}",
  "commentary_format": "little",
  "source": "Release 2.4 ships today: cold starts down 38%, with @[DevTestCo](urn:li:organization:2414183). Notes: https://example.com/releases/v2_4 #launch",
  "idempotency_key": "release-2.4"
}
```

```http
PATCH /v1/linkedin/admin/posts/{id}
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json

{ "commentary": "Release 2.4: cold starts down 38%.", "source": "Release 2.4 ships today: cold starts down 38%." }
```

What must survive from the source: names, numbers, quotes, code, links and
hashtags (the guard's built-in kinds), plus LinkedIn's mentions
(`@[Name](urn:li:organization:123)`, `urn:li:person:…`) as **mentions** —
same name, same URN, unescaped. Both texts are read as a person sees the post:
`little` backslash escapes count as the character they escape, and a hashtag
template `{hashtag|\#|launch}` reads as `#launch`, so a plain `#launch` in
release notes is kept by a template in the post and the other way round. The
digits inside a URN are never an introduced number.

- **Fails**: `422` `linkedin-fact-check-failed`, and nothing is stored or
  sent. `missing` lists each span of the source the commentary dropped or
  altered, `introduced` each number it made up:

  ```json
  {
    "type": ".../linkedin-fact-check-failed",
    "status": 422,
    "detail": "the commentary dropped or altered 1 protected span(s) of the source and introduced 1 number(s); nothing was created, scheduled or edited",
    "missing": [{ "kind": "number", "text": "38%" }],
    "introduced": [{ "kind": "number", "text": "40%" }]
  }
  ```

  `kind` is `name`, `number`, `quote`, `code`, `url`, `hashtag` or
  `mention`.
- **Passes**: the usual answer plus `fact_check`: the source's locked spans
  and a word diff from source to commentary (`removed`, `added`, `same`, and
  `locked` for a locked span that came through unchanged):

  ```json
  "fact_check": {
    "ok": true,
    "locks": [{ "kind": "number", "text": "2.4" }, { "kind": "mention", "text": "@[DevTestCo](urn:li:organization:2414183)" }],
    "diff": [{ "op": "removed", "text": "Release " }, { "op": "same", "text": "..." }, { "op": "locked", "text": "38%" }]
  }
  ```

The source is checked and dropped: it is never stored. On an edit, `source`
needs `commentary` beside it and is never sent to LinkedIn. Without `source`,
a create or an edit answers exactly as before, with no `fact_check` member.

## Configuration

| Key | Required | Default |
|---|---|---|
| `LINKEDIN_CLIENT_ID` | yes | |
| `LINKEDIN_CLIENT_SECRET` | yes (Worker secret) | |
| `LINKEDIN_TOKEN_KEY` | yes (Worker secret) | 32 random bytes, base64 |
| `LINKEDIN_TOKEN_KEY_ID` | no | `1` |
| `LINKEDIN_REDIRECT_URI` | no | `https://api.<venture domain>/v1/linkedin/callback` |
| `LINKEDIN_API_VERSION` | no | `202608` |
| `LINKEDIN_DEFAULT_VISIBILITY` | no | `PUBLIC` |
| `LINKEDIN_REFRESH_LEAD_DAYS` | no | `7` |
| `LINKEDIN_MAX_IMAGE_BYTES` | no | `8388608` |
| `LINKEDIN_PUBLISH_LEASE_SECS` | no | `600` |

Scopes are **compiled in**, not configured: `rw_organization_admin`,
`r_organization_admin`, `r_organization_social`, `w_organization_social`.
Changing the set invalidates every token LinkedIn has issued, so it is a code
change plus a re-consent rather than a config flag. There is deliberately no
`openid`/`profile`: the person URN arrives with the ACL listing, and a second
API product on the app collides with Community Management access.

## Scheduled work

The module branches on the cron expression, so a venture wires two:

| Cron | Work |
|---|---|
| `*/5 * * * *` | Publish due posts, confirm publish-requested posts, poll in-flight assets, retry deferred work |
| `0 3 * * *` | Refresh tokens, warn about expiry, sync the page directory, purge spent states |

## Events

`linkedin.connected`, `linkedin.pages_synced`, `linkedin.post_published`,
`linkedin.post_failed`, `linkedin.token_refreshed`, `linkedin.token_expiring`,
`linkedin.token_expired`.

## What LinkedIn does not allow

Verified against Marketing version `202608`. These are walls, not backlog:

- **No documented endpoint writes a page's profile fields.** `logoV2` is a
  response field only. "Update the avatar" has no route here; issue #14 holds
  the spike that would add one if LinkedIn turns out to accept the write.
- **No endpoint creates a Showcase Page.** Since January 2024 the
  organizationBrand API is gone and a showcase is an organization with
  `primaryOrganizationType: BRAND`. Create one in the LinkedIn UI from the
  parent page's admin view; the next sync picks it up. Posting to a showcase
  already works, with its organization URN as the author.
- **A published post changes in four fields only**: `commentary`,
  `contentCallToActionLabel`, `contentLandingPage`, `lifecycleState`.
  (`adContext` is a fifth, for direct sponsored content, which this module does
  not do.) Media cannot be swapped after publish; that is a delete and a
  repost.
- **A `201` is not a published post.** `lifecycleState` may be
  `PUBLISH_REQUESTED` and then `PUBLISH_FAILED`, whose own documentation says
  an edit is required before publishing can be re-attempted. The module
  confirms before it reports success.
- **Access is metered.** Community Management Development Tier allows 500
  requests per app per day and 100 per member per day, so every read is cached
  and `GET /v1/linkedin/admin/status` reports the day's spend.

## Two deliberate deviations from harness defaults

- **The image route raises the body limit.** Core layers a 64 KiB
  `DefaultBodyLimit` over every `/v1/*` route; the upload route applies its own
  inner limit of `LINKEDIN_MAX_IMAGE_BYTES`, which axum resolves in favour of
  the inner layer. No public module does this.
- **Cron work emits through a synthetic `Scope`.** `EventBus::emit_in` needs a
  `Scope` and `Module::scheduled` is handed none, so scheduled work builds one
  from the `Defer` port. That is why `Defer` is a required port here rather
  than an optional one: under `NoopDefer` every scheduled event would be
  dropped with a warning.

## Connecting a page

1. Create the LinkedIn app and get Community Management access (this repo
   issue #5). A Page super admin must verify the app.
2. Set `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET` and `LINKEDIN_TOKEN_KEY`
   as Worker secrets. Never in `wrangler.toml`.
3. Register the redirect URI, matching `LINKEDIN_REDIRECT_URI` exactly.
4. `POST /v1/linkedin/admin/connect` with the admin bearer, open the returned
   `authorize_url` as a page administrator, grant access.
5. `GET /v1/linkedin/admin/status` should show the account connected, the
   granted scopes and both expiries.
6. Post to LinkedIn's test organization first, `urn:li:organization:2414183`
   (DevTestCo). Anything posted there is publicly visible, so keep it dull.

## Version policy

`LINKEDIN_API_VERSION` is pinned. LinkedIn ships a version monthly and supports
each for at least a year, with a changelog per version. Moving the pin is a
one-line config change plus reading that changelog. The current pin is
`202608`, which sunsets no earlier than August 2027.

## Security

Access and refresh tokens are sealed at rest with XChaCha20-Poly1305 (harness
ADR 0102) under `LINKEDIN_TOKEN_KEY`, with a fresh 24-byte nonce per
encryption and an AAD binding each ciphertext to its table, row and column, so
a blob cannot be moved between columns or accounts. The sealed blob carries a
key id, so rotating the key later does not force a re-consent. Plaintext
tokens never leave `token.rs`, never appear in a response, and never reach a
log line.

`DELETE /v1/linkedin/admin/account` forgets our copy of the tokens. It does
**not** revoke them on LinkedIn's side: that is a separate action by a human in
LinkedIn's settings.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
