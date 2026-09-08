# cratefield-waitlist

Cratefield's own early-access waitlist, on the Factory Zero harness `waitlist`
module. Deployed as a Cloudflare Worker at **api.cratefield.com** with its own
D1 database.

```
POST /v1/waitlist            { "email": ..., "product": "cratefield" }
GET  /v1/waitlist/admin/export.csv   (Bearer ADMIN_TOKEN)
```

The mailer is a no-op until `cratefield.com` has a verified sending domain (see
`src/lib.rs`); swap it for the Resend adapter and double opt-in comes to life.

**Status:** deployed, `/__health` live. The join path is blocked by
[Cratefield/harness#107](https://github.com/Cratefield/harness/issues/107) — the
harness D1 write-bind path fails invisibly on wasm. Not yet wired to the site.

## Deploy

```sh
export CLOUDFLARE_API_TOKEN=...   # Kontinuum account (53e50d9d…)
export CLOUDFLARE_ACCOUNT_ID=53e50d9dab2b9b72e39ce243d0a79e7f
worker-build --release
npx wrangler d1 migrations apply cratefield-waitlist --remote
npx wrangler deploy
```
