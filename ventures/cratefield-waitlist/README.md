# cratefield-waitlist

Cratefield's own early-access waitlist, on the Factory Zero harness `waitlist`
module. Deployed as a Cloudflare Worker at **api.cratefield.com** with its own
D1 database.

```
POST /v1/waitlist            { "email": ..., "product": "cratefield" }
GET  /v1/waitlist/admin/export.csv   (Bearer ADMIN_TOKEN)
```

The mailer picks the first mail key that is set on the Worker: `OWLPOST_API_KEY`
(`op_test_…` in development, `op_live_…` in production), else `RESEND_API_KEY`,
else a no-op that still captures the join as a pending entry. Whichever
provider is picked, the confirmation is sent `from`
`no-reply@send.cratefield.com`. Set a secret with
`wrangler secret put OWLPOST_API_KEY`; double opt-in comes to life once one is
set.

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
