# Meta app review runbook

Ported from Factory-Zero/auth (issue #18 there) and adapted to the
per-instance model: every auth instance is its own Meta app with its own
URLs. Replace `<auth-host>` with the instance's host, for example
`auth.cratefield.com` or `auth.alphahunt.ing`. A staging deployment uses the
same paths on its own origin.

## URLs to enter in the Meta App Dashboard

| Field | Value |
|---|---|
| Base | `https://<auth-host>`: the instance's custom domain, the `routes` entry in `instances/<app>/wrangler.toml` |
| Data deletion callback | `https://<auth-host>/v1/auth-meta/data-deletion`. Meta POSTs `signed_request` here; the route is in `crates/auth-meta/src/handlers.rs` |
| Deletion status page | `https://<auth-host>/v1/auth-meta/deletion-status?code=…`, returned as `url` together with `confirmation_code` |
| Valid OAuth Redirect URI | `https://<auth-host>/v1/auth-meta/callback`, i.e. `<AUTH_META_REDIRECT_BASE>/v1/auth-meta/callback`. It must match exactly |
| Privacy Policy URL | The instance's `AUTH_BRAND_PRIVACY_URL`. Meta refuses review without one, and the login pages link to the same URL |
| Terms of Service URL | The instance's `AUTH_BRAND_TERMS_URL` |

## How the deletion callback works

1. **Verify first.** `signed_request::verify` checks the HMAC against
   `AUTH_META_CLIENT_SECRET` before anything is read; every refusal answers
   the same generic `400`.
2. **Record a job row**, not the deletion itself. The answer is
   `{url, confirmation_code}` for the status page (`deletion.rs`).
3. **Scheduled drain.** `Module::scheduled` calls `deletion::run_pending`,
   which drains a bounded batch of pending jobs per run. The instance's
   Worker needs its cron trigger for this (`[triggers]` in its
   `wrangler.toml`).
4. **Unlink vs purge.** The Meta identity row is always deleted first; the
   account is purged only when no other identity or credential remains,
   otherwise the outcome is `unlinked`. Replays are harmless: an
   already-gone subject completes as `nothing_to_do`.
5. **Status page.** Unknown and missing codes answer identically; known jobs
   say pending ("received and is being carried out") or done ("has been
   carried out") with no account details.

## Reviewer walkthrough

1. Submit a deletion request for a test user via the callback URL.
2. Confirm the answer contains `url` and `confirmation_code`.
3. Open the status URL: expect the pending message, then the done message
   after the next scheduled run.
4. Confirm the Meta identity row is gone, and the account too only if it had
   no other login method.
