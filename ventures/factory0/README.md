<p align="center">
  <img src="assets/readme-banner.png" alt="api.factory0.ventures. The first venture backend built on the harness." width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/VENTURE-FZ%2F01-FF5A36?style=flat-square&labelColor=0A0A0B" alt="Venture: FZ/01">
  <img src="https://img.shields.io/badge/ENDPOINT-api.factory0.ventures-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Endpoint: api.factory0.ventures">
  <img src="https://img.shields.io/badge/MODULES-EMAIL%20SIGNUP%20%C2%B7%20WAITLIST-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Modules: email signup and waitlist">
  <img src="https://img.shields.io/badge/DATABASE-CLOUDFLARE%20D1-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Database: Cloudflare D1">
  <img src="https://img.shields.io/badge/STATUS-NOT%20DEPLOYED-FF5A36?style=flat-square&labelColor=0A0A0B" alt="Status: not deployed">
</p>

<p align="center">
  <b>factory0.ventures</b> · BACKEND · FZ/01
</p>

---

# The first venture backend

Factory Zero's own site is the first venture on the
[harness](https://github.com/Cratefield/harness). This Worker serves
`api.factory0.ventures`: the **enter** form on the website signs people up
with double opt-in, and every venture page can put visitors on a **waitlist**
for that venture.

> **Dogfood first.**
> If the harness cannot run Factory Zero's own signup and waitlist, it is not
> ready for anyone else's.

Built from
[venture-backend-template](https://github.com/Factory-Zero/venture-backend-template).
Same layout, same workflows, one composition file.

## Composition

```rust
Harness::builder()
    .venture(Venture::new("factory0", "factory0.ventures")
        .public_url("https://factory0.ventures")
        .cors_origins(["https://factory0.ventures", "https://www.factory0.ventures"]))
    .module(EmailSignup::new().double_opt_in(true))
    .module(Waitlist::new().products(["kontinuum", "undercover-rockstars", "fz-003"]))
    .runtime(Cloudflare::new()
        .db("DB")
        .mailer(Resend::from_env())
        .captcha(Turnstile::from_env().expected_hostname("factory0.ventures")))
    .build()
```

Product slugs match `assets/fz-data.js` in
[Factory-Zero/website](https://github.com/Factory-Zero/website).

## Endpoints

| Route | Purpose |
|---|---|
| `POST /v1/email-signup` | Sign up. Always `202`; a confirmation mail carries the signed link |
| `GET  /v1/email-signup/confirm?token=` | Double opt-in. Redirects to `/confirmed/` on the site |
| `GET  /v1/email-signup/unsubscribe?token=` | One click, never expires |
| `POST /v1/waitlist` | Join a venture's waitlist. Always `202` |
| `GET  /v1/waitlist/confirm?token=` | Assigns the position, credits a referrer, redirects to the status page |
| `GET  /v1/waitlist/status?token=` | Position, referrals, share link |
| `GET  /__health` · `GET /__ready` | Modules and versions · database check |

Admin exports and deletion live under `/v1/<module>/admin/*` behind `ADMIN_TOKEN`.

## Environments

| | Worker | Database | Mail | Captcha |
|---|---|---|---|---|
| **staging** | `factory0-api-staging` | `factory0-api-staging` | `onboarding@resend.dev` stopgap until the sending domain is verified | off |
| **production** | `factory0-api` at `api.factory0.ventures` | `factory0-api` | `hello@send.factory0.ventures` | Turnstile, required |

Secrets are set once by a human with `wrangler secret put`; the deploy
workflow only carries the Cloudflare deploy token. Production deploys wait for
an approval in the GitHub Environment.

## Getting there

The [issues](../../issues) are ordered: bootstrap and staging first, then the
three steps only the owner can do (Resend sending subdomain, Turnstile site,
production secrets), then wiring the website forms, then the `v0.1.0` tag.

Private to Factory Zero.
