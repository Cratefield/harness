# Pricing and the free tier

> **Cloudflare pricing verified 2026-09-07; re-check before launch — it moves.**
> This is the design that issue #12 records. Enforcement (metering, the
> free-tier caps) is provisioning and dashboard work (#7, #11); this document
> is the decision those build against.

> The two data tables below are **generated** from
> `crates/control-plane-billing`'s pricing data, so the document and the
> billing screen cannot drift:
>
> ```sh
> cargo run -p cratefield-billing --example pricing-doc          # write
> cargo run -p cratefield-billing --example pricing-doc -- --check
> ```
>
> Edit the crate, regenerate, commit. The prose stays hand-written. The
> free-venture marginal cost named in the prose below is checked against
> the crate's constant the same way: edit both together, or neither.

## What one venture consumes on Cloudflare

Hosted mode (ADR): every venture is one Worker + one D1 in **Cratefield's own**
Cloudflare account.

<!-- pricing-doc: platform-costs begin (generated; edit crates/control-plane-billing and run the pricing-doc example) -->
| Resource | Free-plan limit | Paid included (pooled across the account) | Overage |
| :--- | :--- | :--- | :--- |
| Workers requests | 100k/day | 10M/mo ($5) · 20M/mo (Workers for Platforms) | $0.30 / million |
| Worker CPU | 10 ms/req | 30M ms/mo ($5) · 60M ms/mo (WfP) | $0.02 / million ms |
| Worker scripts | ~100/account | ~100 ($5) · **1,000 (WfP)** | $0.02 / script (WfP) |
| D1 rows read | 5M/day | 25 **billion**/mo | $0.001 / million |
| D1 rows written | 100k/day | 50 **million**/mo | $1.00 / million |
| D1 storage | 5 GB total, 500 MB/db | 5 GB pooled, **10 GB/db** hard cap | $0.75 / GB-mo |
| D1 databases | 10 | 50,000 (raise on request) | — |
| Egress / bandwidth | none | **none** | **none** |
<!-- pricing-doc: platform-costs end -->

Account allotments are **pooled**, so thousands of small ventures draw from the
same 20M requests / 60M CPU-ms / 50M writes / 25B reads before a cent of overage.

## Which platform plan

- **$5 Workers Paid** while whitelisted and small: ~100 scripts, so ~100
  ventures. Fine for the invite phase.
- **$25 Workers for Platforms** at scale: 1,000 scripts included,
  dispatch-namespace isolation between customer Workers (the right multi-tenant
  primitive), one request charge across the dispatch chain. Migrate to it before
  the ~100-script wall.

## The marginal cost of a free venture ≈ two cents

A quiet free venture (say 50k req/mo, sub-millisecond CPU, a few MB of D1, a
handful of writes) sits entirely inside the pooled allotments. Its only real
marginal cost is the **$0.02/month WfP script fee** once past the 1,000
included. Everything else rounds to zero.

**Rough cost of 1,000 always-on free ventures:** ~$25 base + up to ~$20 in
per-script fees + up to ~$25 if their traffic collectively exceeds the pooled
20M requests — call it **$25–70/month total, ~$0.05 per free venture**. One
paying customer covers hundreds.

## The competitive edge Cloudflare hands us

**Idle free ventures cost $0 and stay on.** Workers and D1 scale to zero and
bill nothing when idle, and there is no egress fee. So every free site can stay
**always live** — what Supabase's free tier explicitly won't do (it pauses
projects after 7 days idle) and VM/container hosts can't afford. "Your site
never sleeps, even on free" is a real, cheap differentiator, and a viral free
site can't generate a surprise bandwidth bill.

## Where cost actually bites, and the guard for each

1. **Email** — not Cloudflare. Confirmations via Resend or similar; the genuine
   variable cost of a free tier. Guard: a shared sending domain with a low
   monthly cap (~100 emails), bring-your-own key above it.
2. **D1 storage past the pooled 5 GB** ($0.75/GB-mo, 10 GB/db hard cap). Guard:
   a free-tier per-database soft cap (~100 MB), enforced by the control plane.
3. **Runaway traffic / abuse** eats the shared request + CPU budget. Guard: the
   harness's Workers Rate Limiting binding, Turnstile (free) on public writes,
   and a per-tenant monthly request ceiling the control plane throttles at
   rather than bills through.
4. **Custom hostnames** need Cloudflare for SaaS (~$0.10/hostname/mo beyond an
   included tier). Guard: the free tier is a `*.cratefield` subdomain only; a
   custom domain is a paid feature.

## Proposed free tier (competitive, near-zero cost to us)

<!-- pricing-doc: tiers begin (generated; edit crates/control-plane-billing and run the pricing-doc example) -->
| | Free | Paid (indicative, ~$19/mo) |
| :--- | :--- | :--- |
| Ventures | 1 | several |
| Domain | `you.cratefield.app` subdomain | custom domain (Cloudflare for SaaS) |
| Modules | core + curated (signups, waitlist, CMS) | full catalog |
| Requests | ~100k/mo, throttled not billed | high, then metered |
| Database | ~100 MB D1, **always on** | up to 10 GB/db |
| Email | ~100/mo shared domain | bring-your-own key, higher cap |
| Captcha + rate limiting | included (free on CF) | included |
| Support / SLA | community, none | as offered |
<!-- pricing-doc: tiers end -->

This beats Supabase (500 MB but pauses when idle), Vercel Hobby
(non-commercial only) and Netlify (credit-capped) on the axis that matters for a
hosted site: **it stays up, it can be commercial, and it costs us almost
nothing to keep it that way.**

## What the control plane must do about it (feeds #6, #7, #11)

- Meter per-venture requests / storage / email against the tier and
  **throttle, not bill, at the free ceiling** — a free venture must never
  generate an overage we eat unexpectedly.
- Enforce the free-tier D1 cap and the shared-email cap at provision time and at
  runtime.
- Keep every free venture always-on (the differentiator); never pause on idle.

## Honesty note

Every limit here is chosen against Cloudflare's own published allotments, not
measured under Cratefield load. Treat the numbers as the design target to
verify before launch, and keep the website's free-tier claims labelled
**Planned** until the control plane actually enforces them.
