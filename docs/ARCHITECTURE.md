# Cratefield control plane — architecture

The managed service: a customer signs in (invite-only), picks modules,
connects Google SSO, and gets a running harness venture on Cratefield's
Cloudflare. This document records the decisions taken 2026-09-07
(`Cratefield/control-plane` #2); it is the ADR the epic asked for.

## 1. The control plane is a harness venture

Decided. "The same Rust backend as we do now" is literal: the control
plane is one more Worker + D1 built on `Cratefield/harness`, and it
dogfoods what it provisions.

- **Auth and the whitelist** ride on `Factory-Zero/auth` (Google SSO).
- **Customer credentials** — the Google client secret, module keys — are
  secrets in that account's tenant store (`factory0-secrets`): encrypted,
  AAD-bound, audited, rotatable. This is why the secrets layer exists.
- **Its own admin and wizard** are served through the harness UI surface
  (`factory0-ui`): `maud` pages, cf.js, the `cf-*` styling contract.
- **A provisioned venture is a function of its module set** (harness ADR
  0009): choosing modules chooses the artifact, the schema and the deploy.

**The cost, stated plainly.** The control plane ships on the same runtime
it provisions, so a control-plane bug can land on the platform that runs
every customer. The harness pin is a deliberate `rev`, not a floating
branch, and a bump is a real change.

**Layout.** A Cargo workspace: `crates/venture` is the wasm entry and
composition root; the logic lives in module crates (`accounts`, `catalog`,
`connections`, `provisioning`, `cms`) added as the children land. The
harness crates are git dependencies pinned to a revision — nothing is on
crates.io yet.

## 2. The GUI is server-rendered Rust

Decided: **try Rust.** The wizard is `maud` pages served by control-plane
modules, with cf.js for the interactive steps, dogfooding the harness UI
rather than standing up a second toolchain. The multi-step OAuth wizard is
the part that stresses this; where a step genuinely cannot be
server-rendered (an OAuth popup), the fallback is a **scoped island** of
custom JavaScript on that page only, named where it happens, never a
whole SPA. The **Advanced** disclosure reveals in place, on the same page.

## 3. Cloudflare is the platform, hosted by default

Decided: **we use Cloudflare for the SaaS.** Customer ventures deploy into
**Cratefield's own** Cloudflare account. The customer connects no
Cloudflare account in the default path; *bring your own account* is a
later Advanced option, not v1.

**The hazard, recorded (harness#67).** A platform `Workers Scripts: Edit`
credential reaches every customer's script in the account. So isolation
rests on **one database and one secrets store per tenant** (harness ADR
0008), not on the deploy credential — and that credential is the
platform's single most sensitive secret, held only where the provisioning
engine runs.

**The plan.** `$5` Workers Paid through the whitelist phase (caps ~100
scripts); **Workers for Platforms** (`$25`, 1,000 scripts, dispatch-
namespace isolation) before that wall. Free-tier economics are #12.

## What answers today

`crates/venture` builds to wasm and serves the harness's `/__health`,
`/__ready` and `/__surface`. Everything else is a child of the epic.
