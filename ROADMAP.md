# Cratefield roadmap: what would make this a Supabase alternative

**Date: 8 September 2026. Status: for review. Nothing here is filed.**

This document was written in response to an external assessment of cratefield.com dated
8 September 2026, which concluded that Cratefield is not yet a credible Supabase
alternative: the site sells Rust to an audience that reads Rust as difficulty, the managed
service does not exist yet, and the only way to add custom logic is to write a Rust crate.
The assessment also named the two ideas worth defending, one database per tenant and the
honest Shipping / Designed / Planned labels on the site. What follows is the product half of
the response. It is a review document. No issue is created and no label is added until Nick
approves it, and the appendix at the end holds the proposed issues in a form that can be
pasted once he does.

Vocabulary follows the repo. A **venture** is one customer backend, one Worker and one D1.
A **module** is a crate that a venture composes in. The **catalog** is the reviewed set of
modules a customer can pick from. **Provisioning** is turning a module set into a live
venture. The site says "backend" where this document says "venture".

## Positioning

Cratefield is for two audiences: SaaS teams and agencies running many tenant backends, and
builders working with AI coding tools. Both get the same guarantee, which is that each
tenant is a separate database, so there is no cross-tenant policy to get wrong. What is
still to prove is the product around that guarantee, and that is what this roadmap covers.

## 1. The one design decision: how custom logic gets written

Today a customer can only add logic by writing a Rust crate that implements the `Module`
trait. That is a hard stop for most of the second audience and for a good part of the first.
Three ways out were weighed.

| | (a) TS handlers in a JS Worker beside the wasm modules | (b) Declared tables, typed data API, generated TS client | (c) Rust only, with a generated starter module |
| :--- | :--- | :--- | :--- |
| Covers | business rules, webhooks, jobs | schema and queries, which is most of a CRUD app | everything, for people who write Rust |
| Cloudflare fit | excellent: a second Worker over a service binding is the sidecar mount that already ships | excellent: pure Rust, builds on both runtimes, passes the existing gates | poor: cargo to wasm in the edit loop is minutes |
| Hot path | data access must be batched over the binding | Rust only | Rust only |

**Recommendation: ship (b) first, (a) second as a TypeScript sidecar, (c) only as a
template.** The order is forced rather than chosen. Option (a) needs (b) anyway, because a
TypeScript handler has to reach the database through a typed contract, and that same
contract is what generates the TypeScript client, the data browser and the MCP server. One
piece of work pays for four. A separate JavaScript Worker, rather than JavaScript bundled
into the harness Worker, keeps function redeploys independent of the wasm artifact, so a
function change takes seconds instead of a build.

The access vocabulary for (b) stays deliberately small and declarative:
`public-read | owner | tenant-members | admin`, evaluated in Rust. It is not a policy
language, and it should not grow into one. The point of database-per-tenant is that the
dangerous axis is already handled by the boundary.

Two existing decisions carry most of the weight here and are not being reopened. Harness
[ADR 0009](https://github.com/Cratefield/harness/blob/main/docs/adr/0009-sidecar-modules-over-service-bindings.md)
already decides that a module may be mounted in process or as a sidecar Worker over a
service binding, that the mount is runtime configuration rather than a builder call, and
that a sidecar binds the same database with its own secrets. Option (a) is that mount with a
different language inside it. ADR 0009 justifies the sidecar by confidentiality, so adding
"the customer does not write Rust" as a second reason is a real extension of it and should
be recorded as one. Harness
[ADR 0000](https://github.com/Cratefield/harness/blob/main/docs/adr/0000-rust-not-typescript.md)
says everything in the harness repository is Rust. Nothing here changes that. The generated
client and the customer's sidecar are separate artifacts in separate repositories, and the
generator itself is Rust.

## 2. Horizons

Size is rough: S is days, M is a week or two, L is a month, XL is a quarter.

### H0: already in flight, no new issues

| Item | Scope | Maps to | Deps | Size |
| :--- | :--- | :--- | :--- | :--- |
| Control plane core | accounts, catalog, connections, provisioning engine, wizard, dashboard | [cp#1](https://github.com/Cratefield/control-plane/issues/1), [cp#3](https://github.com/Cratefield/control-plane/issues/3), [cp#7](https://github.com/Cratefield/control-plane/issues/7), [cp#8](https://github.com/Cratefield/control-plane/issues/8), [cp#11](https://github.com/Cratefield/control-plane/issues/11) | cp#4, cp#5, cp#6 are closed | L |
| Menu-card onboarding | venture manifest and composition generator, reviewed machine-readable catalog, agent-safe CLI, canonical template and agent docs | [harness#138](https://github.com/Cratefield/harness/issues/138), [harness#139](https://github.com/Cratefield/harness/issues/139), [harness#140](https://github.com/Cratefield/harness/issues/140), [harness#146](https://github.com/Cratefield/harness/issues/146) | none | L |
| Production readiness and deploy gates | catalog supply chain and secret lifecycle, enforceable route security, deploy gated on real Workers requests | [harness#142](https://github.com/Cratefield/harness/issues/142), [harness#143](https://github.com/Cratefield/harness/issues/143), [harness#144](https://github.com/Cratefield/harness/issues/144) | none | M |
| Tenant isolation by database | the schema epic, and the child that actually routes a connection per tenant | [harness#23](https://github.com/Cratefield/harness/issues/23), [harness#32](https://github.com/Cratefield/harness/issues/32) | none | L |
| Content-addressed build cache | cache the artifact on the content address of the module set | [harness#59](https://github.com/Cratefield/harness/issues/59) | harness#138 | M |
| Pricing and the free tier | tier design, free-tier economics, throttle rather than bill | [cp#12](https://github.com/Cratefield/control-plane/issues/12) | none | S |

**Decision to take before H1 starts: whose Cloudflare account.**
[cp#7](https://github.com/Cratefield/control-plane/issues/7) provisions into Cratefield's own
Cloudflare account with one platform credential. [harness#141](https://github.com/Cratefield/harness/issues/141)
says "start with customer-owned Cloudflare accounts using the narrowest supported deployment
credentials". Those two cannot both be the default path.

The recommendation is Cratefield's account, and it is worth noting that this repo has
already decided it. `docs/ARCHITECTURE.md` sections 3 and 4, which is the ADR recorded
against [cp#2](https://github.com/Cratefield/control-plane/issues/2), states that customer
ventures deploy into Cratefield's own account, that bring-your-own-account is a later
Advanced option and not v1, and that isolation rests on one database and one secrets store
per tenant rather than on the deploy credential. So the open action is not to re-decide but
to amend harness#141 so its text stops contradicting the ADR, and to keep customer-owned
Cloudflare as the exit path and a later tier. If Nick wants the opposite, the ADR is what
has to change first.

One correction to note while doing that. The ADR puts the `$5` Workers Paid plan on the
whitelist phase and Workers for Platforms as the pre-scale upgrade before the roughly
100-script wall, behind the `Deployer` port. So H1 hosting is a plain Worker and D1 per
venture, and the dispatch namespace is a later operational change, not an H1 requirement.

### H1: unblock the first paying customer

| Item | Scope | Maps to | Deps | Size |
| :--- | :--- | :--- | :--- | :--- |
| Tables | `[tables]` in the venture manifest, forward-only migrations, CRUD with filter, sort and pagination, batched and parallel declared reads in one request, the small access vocabulary, contract published at `/__surface` | NEW harness epic | [harness#138](https://github.com/Cratefield/harness/issues/138), [harness#23](https://github.com/Cratefield/harness/issues/23) | L |
| Generated TypeScript client | `@cratefield/client` generated from the Tables contract, published on every deploy | NEW, creates a repo | Tables | M |
| Hosting on our account | one Worker and one D1 per venture through the platform credential, `you.cratefield.app` subdomains, Workers for Platforms deferred behind the `Deployer` port | [cp#7](https://github.com/Cratefield/control-plane/issues/7), [harness#141](https://github.com/Cratefield/harness/issues/141), NEW cp issue | the account decision above | L |
| Billing and metering | Stripe subscription per venture on the existing `adapter-stripe`, request and storage counters, free-tier throttle rather than overage | NEW cp issue | [cp#12](https://github.com/Cratefield/control-plane/issues/12) | M |
| Fast loop v1 | compose from precompiled catalog artifacts, config change under 10 s, new venture under 60 s, publish the measured numbers | [harness#59](https://github.com/Cratefield/harness/issues/59), [harness#139](https://github.com/Cratefield/harness/issues/139), NEW harness issue | harness#138 | M |
| Agent-safe errors | `--json` on every `fz` verb, a stable error-code catalogue, exit codes documented in llms.txt | extend [harness#140](https://github.com/Cratefield/harness/issues/140) | none | S |
| Email and password, magic links | registration with argon2, login, magic-link request and consume, plus the rate limiting and lockout that has to ship with them | [auth#19](https://github.com/Factory-Zero/auth/issues/19), [auth#20](https://github.com/Factory-Zero/auth/issues/20), [auth#21](https://github.com/Factory-Zero/auth/issues/21), [auth#12](https://github.com/Factory-Zero/auth/issues/12) | [auth#41](https://github.com/Factory-Zero/auth/issues/41) | M |
| Customer-visible logs | logs and spans for a venture, in the account dashboard | extend [cp#11](https://github.com/Cratefield/control-plane/issues/11) | cp#7 | M |

Passkeys and Google alone lose B2B deals, which is why the auth row is in H1 rather than
later. All four of those auth issues are open and unstarted.

### H2: parity table stakes

| Item | Scope | Maps to | Deps | Size |
| :--- | :--- | :--- | :--- | :--- |
| TypeScript functions | a sidecar Worker running customer TypeScript, mounted as ADR 0009 describes, reaching data through the Tables contract | NEW harness epic, reuses [harness#56](https://github.com/Cratefield/harness/issues/56), [#61](https://github.com/Cratefield/harness/issues/61), [#62](https://github.com/Cratefield/harness/issues/62), [#63](https://github.com/Cratefield/harness/issues/63), [#66](https://github.com/Cratefield/harness/issues/66), [#67](https://github.com/Cratefield/harness/issues/67), [#142](https://github.com/Cratefield/harness/issues/142) | Tables, client | XL |
| Data browser | generated from the Tables contract, plus a read-only SQL console and CSV export | NEW cp issue | Tables | M |
| Blob storage | the Blob port, R2 adapter and a native directory adapter | [harness#105](https://github.com/Cratefield/harness/issues/105) | none | M |
| Realtime | WebSocket rooms on Durable Objects, with a native adapter | [harness#103](https://github.com/Cratefield/harness/issues/103) | none | L |
| Backups | D1 Time Travel plus a scheduled export to R2, restore documented | NEW cp issue | cp#7 | S |
| Custom domains | Cloudflare for SaaS custom hostnames, paid tier only | NEW cp issue | cp#7, cp#12 | M |
| Safe upgrades | module upgrade, removal and migration deployment plans | [harness#145](https://github.com/Cratefield/harness/issues/145) | harness#138 | M |
| MCP server | a thin wrapper over `fz --json`, no second surface to maintain | NEW, creates a repo | agent-safe errors | S |
| Benchmarks | a `bench/` harness and the published page, see section 3 | NEW harness issue | Tables | M |
| Staging and preview environments | a second venture per project, promotion between them | NEW cp issue | cp#7 | M |

### H3: the moat

| Item | Scope | Maps to | Deps | Size |
| :--- | :--- | :--- | :--- | :--- |
| Tenants as a product | a tenant lifecycle API where create, export and delete make GDPR a property of the architecture, plus promotion of a tenant past 10 GB onto the Postgres runtime using the existing export and import | [harness#23](https://github.com/Cratefield/harness/issues/23), NEW harness epic | H1 Tables | XL |
| Agency console | one organisation, many client ventures, clone a template, per-client billing, white-label domains | NEW cp issue | billing, custom domains | L |
| Performance programme | region-pin the primary, KV and Cache for immutable reads, D1 read replication through the Sessions API, Durable Object warmers | NEW harness epic | benchmarks | L |
| Distribution | starter kits for Next.js, SvelteKit and Expo, Claude Code and Cursor templates carrying llms.txt and MCP, a "Deploy to Cratefield" button | NEW, creates a repo | client, MCP | M |
| Sovereign exit | one command moves a venture to a customer-owned Cloudflare account | [harness#141](https://github.com/Cratefield/harness/issues/141) | hosting | M |

Prompt to UiSpec ([cp#9](https://github.com/Cratefield/control-plane/issues/9)) and the CMS
module ([cp#10](https://github.com/Cratefield/control-plane/issues/10)) stay on the list but
drop below everything above. Neither is what a customer is blocked on.

## 3. Benchmarks to publish, and nothing else

Three numbers, because three defensible numbers beat a page of them.

1. **Cold start.** Time to first byte against an evicted venture, split into wasm
   instantiate and first D1 query, p50 and p99, from five vantage points that are not on
   Cloudflare, over seven days.
2. **Warm authenticated read.** p99 at 50 requests per second for ten minutes, measured both
   from the D1 primary's region and from a distant one. The gap between the two is the
   region-pin effect, and publishing it is more useful than hiding it.
3. **Per-tenant write ceiling.** Single-row insert with the audit chain on, p99 at 50
   requests per second, plus the rate at which p99 doubles on one D1. This is the honest
   single-writer number. It also sells database-per-tenant, because each tenant gets its own
   ceiling instead of sharing one.

Honesty rules, which are the point of publishing at all:

- Pin the harness commit that produced every number.
- Publish the scripts and the raw samples, not just the summary.
- State the D1 region.
- Never mix warm and cold measurements in one figure.
- Report sample counts.
- Compare against Supabase only with an identical harness, or not at all.

## 4. Where the assessment is off

- **The hook overclaims as written.** Database-per-tenant removes the *cross-tenant* policy
  problem. User A against user B inside one tenant still needs authorisation, and Tables has
  to carry it. The site wording should be "no cross-tenant policy to get wrong", not "no
  policy to get wrong".
- **Read replicas are over-weighted.** For one small D1 per tenant, region-pinning the
  primary and batching reads deliver more than replication does. Replication goes last in
  the performance programme, not first.
- **The 10 GB cap is per tenant.** For the target customer that is a feature, not a ceiling.
  The real gap is a documented promotion path to the Postgres runtime, which is why it is an
  H3 item rather than a defect.
- **Durable Object hibernation cold start does not matter yet.** It only becomes a real
  number once Realtime exists.
- **MCP is a small piece of work.** Once errors are machine-readable it is a thin wrapper.
  The `--json` flag on every verb matters far more, and it is an S.
- **"Stop selling Rust" is right for the product and wrong for the harness.** Readable MIT
  Rust is the exit story and the reason the portability claim is credible. Hide it in the
  product surface, keep it on the technology pages.
- **Five things the assessment missed entirely.** Billing and metering, custom domains,
  backups, customer-visible logs, and email-and-password authentication. Each of those
  blocks a paying customer more reliably than anything the assessment did name, and all five
  are in H1 or H2 above.

## Appendix: proposed issues

**Nothing in this appendix is filed.** These are drafts. Each entry names the repository,
the title, a body ready to paste, and labels chosen from the labels that already exist in
that repository (`gh label list -R <repo>`). Sixteen issues in total: nine in
`Cratefield/harness`, seven in `Cratefield/control-plane`.

Two caveats on labels. `Cratefield/control-plane` has no `enhancement` label, so the
control-plane entries use `provisioning`, `gui`, `pricing`, `design` and `connections`
instead. Two of the harness entries are epics and would ideally carry a new `epic:tables`
and `epic:tenants` label; those do not exist yet, and creating them is part of filing.

### A1. Tables: declared tables, a typed data API and a published contract

- **Repo:** `Cratefield/harness`
- **Labels:** `design`, `kernel`, `implementation`
- **Body:** A venture should be able to declare its own tables in the venture manifest and
  get a working data API without writing a module crate. Add a `[tables]` section to the
  manifest that generates forward-only migrations, and serve CRUD endpoints per table with
  filter, sort and pagination, plus a batched endpoint that runs several declared reads in
  one request and in parallel, because a sidecar or a browser client pays a round trip for
  each one otherwise. Access is a small fixed vocabulary evaluated in Rust,
  `public-read | owner | tenant-members | admin`, and it must stay a vocabulary rather than
  grow into a policy language. Publish the resulting contract at `/__surface` so the
  TypeScript client, the data browser and the MCP server can all be generated from one
  source. Depends on #138 for the manifest and #23 for the per-tenant schema. This is the
  single largest unlock in the roadmap: it is what lets someone build a CRUD product on
  Cratefield without Rust.

### A2. Generate and publish `@cratefield/client` from the Tables contract

- **Repo:** `Cratefield/harness`
- **Labels:** `cli`, `ci`, `needs-human`
- **Body:** Generate a typed TypeScript client from the `/__surface` contract produced by
  Tables, and publish it on every deploy so the types a customer imports always match the
  venture they are talking to. The generator is Rust and lives in the harness; the generated
  package needs a new public repository (`Cratefield/client-ts` or similar) and an npm
  publishing token, which is why this carries `needs-human`. Scope: query builder over the
  declared tables, typed rows, the access vocabulary reflected in the signatures, and no
  runtime dependency beyond `fetch`. ADR 0000 keeps the harness itself Rust, and nothing
  here changes that, since the generated artifact is a separate repository.

### A3. Artifact linker: compose a venture from precompiled catalog artifacts

- **Repo:** `Cratefield/harness`
- **Labels:** `ci`, `implementation`
- **Body:** Provisioning currently implies a build. Add a linker step that composes a
  venture from precompiled per-module artifacts so a config-only change does not go through
  cargo. Targets to hold and then publish: a configuration change live in under 10 seconds,
  a brand new venture live in under 60 seconds. Build on the content-addressed artifact
  cache (#59) and the reviewed catalog (#139), and measure with the harness commit pinned so
  the published numbers mean something. If the targets turn out to be unreachable, say so
  and publish the real numbers instead; the honesty is the product.

### A4. TypeScript functions as a sidecar Worker

- **Repo:** `Cratefield/harness`
- **Labels:** `design`, `epic:sidecar`, `runtime`
- **Body:** Epic. Let a customer write business rules, webhook handlers and jobs in
  TypeScript, running in its own Worker beside the wasm venture, mounted over a service
  binding exactly as ADR 0009 already specifies. ADR 0009 justifies the sidecar by
  confidentiality; this epic adds a second justification, which is that the customer does
  not write Rust, and that extension should be recorded in the ADR rather than assumed. The
  sidecar reaches data through the Tables contract and the generated client, never through
  a raw database handle, and it does not receive `HARNESS_SECRET`. Keeping it a separate
  Worker rather than JavaScript bundled into the harness Worker is what makes a function
  redeploy take seconds and leaves the wasm artifact a pure function of the module set.
  Reuses #61 for the handshake, #62 for events, #63 for the template, #66 for migrations and
  export, #67 for the credential shape, and #142 for the supply chain. Blocked on Tables and
  the generated client.

### A5. Benchmark harness and published results

- **Repo:** `Cratefield/harness`
- **Labels:** `testing`, `docs`
- **Body:** Add a `bench/` harness that produces exactly three numbers and a page that
  publishes them: cold start time to first byte against an evicted venture split into wasm
  instantiate and first D1 query, warm authenticated read p99 at 50 rps measured both from
  the D1 primary's region and from a distant one, and the per-tenant write ceiling as a
  single-row insert with the audit chain on plus the rate at which p99 doubles. Rules that
  are part of the deliverable, not an afterthought: pin the harness commit, publish the
  scripts and the raw samples, state the D1 region, never mix warm and cold in one figure,
  report sample counts, and compare to another vendor only with an identical harness or not
  at all. Three defensible numbers are worth more than a page of favourable ones.

### A6. Tenants as a product: lifecycle API and a promotion path

- **Repo:** `Cratefield/harness`
- **Labels:** `design`, `epic:schema`
- **Body:** Epic. Turn database-per-tenant from an implementation detail into a feature a
  customer sells to their own customers. Provide a tenant lifecycle API where create, export
  and delete are first-class, which makes a GDPR erasure request a single operation against
  one database rather than a query across a shared one. Add a documented promotion path for
  a tenant that outgrows the 10 GB D1 cap, moving it onto the Postgres runtime with the
  export and import that already exist, so the cap is a threshold rather than a wall. Builds
  on #23 and #32. This is the item that makes the isolation story a product rather than an
  architectural claim.

### A7. Performance programme

- **Repo:** `Cratefield/harness`
- **Labels:** `design`, `runtime`
- **Body:** Epic, and deliberately sequenced after the benchmarks so that each change is
  justified by a measurement rather than by intuition. In order: region-pin a venture's
  primary D1 near its users, serve immutable reads from KV or the Cache API, add Durable
  Object warmers where cold start is shown to matter, and only then look at D1 read
  replication through the Sessions API. Replication is last on purpose. For one small
  database per tenant, pinning and batching deliver more than replication does, and an
  external assessment that ranked replication first was reasoning about a single large
  shared database.

### A8. MCP server over `fz --json`

- **Repo:** `Cratefield/harness`
- **Labels:** `cli`, `docs`, `needs-human`
- **Body:** Publish an MCP server so an agent can create a venture, add a module, plan and
  deploy without screen-scraping CLI output. It must be a thin wrapper over `fz --json` and
  the stable error-code catalogue, with no second surface of its own to drift, which is why
  it is small and why it is blocked on the agent-safe errors work in #140. Needs a new
  public repository and a publishing token, hence `needs-human`.

### A9. Starter kits and a deploy button

- **Repo:** `Cratefield/harness`
- **Labels:** `docs`, `needs-human`
- **Body:** Create `Cratefield/starters` with working starters for Next.js, SvelteKit and
  Expo that use the generated TypeScript client, plus Claude Code and Cursor project
  templates that ship `llms.txt` and the MCP server configured. Add a "Deploy to Cratefield"
  button that takes a repository to a live venture. This is the distribution half of the
  second audience: builders working with AI tools adopt what their tool already knows how to
  scaffold. Needs a new public repository, hence `needs-human`.

### B1. Host ventures on Cratefield's Cloudflare account

- **Repo:** `Cratefield/control-plane`
- **Labels:** `provisioning`, `design`
- **Body:** Make hosted provisioning real end to end: one Worker and one D1 per venture
  created with the platform credential, a `you.cratefield.app` subdomain bound and
  health-checked, and resource ownership recorded so a failed provision can be cleaned up.
  `docs/ARCHITECTURE.md` sections 3 and 4 already decide that this is the default path and
  that customer-owned Cloudflare is a later Advanced option, so part of this issue is
  amending `Cratefield/harness#141`, which still says to start with customer-owned accounts
  and now contradicts the ADR. Keep Workers for Platforms behind the `Deployer` port as the
  pre-scale upgrade before the roughly 100-script wall rather than an initial requirement.
  Builds on #7.

### B2. Billing and metering per venture

- **Repo:** `Cratefield/control-plane`
- **Labels:** `pricing`, `provisioning`
- **Body:** Charge for a venture and know what it costs. Add a Stripe subscription per
  venture on the existing `adapter-stripe`, per-venture counters for requests, storage and
  email, and enforcement of the free tier by throttling rather than billing, so a free
  venture can never produce an overage we absorb. #12 records the tier design and the
  free-tier economics; this issue is the enforcement that document says is provisioning and
  dashboard work. The free tier staying always-on is the differentiator against Supabase
  pausing an idle project, so the throttle must never become a pause.

### B3. Data browser, SQL console and CSV export

- **Repo:** `Cratefield/control-plane`
- **Labels:** `gui`
- **Body:** Generate a data browser in the dashboard from the Tables contract published at
  `/__surface`, so it stays correct without being maintained separately: list and edit rows,
  filter and sort, follow relations. Add a read-only SQL console and CSV export of a table
  or a query result. Read-only is the important constraint on the console; a write console
  against a customer's live tenant database is a support incident waiting to happen. Blocked
  on the Tables work in the harness.

### B4. Backups and restore

- **Repo:** `Cratefield/control-plane`
- **Labels:** `provisioning`, `design`
- **Body:** Every venture needs a recovery story before the first paying customer, not
  after. Use D1 Time Travel for point-in-time recovery inside its retention window, and add
  a scheduled export of each venture's database to R2 for anything older. Surface the last
  successful backup in the dashboard, and document and test the restore path, because a
  backup that has never been restored is not a backup. Small, and it removes an objection
  that comes up in every serious evaluation.

### B5. Custom domains through Cloudflare for SaaS

- **Repo:** `Cratefield/control-plane`
- **Labels:** `provisioning`, `connections`
- **Body:** Let a paying customer put a venture on their own domain using Cloudflare for
  SaaS custom hostnames: add the hostname, show the DNS record to create, verify it, issue
  the certificate, and show the status while it settles. The free tier stays on a
  `you.cratefield.app` subdomain, as `docs/PRICING.md` sets out, since custom hostnames
  carry a per-hostname cost. Deferring this blocks anyone who wants a branded backend, which
  is most of the agency audience.

### B6. Staging and preview environments

- **Repo:** `Cratefield/control-plane`
- **Labels:** `provisioning`, `design`
- **Body:** Give a project more than one environment: a staging venture alongside
  production, with its own database and secrets, and a promotion action that moves a module
  set and its migrations from staging to production. Anyone who has used a hosted backend
  expects this, and without it every schema change on Cratefield is tested in production.
  Depends on provisioning (#7) and on the safe-upgrade plans in `Cratefield/harness#145`.

### B7. Agency console

- **Repo:** `Cratefield/control-plane`
- **Labels:** `gui`, `design`
- **Body:** Serve the audience that runs many client backends rather than one. One
  organisation holds many ventures, a template venture can be cloned for a new client,
  billing is per client and can be passed through, and each client venture can carry its own
  domain and branding. This is where database-per-tenant stops being an architecture
  argument and becomes a commercial one, because an agency can hand a client an isolated
  database and an export without doing any work for it. Depends on billing and custom
  domains.
