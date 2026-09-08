# Cratefield roadmap: what would make this a Supabase alternative

**Date: 8 September 2026. Status: for review. The appendix was filed on 8 September 2026.**

This is the product half of the response to an external assessment of cratefield.com dated
8 September 2026, which concluded that Cratefield is not yet a credible Supabase
alternative: the site sells Rust to an audience that reads Rust as difficulty, the managed
service does not exist, and the only way to add custom logic is a Rust crate. It named two
ideas worth defending, one database per tenant and the Shipping / Designed / Planned
labels. Nick approved filing on 8 September 2026 and the appendix records the issue each
entry became. This revision answers a second review of the same date, and section 8 says
what was done with each of its ten proposals.

Vocabulary follows the repo, where three terms had been doing each other's work. Used
consistently from here:

- A **venture** is one customer backend: one Worker, one primary database, one deploy. It is
  what ships and what is billed. The site says "backend" where this says "venture".
- A **database** is one D1, or one Postgres database on the native runtime.
- A **tenant** is a customer of the venture's own product. Each tenant gets its own database
  once [harness#23](https://github.com/Cratefield/harness/issues/23) ships, which is Designed
  today, not Shipping.
- A **module** is a crate a venture composes in, the **catalog** is the reviewed set to pick
  from, and **provisioning** is turning a module set into a live venture.

So a venture is one database on day one and can become many. Pricing says the same thing:
$19 per venture includes the primary database up to the D1 cap. How additional tenant
databases are metered is an open decision for Nick, and no number is invented here. It sits
under billing in H1 and under "Tenants as a product" in H3. Once settled, `docs/PRICING.md`
and the site's /pricing/ page change together.

## Positioning

Cratefield is for two audiences: SaaS teams and agencies running many tenant backends, and
builders working with AI coding tools. Both get the same guarantee, which is that each
tenant is a separate database, so there is no cross-tenant policy to get wrong.

The sequencing does not serve both at once, so say which one H1 is for. H1 ships a B2B and
agency product: hosted ventures, declared tables, a typed client, billing, auth and a domain.
What the AI-builder audience actually adopts, the MCP server, the starter kits and the deploy
button, arrives in H2 and H3.

The promise H1 can make and keep is the boring 70% of a backend running in a minute: storage,
sign-in, permissions, an admin panel, a live URL and a typed client. Not "build your app in
minutes". The other 30% is business rules, and until H2 those are Rust.

## 1. The one design decision: how custom logic gets written

Today a customer can only add logic by writing a Rust crate implementing the `Module` trait.
That is a hard stop for most of the second audience and much of the first. Three ways out
were weighed.

| | (a) TS handlers in a JS Worker beside the wasm modules | (b) Declared tables, typed data API, generated TS client | (c) Rust only, with a generated starter module |
| :--- | :--- | :--- | :--- |
| Covers | business rules, webhooks, jobs | schema and queries, which is most of a CRUD app | everything, for people who write Rust |
| Cloudflare fit | good: a second Worker over a service binding is the sidecar mount that already ships | good: pure Rust, builds on both runtimes, passes the existing gates | poor: cargo to wasm in the edit loop is minutes |
| Hot path | data access must be batched over the binding | Rust only | Rust only |

**Recommendation: ship (b) first, (a) second as a TypeScript sidecar, (c) only as a
template.** The order is forced. Option (a) needs (b) anyway, because a TypeScript handler
reaches the database through a typed contract, and that contract also generates the
TypeScript client, the data browser and the MCP server: one piece of work pays for four. A
separate JavaScript Worker keeps function redeploys independent of the wasm artifact, so a
function change takes seconds instead of a build.

The access vocabulary for (b) stays small and declarative:
`public-read | owner | tenant-members | admin`, evaluated in Rust. It is not a policy
language and should not grow into one, because database-per-tenant already handles the
dangerous axis at the boundary. State the cost of that rather than discover it. Four words
cover a product where a row belongs to one user or to one tenant, which is most internal
tools and most simple CRUD. They do not cover sharing with a named person, publishing a
draft, project membership with roles, or a marketplace. Those need code, which means the H2
TypeScript functions. H1's promise is a simple CRUD product without Rust, and the escape
hatch for anything wider is a function, not a longer vocabulary.

Two existing decisions carry the weight here and are not reopened. Harness
[ADR 0009](https://github.com/Cratefield/harness/blob/main/docs/adr/0009-sidecar-modules-over-service-bindings.md)
already decides that a module may be mounted in process or as a sidecar Worker over a service
binding, that the mount is runtime configuration, and that a sidecar binds the same database
with its own secrets. Option (a) is that mount with a different language inside it, so "the
customer does not write Rust" is a second justification for the sidecar and should be
recorded in the ADR alongside confidentiality. Harness
[ADR 0000](https://github.com/Cratefield/harness/blob/main/docs/adr/0000-rust-not-typescript.md)
keeps the harness repository Rust and nothing here changes that: the generated client and the
customer's sidecar are separate artifacts in separate repositories, and the generator is
Rust.

## 2. Schema representation

Where `[tables]` lives has already made the representation choice. A customer edits the
manifest and redeploys without a rebuild, so the schema is a runtime value. Customer rows are
dynamic values validated by a Rust interpreter reading that value, not typed structs fixed at
compile time. Rust cannot infer a compile-time type from a runtime value, so the two do not
mix and this is not a per-feature choice. What follows:

- **A small purpose-built schema enum, not JSON Schema.** JSON Schema is sprawling and does
  not express the SQLite and Postgres DDL mapping. Emit it as a derived view instead.
- **One definition, many artifacts.** From the same declaration: SQLite and Postgres DDL,
  runtime validation, CRUD route shapes, the `/__surface` contract, the Zod schema and
  inferred types in `@cratefield/client`, data browser widgets, MCP tool definitions, and the
  forward-only migration as a diff between two versions of the definition.
- **A two-validator conformance corpus.** The Rust validator and the generated Zod schema
  will disagree on empty versus absent, number coercion, null versus missing, unicode length
  and dates. Run a shared corpus of schema, input and expected verdict against both in CI,
  the way the conformance kit already does. It is a deliverable of Tables, not later
  hardening.
- **The line between a field and a function.** Declarations generate required, length, range,
  format, enum, uniqueness, foreign keys, defaults and indexes. Write the bound down before
  the first feature request: anything referencing another row or another request is a
  function, not a field. Overlap checks, state machines and side effects are functions.
- **The Rust starter module stays as the escape hatch.** A generated starter on the existing
  `Module` trait mounts the way a declared table does and publishes to the same `/__surface`.

Validation cost is not part of this decision: interpreting a small schema is microseconds
against a millisecond query. The ceiling is D1, single-threaded per database, and that
ceiling is per tenant.

## 3. Sidecar runtime cost

The TypeScript sidecar is the right shape and it is not free. Its costs, in the order they bite:

1. **Cold start**, tens to low hundreds of milliseconds against single digits for wasm.
   Contained, because only ventures that use functions pay it and only on those routes.
2. **Memory and density**, tens of megabytes against a few. This decides free-tier
   economics, so model density before pricing the free tier.
3. **The service-binding hop**, harness to TypeScript to data API on every call. It is why
   batched declared reads are in the Tables scope rather than a later optimisation.

Two decisions follow. TypeScript is never in the hot path by default: a request reaches the
sidecar only where the venture declared a function. And a venture that uses functions keeps
one warm instance, so cold start is paid once rather than per request.

## 4. Horizons

Size is rough: S is days, M is a week or two, L is a month, XL is a quarter.

### H0: already in flight, no new issues

| Item | Scope | Maps to | Deps | Size |
| :--- | :--- | :--- | :--- | :--- |
| Control plane core | accounts, catalog, connections, provisioning engine, wizard, dashboard | [cp#1](https://github.com/Cratefield/control-plane/issues/1), [cp#3](https://github.com/Cratefield/control-plane/issues/3), [cp#7](https://github.com/Cratefield/control-plane/issues/7), [cp#8](https://github.com/Cratefield/control-plane/issues/8), [cp#11](https://github.com/Cratefield/control-plane/issues/11) | cp#4, cp#5, cp#6 are closed | L |
| Menu-card onboarding | manifest and composition generator, reviewed machine-readable catalog, agent-safe CLI, canonical template and agent docs | [harness#138](https://github.com/Cratefield/harness/issues/138), [harness#139](https://github.com/Cratefield/harness/issues/139), [harness#140](https://github.com/Cratefield/harness/issues/140), [harness#146](https://github.com/Cratefield/harness/issues/146) | none | L |
| Production readiness and deploy gates | catalog supply chain and secrets, enforceable route security, deploy gated on real Workers requests | [harness#142](https://github.com/Cratefield/harness/issues/142), [harness#143](https://github.com/Cratefield/harness/issues/143), [harness#144](https://github.com/Cratefield/harness/issues/144) | none | M |
| Tenant isolation by database | the schema epic, and the child that actually routes a connection per tenant | [harness#23](https://github.com/Cratefield/harness/issues/23), [harness#32](https://github.com/Cratefield/harness/issues/32) | none | L |
| Content-addressed build cache | cache the artifact on the content address of the module set | [harness#59](https://github.com/Cratefield/harness/issues/59) | harness#138 | M |
| Pricing and the free tier | tier design, free-tier economics, throttle rather than bill | [cp#12](https://github.com/Cratefield/control-plane/issues/12) | none | S |

**Decision to take before H1 starts: whose Cloudflare account.**
[cp#7](https://github.com/Cratefield/control-plane/issues/7) provisions into Cratefield's own
Cloudflare account with one platform credential. [harness#141](https://github.com/Cratefield/harness/issues/141)
says "start with customer-owned Cloudflare accounts". Those cannot both be the default path.

The repo has already decided it. `docs/ARCHITECTURE.md` sections 3 and 4, the ADR recorded
against [cp#2](https://github.com/Cratefield/control-plane/issues/2), states that ventures
deploy into Cratefield's own account, that bring-your-own-account is a later Advanced option,
and that isolation rests on one database and one secrets store per tenant rather than on the
deploy credential. So the open action is to amend harness#141 so it stops contradicting the
ADR, keeping customer-owned Cloudflare as the exit path and a later tier. If Nick wants the
opposite, the ADR changes first. The same ADR is why a customer has no Cloudflare dashboard
of their own, which the H1 logs row depends on.

The ADR also puts the `$5` Workers Paid plan on the whitelist phase and Workers for Platforms
behind the `Deployer` port before the roughly 100-script wall, so H1 hosting is a plain Worker
and D1 per venture.

### H1: unblock the first paying customer

| Item | Scope | Maps to | Deps | Size |
| :--- | :--- | :--- | :--- | :--- |
| Tables | `[tables]` in the manifest, forward-only migrations, CRUD with filter, sort and pagination, batched parallel reads, the small access vocabulary and nothing wider than a row owned by a user or a tenant, contract at `/__surface` | NEW harness epic | [harness#138](https://github.com/Cratefield/harness/issues/138), [harness#23](https://github.com/Cratefield/harness/issues/23) | L |
| Generated TypeScript client | `@cratefield/client` generated from the Tables contract, published on every deploy | NEW, creates a repo | Tables | M |
| Hosting on our account | one Worker and one D1 per venture on the platform credential, `you.cratefield.app` subdomains, Workers for Platforms behind the `Deployer` port | [cp#7](https://github.com/Cratefield/control-plane/issues/7), [harness#141](https://github.com/Cratefield/harness/issues/141), NEW cp issue | the account decision above | L |
| Billing and metering | Stripe subscription per venture on `adapter-stripe`, request and storage counters, free-tier throttle rather than overage, plus the open decision on metering tenant databases past the first | NEW cp issue | [cp#12](https://github.com/Cratefield/control-plane/issues/12) | M |
| Agent-safe errors | `--json` on every `fz` verb, a stable error-code catalogue, exit codes documented in llms.txt | extend [harness#140](https://github.com/Cratefield/harness/issues/140) | none | S |
| Email and password, magic links | registration with argon2, login, magic-link request and consume, with the rate limiting and lockout that must ship with them |  [auth#19](https://github.com/Factory-Zero/auth/issues/19), [auth#20](https://github.com/Factory-Zero/auth/issues/20), [auth#21](https://github.com/Factory-Zero/auth/issues/21), [auth#12](https://github.com/Factory-Zero/auth/issues/12) | [auth#41](https://github.com/Factory-Zero/auth/issues/41) | M |
| Log tail from the CLI | `fz logs tail` over the Workers Tail and Logpush APIs, since ventures run in our account and a customer has no dashboard to be pointed at | extend [cp#11](https://github.com/Cratefield/control-plane/issues/11), [harness#140](https://github.com/Cratefield/harness/issues/140) | cp#7 | S |
| Email abuse and deliverability | per-venture sending domains through Resend, platform send caps and abuse controls, a shared-domain policy for the free tier | NEW cp issue | cp#7 | M |
| Data residency | a D1 location hint chosen at provisioning, the region recorded and shown in the dashboard; latency is the H3 programme | NEW cp issue | cp#7 | S |

Passkeys and Google alone lose B2B deals, which is why the auth row is in H1 rather than
later. All four of those auth issues are open and unstarted.

### H2: parity table stakes

| Item | Scope | Maps to | Deps | Size |
| :--- | :--- | :--- | :--- | :--- |
| TypeScript functions | a sidecar Worker running customer TypeScript, mounted as ADR 0009 describes, reaching data through the Tables contract only | NEW harness epic, reuses [harness#56](https://github.com/Cratefield/harness/issues/56), [#61](https://github.com/Cratefield/harness/issues/61), [#62](https://github.com/Cratefield/harness/issues/62), [#63](https://github.com/Cratefield/harness/issues/63), [#66](https://github.com/Cratefield/harness/issues/66), [#67](https://github.com/Cratefield/harness/issues/67), [#142](https://github.com/Cratefield/harness/issues/142) | Tables, client | XL |
| Fast loop v1 | compose from precompiled catalog artifacts, config change under 10 s, new venture under 60 s, publish the measured numbers | [harness#59](https://github.com/Cratefield/harness/issues/59), [harness#139](https://github.com/Cratefield/harness/issues/139), NEW harness issue | harness#138 | M |
| Data browser | generated from the Tables contract, plus a read-only SQL console and CSV export | NEW cp issue | Tables | M |
| Log and trace UI | logs and spans in the account dashboard, on top of the H1 log tail | extend [cp#11](https://github.com/Cratefield/control-plane/issues/11) | cp#7, log tail | M |
| Blob storage | the Blob port, R2 adapter and a native directory adapter | [harness#105](https://github.com/Cratefield/harness/issues/105) | none | M |
| Realtime | WebSocket rooms on Durable Objects, with a native adapter | [harness#103](https://github.com/Cratefield/harness/issues/103) | none | L |
| Backups | D1 Time Travel plus a scheduled export to R2, restore documented | NEW cp issue | cp#7 | S |
| Custom domains | Cloudflare for SaaS custom hostnames, paid tier only | NEW cp issue | cp#7, cp#12 | M |
| Safe upgrades | module upgrade, removal and migration deployment plans | [harness#145](https://github.com/Cratefield/harness/issues/145) | harness#138 | M |
| MCP server | a thin wrapper over `fz --json`, no second surface to maintain | NEW, creates a repo | agent-safe errors | S |
| Benchmarks | a `bench/` harness and the published page, see section 5 | NEW harness issue | Tables | M |
| Staging and preview environments | a second venture per project, promotion between them | NEW cp issue | cp#7 | M |

### H3: the moat

| Item | Scope | Maps to | Deps | Size |
| :--- | :--- | :--- | :--- | :--- |
| Tenants as a product | a lifecycle API where create, export and delete make GDPR a property of the architecture, promotion past the 10 GB cap onto Postgres through the existing export and import, and the open decision on pricing tenant databases past the first | [harness#23](https://github.com/Cratefield/harness/issues/23), NEW harness epic | H1 Tables | XL |
| Agency console | one organisation, many client ventures, clone a template, per-client billing, white-label domains | NEW cp issue | billing, custom domains | L |
| Performance programme | region-pin the primary, KV and Cache for immutable reads, D1 read replication, Durable Object warmers | NEW harness epic | benchmarks | L |
| Distribution | starter kits for Next.js, SvelteKit and Expo, Claude Code and Cursor templates carrying llms.txt and MCP, a deploy button | NEW, creates a repo | client, MCP | M |
| Sovereign exit | one command moves a venture to a customer-owned Cloudflare account | [harness#141](https://github.com/Cratefield/harness/issues/141) | hosting | M |

Prompt to UiSpec ([cp#9](https://github.com/Cratefield/control-plane/issues/9)) and the CMS
module ([cp#10](https://github.com/Cratefield/control-plane/issues/10)) stay on the list below
everything above. Neither is what a customer is blocked on.

## 5. Benchmarks to publish, and nothing else

Four numbers, because four defensible numbers beat a page of them.

1. **Cold start.** Time to first byte against an evicted venture, split into wasm
   instantiate and first D1 query, p50 and p99, from five vantage points off Cloudflare over
   seven days.
2. **Warm authenticated read.** p99 at 50 requests per second for ten minutes, measured both
   from the D1 primary's region and from a distant one. The gap is the region-pin effect,
   and publishing it is more useful than hiding it.
3. **Per-tenant write ceiling.** Single-row insert with the audit chain on, p99 at 50
   requests per second, plus the rate at which p99 doubles on one D1. It is the measured
   single-writer number, and it sells database-per-tenant, because each tenant gets its own
   ceiling instead of sharing one.
4. **Provisioning time.** A configuration change to a live venture, and a new venture from
   nothing to its first successful request, p50 and p99. This is the number the fast loop
   work has to hold, and publishing it is what stops the 10 s and 60 s targets being
   marketing.

Rules for publishing them, which are the point of publishing at all:

- Pin the harness commit that produced every number.
- Publish the scripts and the raw samples, not just the summary.
- State the D1 region.
- Never mix warm and cold measurements in one figure.
- Report sample counts.
- Compare against Supabase only with an identical harness, or not at all.

## 6. Where the assessment is off

- **The hook overclaims as written.** Database-per-tenant removes the *cross-tenant* policy
  problem. User A against user B inside one tenant still needs authorisation, and Tables
  carries it. The site should say "no cross-tenant policy to get wrong".
- **Read replicas are over-weighted.** For one small D1 per tenant, region-pinning the primary
  and batching reads beat replication, which is why replication goes last.
- **The 10 GB cap is per tenant.** For the target customer that is a feature. The real gap is
  a documented promotion path to Postgres, which is why it is H3 and not a defect.
- **Hibernation is benchmark 1, not a separate concern.** D1 sits on a Durable Object, so an
  idle venture pays a D1 wake on its first query and benchmark 1 measures exactly that. Keep
  the benchmark and drop the claim that hibernation does not matter. What does not matter yet
  is Realtime-room hibernation, and the Realtime port
  ([harness#103](https://github.com/Cratefield/harness/issues/103)) is H2.
- **MCP is a small piece of work.** Once errors are machine-readable it is a thin wrapper;
  the `--json` flag on every verb matters far more, and it is an S.
- **"Stop selling Rust" is right for the product and wrong for the harness.** Readable MIT
  Rust is the exit story and the reason the portability claim is credible. Hide it in the
  product surface, keep it on the technology pages.
- **Five things the assessment missed entirely.** Billing and metering, custom domains,
  backups, customer-visible logs, and email-and-password authentication. Each blocks a paying
  customer more reliably than anything it did name, and all five are in H1 or H2 above.

## 7. Site copy consequences

No site change now. cratefield.com says misconfiguration fails `cargo test` rather than
production, and that is accurate for everything that ships: module composition, ports, routes
and contracts are checked at compile time, and Tables does not exist.

Once Tables ships the claim splits in two. Module composition still fails at compile time. A
customer schema is a runtime value in the manifest, so it fails at manifest validation and at
deploy time, earlier than production but later than `cargo test`. `COPY.md` in
`Cratefield/website` carries that row when Tables lands, not before.

## 8. The review, item by item

The ten proposals from the review, and what this revision did with each.

1. **Vocabulary, pricing and billing.** Applied with change. They now say the same thing, but
   how tenant databases past the first are metered is left open for Nick rather than given an
   invented number.
2. **The hibernation contradiction.** Applied with change. The claim is narrowed, not
   dropped: benchmark 1 is the D1 wake, and only Realtime-room hibernation is premature.
3. **Provisioning time as the fourth benchmark.** Applied.
4. **Email abuse controls and per-customer sending domains in H1.** Applied, as a new
   control-plane issue at M.
5. **Data residency as a compliance feature.** Applied, as a new control-plane issue at S,
   cross-referenced to the H3 performance programme.
6. **H1 serves B2B and agencies, AI builders arrive in H2 and H3.** Applied.
7. **The access vocabulary's limits, and that many apps need H2 functions.** Applied.
8. **Cut fast loop v1 and customer-visible logs from H1.** Applied with change. Fast loop v1
   moves to H2 with its targets intact. Logs split rather than being cut, because ventures
   run in Cratefield's Cloudflare account and a customer has no dashboard to be linked to:
   `fz logs tail` stays in H1 at S, the dashboard log UI moves to H2.
9. **Amend the site's compile-time safety claim.** Deferred. The claim is accurate for
   everything that ships. Section 7 records what changes when Tables lands.
10. **Schema enum, conformance corpus and field-versus-function rule in the Tables issue.**
    Applied. Section 2 carries the reasoning, appendix entry A1 carries the scope.

## Appendix: the filed issues

**Filed on 8 September 2026.** All eighteen were opened: nine in `Cratefield/harness`
(#153 to #161) and nine in `Cratefield/control-plane` (#26 to #34). Each entry names the
repository, the title, the body and the labels it was filed with, and the issue it became.
Every filed body ends with a link back to this document, and with a `Depends on:` line
where the entry names a dependency.

Two notes on labels. `Cratefield/control-plane` has no `enhancement` label, so the
control-plane entries use `provisioning`, `gui`, `pricing`, `design` and `connections`
instead. The two epics that needed a label of their own now have one: `epic:tables` and
`epic:tenants` were created in `Cratefield/harness` in the same blue as `epic:schema`, and
are carried by A1 and A6 alongside the labels listed below.

### A1. Tables: declared tables, a typed data API and a published contract

- **Repo:** `Cratefield/harness`
- **Issue:** [harness#153](https://github.com/Cratefield/harness/issues/153)
- **Labels:** `design`, `kernel`, `implementation`, `epic:tables`
- **Body:** A venture should be able to declare its own tables in the venture manifest and
  get a working data API without writing a module crate. Add a `[tables]` section to the
  manifest that generates forward-only migrations, and serve CRUD endpoints per table with
  filter, sort and pagination, plus a batched endpoint that runs several declared reads in
  one request and in parallel, because a sidecar or a browser client pays a round trip for
  each one otherwise. Access is a small fixed vocabulary evaluated in Rust,
  `public-read | owner | tenant-members | admin`, and it must stay a vocabulary rather than
  grow into a policy language. Publish the resulting contract at `/__surface` so the
  TypeScript client, the data browser and the MCP server can all be generated from one
  source. Depends on #138 for the manifest and #23 for the per-tenant schema.

  Three things belong in the scope from the start. Represent a table as a small
  purpose-built schema enum rather than JSON Schema, because JSON Schema is sprawling and
  does not express the SQLite and Postgres DDL mapping; emit JSON Schema as a derived view
  for anyone who wants one. Ship a conformance corpus of schema, input and expected verdict,
  run in CI against both the Rust validator and the generated Zod schema, because those two
  will disagree on empty versus absent, number coercion, null versus missing, unicode length
  and dates. And write down the rule that bounds the declaration surface: anything
  referencing another row or another request is a function, not a field, so overlap checks,
  state machines and side effects go to a module or a sidecar rather than growing the
  manifest.

  This is the single largest unlock in the roadmap: it is what lets someone build a simple
  CRUD product on Cratefield without Rust.

### A2. Generate and publish `@cratefield/client` from the Tables contract

- **Repo:** `Cratefield/harness`
- **Issue:** [harness#155](https://github.com/Cratefield/harness/issues/155)
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
- **Issue:** [harness#159](https://github.com/Cratefield/harness/issues/159)
- **Labels:** `ci`, `implementation`
- **Body:** Provisioning currently implies a build. Add a linker step that composes a
  venture from precompiled per-module artifacts so a config-only change does not go through
  cargo. Targets to hold and then publish: a configuration change live in under 10 seconds,
  a brand new venture live in under 60 seconds. Build on the content-addressed artifact
  cache (#59) and the reviewed catalog (#139), and measure with the harness commit pinned so
  the published numbers mean something. If the targets turn out to be unreachable, say so
  and publish the real numbers instead; the measured number is the product.

### A4. TypeScript functions as a sidecar Worker

- **Repo:** `Cratefield/harness`
- **Issue:** [harness#157](https://github.com/Cratefield/harness/issues/157)
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
- **Issue:** [harness#156](https://github.com/Cratefield/harness/issues/156)
- **Labels:** `testing`, `docs`
- **Body:** Add a `bench/` harness that produces exactly four numbers and a page that
  publishes them: cold start time to first byte against an evicted venture split into wasm
  instantiate and first D1 query, which is also the D1 hibernation wake; warm authenticated
  read p99 at 50 rps measured both from the D1 primary's region and from a distant one; the
  per-tenant write ceiling as a single-row insert with the audit chain on plus the rate at
  which p99 doubles; and provisioning time for a configuration change and for a brand new
  venture, p50 and p99. Rules that
  are part of the deliverable, not an afterthought: pin the harness commit, publish the
  scripts and the raw samples, state the D1 region, never mix warm and cold in one figure,
  report sample counts, and compare to another vendor only with an identical harness or not
  at all. Four defensible numbers are worth more than a page of favourable ones.

### A6. Tenants as a product: lifecycle API and a promotion path

- **Repo:** `Cratefield/harness`
- **Issue:** [harness#154](https://github.com/Cratefield/harness/issues/154)
- **Labels:** `design`, `epic:schema`, `epic:tenants`
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
- **Issue:** [harness#158](https://github.com/Cratefield/harness/issues/158)
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
- **Issue:** [harness#160](https://github.com/Cratefield/harness/issues/160)
- **Labels:** `cli`, `docs`, `needs-human`
- **Body:** Publish an MCP server so an agent can create a venture, add a module, plan and
  deploy without screen-scraping CLI output. It must be a thin wrapper over `fz --json` and
  the stable error-code catalogue, with no second surface of its own to drift, which is why
  it is small and why it is blocked on the agent-safe errors work in #140. Needs a new
  public repository and a publishing token, hence `needs-human`.

### A9. Starter kits and a deploy button

- **Repo:** `Cratefield/harness`
- **Issue:** [harness#161](https://github.com/Cratefield/harness/issues/161)
- **Labels:** `docs`, `needs-human`
- **Body:** Create `Cratefield/starters` with working starters for Next.js, SvelteKit and
  Expo that use the generated TypeScript client, plus Claude Code and Cursor project
  templates that ship `llms.txt` and the MCP server configured. Add a "Deploy to Cratefield"
  button that takes a repository to a live venture. This is the distribution half of the
  second audience: builders working with AI tools adopt what their tool already knows how to
  scaffold. Needs a new public repository, hence `needs-human`.

### B1. Host ventures on Cratefield's Cloudflare account

- **Repo:** `Cratefield/control-plane`
- **Issue:** [cp#26](https://github.com/Cratefield/control-plane/issues/26)
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
- **Issue:** [cp#27](https://github.com/Cratefield/control-plane/issues/27)
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
- **Issue:** [cp#28](https://github.com/Cratefield/control-plane/issues/28)
- **Labels:** `gui`
- **Body:** Generate a data browser in the dashboard from the Tables contract published at
  `/__surface`, so it stays correct without being maintained separately: list and edit rows,
  filter and sort, follow relations. Add a read-only SQL console and CSV export of a table
  or a query result. Read-only is the important constraint on the console; a write console
  against a customer's live tenant database is a support incident waiting to happen. Blocked
  on the Tables work in the harness.

### B4. Backups and restore

- **Repo:** `Cratefield/control-plane`
- **Issue:** [cp#29](https://github.com/Cratefield/control-plane/issues/29)
- **Labels:** `provisioning`, `design`
- **Body:** Every venture needs a recovery story before the first paying customer, not
  after. Use D1 Time Travel for point-in-time recovery inside its retention window, and add
  a scheduled export of each venture's database to R2 for anything older. Surface the last
  successful backup in the dashboard, and document and test the restore path, because a
  backup that has never been restored is not a backup. Small, and it removes an objection
  that comes up in every serious evaluation.

### B5. Custom domains through Cloudflare for SaaS

- **Repo:** `Cratefield/control-plane`
- **Issue:** [cp#30](https://github.com/Cratefield/control-plane/issues/30)
- **Labels:** `provisioning`, `connections`
- **Body:** Let a paying customer put a venture on their own domain using Cloudflare for
  SaaS custom hostnames: add the hostname, show the DNS record to create, verify it, issue
  the certificate, and show the status while it settles. The free tier stays on a
  `you.cratefield.app` subdomain, as `docs/PRICING.md` sets out, since custom hostnames
  carry a per-hostname cost. Deferring this blocks anyone who wants a branded backend, which
  is most of the agency audience.

### B6. Staging and preview environments

- **Repo:** `Cratefield/control-plane`
- **Issue:** [cp#31](https://github.com/Cratefield/control-plane/issues/31)
- **Labels:** `provisioning`, `design`
- **Body:** Give a project more than one environment: a staging venture alongside
  production, with its own database and secrets, and a promotion action that moves a module
  set and its migrations from staging to production. Anyone who has used a hosted backend
  expects this, and without it every schema change on Cratefield is tested in production.
  Depends on provisioning (#7) and on the safe-upgrade plans in `Cratefield/harness#145`.

### B7. Agency console

- **Repo:** `Cratefield/control-plane`
- **Issue:** [cp#34](https://github.com/Cratefield/control-plane/issues/34)
- **Labels:** `gui`, `design`
- **Body:** Serve the audience that runs many client backends rather than one. One
  organisation holds many ventures, a template venture can be cloned for a new client,
  billing is per client and can be passed through, and each client venture can carry its own
  domain and branding. This is where database-per-tenant stops being an architecture
  argument and becomes a commercial one, because an agency can hand a client an isolated
  database and an export without doing any work for it. Depends on billing and custom
  domains.

### B8. Email abuse controls and per-venture sending domains

- **Repo:** `Cratefield/control-plane`
- **Issue:** [cp#32](https://github.com/Cratefield/control-plane/issues/32)
- **Labels:** `provisioning`, `connections`, `pricing`
- **Body:** A free tier sending through one shared Resend account is an abuse magnet, and one
  spam incident damages deliverability for every venture on the platform. Give a paying
  venture its own sending domain or a subdomain of ours, with the DNS records to create and
  verification surfaced the same way custom hostnames are. Keep a low shared-domain cap for
  the free tier, as `docs/PRICING.md` already proposes, and add platform-level controls that
  do not depend on the customer: per-venture send rate limits, a bounce and complaint
  threshold that suspends sending, and an alert when either moves. Deliverability is shared
  across all ventures on a shared domain, which is why this is platform work and not a
  per-customer setting.

### B9. Data residency: pick and show a venture's region

- **Repo:** `Cratefield/control-plane`
- **Issue:** [cp#33](https://github.com/Cratefield/control-plane/issues/33)
- **Labels:** `provisioning`, `design`
- **Body:** Residency is the first question a GDPR-conscious B2B buyer asks after isolation,
  and it is a compliance feature before it is a performance one. Let a venture choose a
  region at provisioning time, pass it through as the D1 location hint, record what was
  actually granted rather than what was asked for, and show the region in the dashboard and
  in the API. Small, because the hint is one field on creation; the value is being able to
  answer where the data lives without qualifying the answer. The latency half of region
  choice belongs to the H3 performance programme in `Cratefield/harness`, which pins a
  primary near its users; this issue is only about choosing, recording and showing it.
