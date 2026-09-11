# Tenant isolation and connection routing

Design for issue #32; the implementation follows it. This is the point
where "one database per tenant" stops being a decision and becomes
something a request cannot get around.

Context: ADR [0008](adr/0008-native-runtime-is-multi-tenant-database-per-tenant.md)
(one database per tenant, a separate control database, two-tier
secrets), [RECONCILIATION.md](RECONCILIATION.md) (#29, which owns boot
and the registry), and ARCHITECTURE [§7](ARCHITECTURE.md). This applies
to the **native** runtime. The Cloudflare path has one venture per
Worker and one D1; §6 says how it keeps one module codebase anyway.

> **Status: proposed, revised once.** Not signed off. The acceptance for
> #32 asks a reviewer to answer the questions in
> [§11](#11-review-questions) without reading the rest first. Record the
> sign-off here when that happens.
>
> The first draft was reviewed against the code and did not survive it.
> Four claims were false: that the extractor could reach a pool registry
> through handler state, that a `TenantConn` could hold a connection
> checkout (core cannot name a sqlx type, and an axum extractor is
> owned and `'static` regardless), that `pub(crate)` could admit the
> runtimes while excluding modules across crate boundaries, and that
> `ports.db` had a few dozen callers rather than sixty across three
> runtimes. Two whole subjects were missing: that a tenant is not only a
> database (§8a) and that scheduled and deferred work has no database at
> all under the plan as first written (§8, §10). Those corrections are
> the difference between this revision and the first, and they are why
> the sections below argue rather than assert.

## 1. What already exists

This design assembles shipped pieces. Naming them is the point: the
failure mode for an issue this size is a second mechanism beside a
working one.

- **The registry and its statuses.** RECONCILIATION.md §6 defines
  `active`, `provisioning` and `degraded`, and names `unknown-tenant`
  and `tenant-degraded` as the answers. Both documents are proposed and
  neither slug exists: `problems.rs` has no `unknown_tenant` or
  `tenant_degraded`, and `docs/ERRORS.md` does not list them. Two
  unsigned designs citing each other is not a shipped contract —
  registering the slugs is work item 1 of §10, not a dependency.
- **DSNs come from the global secrets store.** `cratefield-secrets`
  ships the two-tier store, and `Secrets::global` is reachable only with
  a `HarnessOnly` proof that module code cannot construct (#39). A
  tenant's DSN is a global secret named `tenants/<id>/db_ref`.
- **Host parsing and normalisation are shipped.** `runtime-native`'s
  host layer (#129) refuses a production request whose `Host` this
  deployment does not answer for, with `421 Misdirected Request`, and
  exempts loopback so probes keep working. Its *parsing* is reusable;
  its *allowlist* is not an extension point. `HostTrust.allowed` is
  built from one compiled-in `Venture` plus `TRUSTED_HOSTS`, so in
  production every tenant host but the venture's own is refused 421
  before resolution could run. Replacing that allowlist with a registry
  lookup is a rewrite of `HostTrust`, and §3 treats it as one.
- **Forwarded headers already have one trust point.** `TRUSTED_PROXY_HEADERS`
  (#131) decides when a forwarded header is believable. Tenant
  resolution reads `Host` and nothing else, for the reason §3 gives.
- **Request state already travels in extensions.** ADR 0007: there is no
  ambient current request, and `Scope` is an extractor. `Tenant` joins
  it, which is what makes §5 possible.
- **DSN redaction already exists, at the type.** `Display for DbError`
  runs every message through `scrub_text`, which rewrites
  `postgres://user:pass@host` to `postgres://[redacted]@host` (#135). So
  a *displayed* `DbError` is already safe. What is not covered is
  `Debug`, which derives raw, and anything that formats a DSN before it
  becomes a `DbError` at all.

## 2. The tenant identity

```rust
/// Immutable. Constructed only by the resolution layer, from a registry
/// row; never from a header, a path segment, or module code.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Tenant {
    id: TenantId,       // the registry's primary key, a slug
    status: TenantStatus,
}
```

`TenantId` is not `String`. A newtype with a private field and no public
constructor is what stops a module from asking the registry for a
neighbour's pool by writing a different string — the same shape as
`HarnessOnly` in #39, and for the same reason: the type is the boundary,
not a convention about how to call a function.

`Tenant` is `Clone` because a request carries it into a deferred job
(§8). It is not `Deserialize`, which is the trait that matters: the
threat is an identity **read back in** from an attacker-supplied body,
not one written out. `Serialize` is fine and probably wanted, so a
tenant id can be a structured log field.

## 3. Resolution

**Host, and only host.** `#32` leaves the policy open (host vs header vs
key) and asks for the hook. Host is the answer for the native runtime,
and the alternatives are worth refusing explicitly:

- A **header** (`X-Tenant-Id`) is caller-supplied. It would need to join
  the `TRUSTED_PROXY_HEADERS` contract, and a deployment that got that
  list wrong would let any caller name any tenant. The blast radius of
  that mistake is every tenant's data.
- An **API key** resolves to a tenant only after a database read, and the
  database that read happens in is the thing being resolved. The
  bootstrap is circular unless the key lives in the control database,
  which makes every request pay a control-database round trip.
- **Host** is established before any tenant state is consulted, is
  already validated (#129), and is what the registry is keyed on for
  operational reasons anyway: a tenant's domain is how its customers
  reach it.

The hook stays: resolution is a trait so a deployment that must use
something else can, and so tests can resolve without DNS.

```rust
pub trait ResolveTenant: Send + Sync {
    fn resolve(&self, host: &str) -> Resolution;
}

pub enum Resolution {
    Found(Tenant),
    Unknown,                 // 404 unknown-tenant
    Degraded(TenantId),      // 503 tenant-degraded
}
```

**The layer runs inside `Harness::router`, not beside the host check.**
Three things force this and none of them are style:

- *Visibility.* A `TenantConn` constructor must be callable from
  `runtime-native` and `runtime-cloudflare` and not from `module-*`.
  Every one of those is a different crate, so `pub(crate)` cannot
  express it and a compile-fail test written in the secrets crate's
  style would prove nothing about the runtimes. If core mints the
  `Tenant` — runtimes supplying only a `ResolveTenant` impl — the
  constructor never leaves core and `pub(crate)` says exactly the right
  thing.
- *Request id.* `scope_layer` runs inside the harness. A refusal from
  outside it carries no `instance`, which is the reason #143's readiness
  guard was pushed inside rather than left at the edge.
- *Probes.* `/__health`, `/__ready`, `/.well-known` and `/ui` have no
  tenant. Resolution outside the router would 404 every liveness probe
  in production, because those arrive by loopback and the host layer's
  loopback exemption is not resolution's exemption.

Order, therefore: client-IP and host in the native server; then inside
the router cors, token-response, scope, gateway guard, readiness, and
**resolution last before the module routes**, applying to `/v1/*` only.

The two refusals are distinguishable, and saying so is more honest than
the alternative: an unserved host is `421` from the host layer, an
unknown tenant on a served host is `404`. That does leak whether a
tenant exists to a caller who already knows a hostname the deployment
answers for. The alternative — answering 421 for both — would mean the
host layer consulting the registry, which is the coupling §1 just
refused. Accepted, and recorded here rather than argued away.

## 4. The pool registry

```rust
pub struct PoolRegistry { /* … */ }

impl PoolRegistry {
    /// The tenant's pool, opened on first use. The only place a DSN is
    /// read, and the only thing that holds one.
    async fn pool(&self, tenant: &Tenant) -> Result<TenantPool, PoolError>;
}
```

- **Lazy.** A pool opens on the tenant's first request, not at boot.
  Boot already touches every tenant database for reconciliation; holding
  the connections afterwards would mean a replica's idle cost scales with
  the tenant count rather than with its traffic.
- **Evicted when idle.** A pool with no checkout for `TENANT_POOL_IDLE`
  (default 5 minutes) closes. The registry is a cache, not an inventory.
- **Capped per tenant** (`TENANT_POOL_MAX`, default 8) and **in total**
  (`TENANT_POOL_TOTAL`, default 64). The per-tenant cap is what stops one
  busy tenant taking every connection on a shared cluster; the total cap
  is what stops the process taking every connection on the *server*,
  which is the failure the per-tenant cap alone does not prevent. A
  checkout that would exceed either waits with a deadline and then
  refuses — the same fail-closed instinct as #136's outbound budget,
  which refuses rather than queues unboundedly.
- **The caps are adapter options, not registry bookkeeping.**
  `Postgres::connect(url)` takes no options at all today — no
  `max_connections`, no idle timeout — so the per-tenant cap is a
  `PgPoolOptions` change in `adapter-postgres` before it is anything
  here. The **total** cap is not something sqlx offers across pools: it
  needs a semaphore the registry holds, acquired around every
  `execute`, `query` and `batch`. `batch` holds its connection across
  `pool.begin()`, so the permit has to span the whole batch, not each
  statement. Without that semaphore `TENANT_POOL_TOTAL` is a config key
  that does nothing, which is worse than not having it.
- **Nothing else knows a DSN.** The registry maps a connect failure to
  `PoolError::Unreachable { tenant }` before the URL can reach a log
  line or a response body. `Display for DbError` already scrubs, so this
  is not the only defence — but `Debug` derives raw, and a DSN formatted
  before it ever becomes a `DbError` is scrubbed by nothing. Not
  producing the string is the first line; the sink is the second.

## 5. `TenantConn`: the only route to a database

The requirement is that a module cannot reach any database but its
tenant's. Today `ModuleContext` holds `Ports`, `Ports` holds one
`Arc<dyn Database>`, and the context is built once and captured in
handler state. That single handle is the thing to remove.

`TenantConn` lives in **core**, because §6 wants the identical extractor
on Cloudflare and core is the only crate every module depends on. Core
cannot name a sqlx type — `adapter-postgres` is forbidden from wasm — so
`TenantConn` holds a `Tenant` and an `Arc<dyn Database>`, never a
checkout:

```rust
// An axum extractor. Rejects with 500 when no Tenant is in the
// extensions, which can only happen if the layer order in §3 is wrong.
pub struct TenantConn {
    tenant: Tenant,
    db: Arc<dyn Database>,   // the tenant's pool, already resolved
}

impl TenantConn {
    pub fn tenant(&self) -> &Tenant;
}

impl Database for TenantConn { /* delegates to `db` */ }
```

It is fair to say this is `ports.db` with a private constructor and a
`Tenant` welded to it. That is the whole idea: the handle a module can
reach is one it cannot have obtained for a tenant other than the
request's.

**How the handle gets there.** The extractor cannot pull a
`PoolRegistry` out of handler state — state is per module and privately
typed (`Arc<ModuleState>`), and a `FromRef` bound on every module's
private struct is not a contract worth having. So the resolution layer
puts the resolved `Arc<dyn Database>` into the request extensions
alongside the `Tenant`, and the extractor reads both. That has a cost
worth naming: the pool opens during resolution, so it opens for requests
the readiness gate is about to refuse. Resolution running last (§3)
keeps that to `/v1/*` on a deployment that is otherwise serving.

A handler takes it the way it already takes `Scope`:

```rust
async fn join(scope: Scope, db: TenantConn, State(ctx): State<Arc<ModuleContext>>) -> …
```

Three properties follow, and they are the acceptance criteria:

1. **`TenantConn` cannot be constructed in module code.** Its fields are
   private and it has no public constructor; the only way to obtain one
   is the extractor, which reads a `Tenant` the resolution layer put in
   the extensions. A compile-fail test holds this, the way #39's hold
   `HarnessOnly`.
2. **There is no "any connection" API.** `Ports.db` stops being reachable
   from `ModuleContext` on the native path. This is the breaking change
   in the design and §10 is its migration.
3. **A `TenantConn` cannot be re-pointed at another tenant.** Its
   `Tenant` and its handle are set together at construction and neither
   is reachable to change.

   The stronger claim — that a handler cannot stash one — would be
   false, and worth being explicit about because the first draft made
   it. An axum extractor yields an **owned** value and handler futures
   are `'static`, so nothing stops a `TenantConn` going into a
   `OnceLock` or a spawned task. The modules already do exactly this
   with the context: `module-email-signup` stashes an
   `Arc<ModuleContext>` in a process-wide `OnceLock` at router build and
   its event handlers read it back. A stashed `TenantConn` is a handle
   to one tenant's database used later, which is a bug, but it is not
   cross-tenant access — and if the type held a live checkout instead,
   stashing it would pin a connection the registry wants to evict and
   eight slow handlers would starve a tenant at the default cap. Holding
   an `Arc<dyn Database>` rather than a checkout is what makes that
   failure impossible.

## 6. The Cloudflare path keeps one module codebase

A Worker serves one venture and one D1. If `TenantConn` existed only on
the native runtime, every module would need two code paths, and the one
exercised in production for most ventures would be the one without the
isolation.

So a runtime with no registry inserts a **single implicit tenant** — the
venture itself, status `active`, its handle the one database binding —
and `TenantConn` resolves identically. Modules are written once, against
the stricter shape.

That is not only the Cloudflare path. The browser runtime is a third
one, and **native without a control database is a fourth**: every
development run and every test. Scoping the implicit tenant to
Cloudflare, as this section first did, would mean `cargo test` cannot
resolve a tenant and every module suite 500s. The rule is therefore
about the *absence of a registry*, not about which runtime it is.

## 7. Isolation is the database boundary

No `search_path` switching, no row-level security, no shared tables, per
ADR 0008. The consequence worth stating: **the misrouting test cannot be
written from the harness's side**, because from inside the process both
tenants look like `Database` trait objects. It is written from the
databases' side — two real databases, interleaved concurrent requests for
both tenants, then each database is asked what it was actually told to
do. Anything less tests the mock.

"Asked what it was told to do" needs a mechanism, or it is a wish. The
one this design commits to is **row inspection against two real
Postgres databases**: each tenant's request writes a row that names the
tenant, and each database is then queried directly for rows naming the
other. `pg_stat_statements` would be more thorough and is not enabled by
default; the assertion that matters is the one about data, not
statements. The existing `PgFixture` creates one throwaway database per
harness, so this needs a two-database fixture — a testing-kit change,
listed in §10.

## 8. Deferred work carries the tenant it was created with

`Defer` and the cron scheduler run outside a request, so there is no
extension to read. A deferred job records its `TenantId` at creation and
resolves the pool again when it runs — it does not capture a
`TenantConn`, which would hold a checkout across an unbounded wait and
pin a pool the registry wants to evict. A cron fan-out runs once per
`active` tenant, each under its own identity.

This is the case #129's issue text called out as losing tenant identity,
and it is the one that fails silently: a job that runs under the last
request's tenant writes plausible rows into the wrong database.

## 8a. A tenant is not only a database

The largest thing neither #32 nor ADR 0008 says out loud. `ModuleContext`
carries one compiled `Venture`, and modules build user-visible strings
from it: confirmation links and redirects from `venture.public_url`,
mail `From:` and branding from `venture.domain` and `venture.brand`,
and the harness sets CORS from `venture.cors_origins`.

Route tenant B's request to tenant B's database and nothing else, and
its confirmation mail still links to tenant A's domain, from tenant A's
sending address, under tenant A's branding. The database boundary held
and the product broke. ADR 0008 says Factory Zero's own venture "is an
ordinary tenant", so this is not hypothetical.

`Tenant` therefore carries the venture-shaped fields — domain,
`public_url`, brand — and `ctx.venture` becomes per request on the
native path, or modules read them from `Tenant`. Either way it is an API
change of the same size as the database one, and it belongs in the same
`HARNESS_API` bump (§10). Deciding *which* is an open question (§12).

## 8b. The other stateful ports

Issue #32 is scoped to databases, and ADR 0008's "a compromised venture
database exposes that venture's secrets and nothing else" does not
survive a shared Redis with unprefixed keys. Today `RedisKv` keys are
`kv:{key}`, the rate limiter's are `rl:{key}`, `DirBlob` scopes by
module only, and realtime rooms are in-process.

None of that is this issue's to fix, and all of it is a hole in the same
wall. The rule: every shared-infrastructure key gains a `TenantId`
prefix where the port is constructed, so a module cannot spell a
neighbour's key. Filed separately rather than smuggled in here, and
named so the boundary claim in `SECURITY.md` stays true when it is
written.

## 9. The ceiling

Pool-per-tenant in one process is fine at six tenants and it is not fine
at six hundred. The number that matters is not the tenant count but the
product of *concurrently active* tenants and `TENANT_POOL_MAX` against
the cluster's `max_connections`. At the defaults (8 per tenant, 64
total), one replica sustains 8 busy tenants before the total cap is what
refuses, not the per-tenant one.

Past that there are two answers and the design commits to neither now:

- a connection **proxy** (PgBouncer in transaction mode) so pools
  multiplex, which keeps one process serving everyone;
- **one process per tenant**, which is the shape the Cloudflare harness
  already has, and where the two paths converge — ADR 0008's own
  consequence note.

What this design owes the future is that the choice stays open: nothing
above assumes a process serves more than one tenant, so the second answer
is a deployment change and not a rewrite.

## 10. Migrating the existing modules

The first draft of this section said "four modules and the auth crates,
mechanical but not small". That was wrong by a factor: `ports.db` has
**60 callsites**, across **three** runtimes (native, Cloudflare **and
browser**), the testing kit, `/__ready`'s probe, and the `requires(&[Port::Db])`
check in `Harness::build`. Being wrong about the size is how a migration
plan turns into a long red tree, so the corrected order is deliberately
slower.

This is a **`HARNESS_API` bump and a core major**. `scheduled` and the
event handlers change signature (§8), `Ports` changes shape, and module
crates are published (ADR 0005/0011), so "the compiler finds every
caller" is true inside this workspace and false for anyone consuming the
published crates. Saying so is part of the design.

0. **Register the problems.** `unknown-tenant` and `tenant-degraded`
   into `problems.rs` and `docs/ERRORS.md`. Both documents currently
   cite the other for these; neither has them. **Done** (#32).
0b. **Reword RECONCILIATION.md §6** so the registry row, not pool
   presence, is what refuses a degraded tenant — see §12. **Done** (#32),
   and it needed more than a reword: see the note below.
1. **Adapter first.** `PgPoolOptions` on `Postgres::connect` (per-tenant
   cap, idle timeout) and the registry's total-cap semaphore. Nothing
   consumes them yet, and without them §4 is aspirational.
2. **Types.** `Tenant`, `TenantId`, `TenantStatus`, `Resolution`,
   `ResolveTenant`, `PoolRegistry`, `TenantConn` in core. Still
   unconsumed.
3. **The testing kit learns the implicit tenant.** **Done** (#32), and it
   needed no change to the kit. This item assumed resolution would sit
   beside the host check, outside `Harness::router` — in which case the
   kit, which calls `router` and nothing else, would indeed insert no
   `Tenant` and 500 on the first module to adopt the extractor. §3 moved
   resolution *inside* `router` for three unrelated reasons (visibility,
   request id, probes), and the kit gets the implicit tenant for free as
   a consequence. `a_module_using_tenant_conn_works_under_the_kit` pins
   it, and fails if the no-registry path ever stops inserting.
4. **All three runtimes insert a tenant** — the implicit one on
   Cloudflare and browser, and on native too when there is no control
   database, which is every development and test deployment. §6's
   "Cloudflare only" was wrong; native without a registry gets the
   implicit tenant or `cargo test` cannot run.

   **Partly done** (#32). Core's layer inserts the implicit tenant
   whenever a deployment supplies no tenant plane, which covers
   Cloudflare, the browser and native-without-a-registry in one place
   rather than in three runtimes. What remains is native *with* a control
   database, wiring a `PoolRegistry` into `Ports.tenants`.
5. **Modules move one at a time**, each with its suite passing, request
   handlers before scheduled work.

   **Not started.** `TenantConn` exists and is proven end to end by
   `crates/core/tests/tenant_routing.rs`, but no shipped module uses it
   yet: they still capture `ctx.ports.db`.
6. **`scheduled`, events and `defer` gain a tenant** (§8), in the same
   API bump.
7. **Hide `db` from what a `ModuleContext` exposes** — `view_for` stops
   handing it over — while `Ports.db` stays for the runtimes,
   `/__ready` and the port-provision check, which all legitimately need
   a handle and none of which are module code.

Step 7 is deliberately not "remove the field". Removing it breaks the
runtimes and the probe for no isolation gain: the boundary that matters
is what a *module* can reach.

## 11. Review questions

Answer without reading the rest, then compare:

1. A request arrives for a host in the registry whose tenant is
   `degraded`. What does the caller get, and how many databases were
   touched?
2. A module handler wants to read a row for a tenant other than the one
   in the request. Name every step it would have to defeat.
3. A cron fires while tenant B's pool is evicted and tenant C is
   `degraded`. What runs?
4. A connect failure names the DSN in its error string. Where is that
   string first turned into something safe, and what is the second line
   of defence if that fails?
5. Tenant B's customer confirms an email address. What domain is in the
   link, and what address is it sent from?

## 12. Decisions taken, and what is still open

Three of these were settled on 2026-09-11 (issue #32). They are recorded
here rather than in a commit message, because each was a real fork and
the reasoning is the part that stops it being re-opened.

**`Tenant` stays `{ id, status }`; `ctx.venture` becomes per-request.**
The alternative — venture-shaped fields on `Tenant` — is harder to get
wrong, because you cannot hold a `Tenant` and read a neighbour's mail
domain. It was rejected on churn: it changes every module call site that
touches `ctx.venture`, *on top of* the `ports.db` migration in §10, and
two large mechanical migrations landing together is how a migration plan
turns into the long red tree §10 already warns about. The isolation that
matters is §5's, and that is unaffected either way.

**Pools are lazy; the registry row is authoritative.** RECONCILIATION.md
§6 refuses a degraded tenant "because the pool for it was never
registered", which implies boot registers pools. That sentence is wrong
on purpose now: refusal is decided by `TenantStatus` read from the
registry, never by whether a pool happens to exist. A replica's idle cost
should follow its traffic rather than the tenant count — and tying a 503
to pool presence would make an evicted idle pool indistinguishable from a
degraded tenant, which is the same silent conflation in a different
place. The one-sentence reword is work item 0b in §10.

*A consequence worth naming.* The old RECONCILIATION.md sentence was
carrying a safety property, not just describing a mechanism: a tenant
whose `degraded` write failed (control database gone mid-boot) was still
refused, because its pool had never been registered. Lazy pools remove
that guard — the registry row still reads `active`, and a lazy pool would
open for it happily, against a schema that is behind.

So the replica keeps the set of tenants **its own** reconciliation could
not complete, and resolution consults it alongside the registry row. The
replica that failed to reconcile a tenant is exactly the replica that
must not serve it, so process-local is the right scope; it also survives
the control database being unreachable, which is the case that produced
the problem. This is a §10 work item, not free.

**`TENANT_POOL_TOTAL` ships at 64, enforced, documented as unmeasured.**
The number is still a guess pending a real cluster's `max_connections`
and replica count. What is not optional is the semaphore behind it: sqlx
caps per pool, so without a cross-pool permit held across `execute`,
`query` and a whole `batch`, the key would be configuration that silently
does nothing — the failure §4 already names. An enforced guess is
re-tuned by changing a number; an unenforced one is discovered during an
incident.

## 13. Still open

- **Registry cache lifetime.** Resolution reads the registry on every
  request or from a cache with a TTL. A cache makes a status change take
  effect late; no cache makes the control database a per-request
  dependency, which §3 rejected for API keys and should probably reject
  here too. Leaning: cache with a short TTL plus an explicit invalidation
  on the reconciliation write, but this is not settled.
- **Who owns `degraded`.** Following from the above: if the registry is
  authoritative and §3 caches it with a TTL, a tenant marked degraded
  mid-boot keeps serving for up to the TTL, and a recovered one stays
  refused just as long. The reconciliation write needs an explicit cache
  invalidation, which neither document has.
- **Per-tenant Postgres roles.** #32 puts them out of scope, noted for
  later hardening. Worth saying that without them, the isolation is the
  harness's to enforce and a bug in §5 is not caught by the database.
