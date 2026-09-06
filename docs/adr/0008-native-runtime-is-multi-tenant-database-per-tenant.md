# ADR 0008: The native runtime serves many tenants, one database each, with two-tier secrets

Status: accepted, 2026-09-06

## Context
ADR 0003 gives every venture its own Worker and its own database on the
Cloudflare path, and section 12 of the architecture lists a multi-tenant
single deployment as a non-goal. The phase-3 native runtime (issue #19)
raised the question again: ventures on self-hosted infrastructure will share
one process, and they need per-tenant schema extensions, per-tenant migration
history, and a place for secrets. Issues #23 to #44 specify that work. Three
decisions were taken while writing them.

## Decision
1. **One database per tenant.** Never one schema per tenant, never shared
   tables. Migration history, the tenant's secrets and its audit log live
   inside the tenant's own database, so a tenant can be backed up, restored,
   moved or dropped as one unit. Isolation is the database boundary; there
   is no `search_path` switching and no row-level security.
2. **A separate control database.** A small, low-traffic database that no
   venture role has credentials for holds the tenant registry and the global
   secrets store. Its connection string is the one value that comes from the
   environment; every tenant's connection string is a global secret resolved
   from it. Factory Zero's own venture is an ordinary tenant.
3. **Two-tier secrets.** Global secrets (tenant connection strings, platform
   keys) live in the control database. Tenant secrets live in that tenant's
   database. Each store has its own data key wrapped by a KMS master key.
   Modules can only ever obtain a tenant store; the global store is
   unreachable from module code, enforced by both the API and by credentials.

## Scope
This applies to `factory0-runtime-native` and the Postgres adapter. The
Cloudflare path is unchanged: one Worker, one D1, one venture, as ADR 0003
says. sqlx and SeaORM still do not enter the core (ADR 0004). Section 12's
non-goal is narrowed to "a multi-tenant deployment on the Worker path".

## Consequences
- The native runtime holds one connection pool per tenant, created lazily.
  The isolation issue (#32) names the tenant count at which that stops
  being fine; past it the answer is one process per tenant, which is the
  Worker shape, so the two paths converge.
- Restoring a venture database never rolls back the registry or another
  tenant's connection string.
- A compromised venture database exposes that venture's secrets and nothing
  else.
