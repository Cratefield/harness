# ADR 0019: The tenant lifecycle is a port in core, and the operator steps stay operator

Status: accepted, 2026-09-19. Issue #154, part of epic #23 (tenants as
a product). Records where the registry's write half lives, and what it
deliberately cannot reach.

## Context

The onboarding runbook (#36) ends in a verifiable state, and its §4
names the two things that stood between its steps and the
`harness tenant create <id>` command the issue asks for. The
mechanical steps were never the problem: `register_tenant` and
`set_tenant_status` exist in `cratefield-adapter-postgres`, against
the `harness_tenants` registry on the control database, and
reconciliation performs the `provisioning` -> `active` flip itself.
The first blocker was shape: those writes lived on the Postgres
adapter only, so a CLI subcommand would either have been a
Postgres-only command wearing a runtime-neutral name, or the place
where a second answer to "what is a tenant" gets invented. The second
was standing proof: nothing has run the path end to end, because no
tenant database has ever been provisioned.

#154's other half is the promotion path past D1's 10 GB cap
(`docs/control-plane/PRICING.md`), and it starts from an identity that
bounds the whole design: on the Cloudflare path a tenant is the
venture — one Worker, one D1, the implicit tenant of
`docs/TENANT-ROUTING.md` §6 — so there is no per-tenant promotion off
D1 to build. Promotion is a venture-level move, and the per-tenant
lifecycle only begins once a tenant is a row in the registry on the
multi-tenant Postgres runtime. Both halves need the same thing: the
registry's write half, somewhere a caller that is not the Postgres
adapter can reach it.

## Decision

**The write half of the registry becomes a core trait.**
`TenantLifecycle` (`crates/core/src/tenant_lifecycle.rs`) carries
`create`, `status`, `tenants` and `set_status`, with the erasure half
of offboarding as provided methods, `begin_erasure` and
`complete_erasure`. `cratefield-adapter-postgres` implements it over
the calls that already existed. Nothing about what a tenant is
changes, because the trait is a doorway to the same registry, not a
second definition of it — which is the dilemma TENANT-ONBOARDING §4
said the command had to wait for, resolved by refusing both of its
horns.

**It is not a `Port`.** Modules must never write the registry: the
registry is what decides who may be served, and a module that could
write it could mark itself `active` or a neighbour `archived`. So
`TenantLifecycle` goes neither into the `Ports` struct nor the `Port`
enum, and nothing reachable from module code exposes it. Being a port
in the architectural sense (ADR 0002) does not make a type a member of
that struct; some capabilities belong to the operator's side of the
line, and this is one.

**The transition rule stays where #361 put it.**
`TenantStatus::admits` decides which status writes are legal; the port
consumes it rather than restating it. A caller asking for an
inadmissible transition is refused by the same code the runtime
reconciler is refused by, and the tests that pin the rule —
`a_retired_tenant_cannot_be_resurrected_or_re_flown`,
`archived_is_the_only_terminal_status` — hold unchanged.

**Provisioning and dropping a database stay operator steps.** ADR 0008
scopes a tenant's application role to its own database, so the harness
holds no credential that could create or drop one — deliberately. The
port's `create` writes a registry row in status `provisioning` over a
database a person has already made (onboarding steps 1–2), and it
provisions nothing. For the same reason "delete" means the registry
lifecycle — `begin_erasure`, the crypto-shred bookkeeping,
`complete_erasure` — plus an operator's drop after the retention hold,
never a `DROP DATABASE` issued by the harness.

**The D1 cap is a venture-level threshold, and promotion is a
venture-level move.** Per `docs/TENANT-ROUTING.md` §6, the tenant on
D1 is the venture, so nothing in the lifecycle promotes a tenant off
D1 and none will; the move off D1 is
[DATA-MOVE](../DATA-MOVE.md)'s runbook
([TENANT-PROMOTION](../TENANT-PROMOTION.md) §3), and the lifecycle's
first work for that venture begins after it lands, as a registry row.

## Rejected

**1. Leaving the lifecycle on `Postgres` only.** What exists today,
and the status quo has a real virtue: one implementation, already
tested. It fails the way the pre-#154 world did: a CLI subcommand
built on it is a Postgres-only command wearing a runtime-neutral name,
or every runtime that is not Postgres grows its own answer to what a
tenant is — the second definition the onboarding document refused in
advance. A trait in core is what lets the wasm runtime keep having no
registry without making the CLI a special case for noticing.

**2. Adding it to the `Ports` struct.** `Ports` is what module code
holds, and the enum is a capability list — `requires(&[Port::Db])` is
how a module declares it touches a database. A `TenantLifecycle`
member would hand every module that asks a registry write: set itself
`active`, set a neighbour `offboarding`, read the tenant list. The
registry's whole value is that modules are not in that loop; the
isolation TENANT-ROUTING §5 builds at the request layer would be
undone at the capability layer.

**3. Having the port shell out to `DROP DATABASE`.** The tempting
completeness: a delete that ends with the database gone. It needs a
credential ADR 0008 deliberately withholds — the harness's role
reaches one tenant's database and nothing else, so no grant it holds
may create or drop one — and it would move the most irreversible step
of offboarding to the wrong side of the order that makes offboarding
safe: export while the data is readable, shred the keys, hold, drop.
The harness can own the bookkeeping; the drop stays where the
credential is, with the operator.

## Consequences

- The first of TENANT-ONBOARDING §4's two blockers is gone; the second
  stands. No CLI subcommand ships here, and #36 remains its right
  home: a command is worth writing after the procedure it automates
  has been performed once, and none has.
- The wasm and browser runtimes gain nothing to call. They resolve
  through the implicit tenant and have no registry; the trait does not
  change that, and is not supposed to.
- runtime-native still has no tenant plane. Wiring a `PoolRegistry`
  into `Ports.tenants` remains `docs/TENANT-ROUTING.md` §10's item; a
  venture promoted off D1 serves as the implicit tenant until it
  lands.
- The promotion runbook (`docs/TENANT-PROMOTION.md`) can name what
  writes the registry without borrowing a Postgres-only type, and its
  operator steps stay operator steps — which is what keeps the SOC 2
  mapping's rows pointing at people for provision and drop.
- `begin_erasure` and `complete_erasure` being provided methods keeps
  offboarding's erasure half on the trait itself, so a caller marks a
  tenant erased through the registry's own accounting rather than a
  status write of its own devising.

## References

Issue #154; epic #23; #36 (onboarding, and its §4); #361 (the
transition rule); ADR
[0002](0002-ports-and-adapters.md) (ports and adapters); ADR
[0008](0008-native-runtime-is-multi-tenant-database-per-tenant.md) (one
database per tenant, and the credential this ADR refuses to invent);
`docs/TENANT-ONBOARDING.md`, `docs/TENANT-PROMOTION.md`,
`docs/TENANT-ROUTING.md` §6; `docs/control-plane/PRICING.md`;
`crates/core/src/tenant_lifecycle.rs`;
`crates/adapter-postgres/src/reconcile.rs`.
