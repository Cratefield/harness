# ADR 0009: A module may be mounted in-process or as a sidecar Worker

Status: accepted, 2026-09-06

## Context
ADR 0003 composes a venture's modules at compile time: the venture lists module
crates, `Harness::build()` wires them, and the wasm binary contains exactly
those modules. That is right for a venture that owns its backend, and it leaves
one case with no answer for a managed service that provisions one.

It is worth saying first what the case is **not**. Build cost was the obvious
suspicion and it is unfounded: adding a module crate to a warm build takes about
five seconds, and a cold build with nothing cached is under thirty
(`docs/BUILD-COST.md`, issue #58). Nothing in this ADR is justified by avoiding
a rebuild, and no documentation should claim otherwise.

The real case is confidentiality. A customer may want a module whose source they
will not hand to a supplier. Linking it into a shared artifact means we hold the
source. Building the whole bundle privately for that customer still means we
hold the source. Neither is acceptable, and there is no arrangement of
compile-time composition that fixes it, because compiling requires the code.
That is the case this ADR exists for.

## Decision
**A module may be mounted one of two ways, and a caller cannot tell which.**

1. **In-process.** The crate is linked into the Worker, as ADR 0003 describes.
   This stays the default.
2. **Sidecar.** The module runs in its own Worker, carrying one module plus core
   and the runtime, reached over a Cloudflare service binding and mounted at the
   same `/v1/<name>` prefix. The harness forwards the method, path, query and body;
   headers cross only the explicit allowlist of the issue #131 amendment
   below, and the answer is copied back through the response allowlist there.

The mount is **runtime configuration, not a builder call.** A `.sidecar()` in
`src/harness.rs` would bake a customer-specific mount into the artifact, so
the artifact would stop being a function of the module set and #59's cache could
never hit for a sidecar customer. The mount table is read from configuration
alongside the other bindings, so one wasm serves customers with and without
sidecars. This matters for artifact identity and provenance rather than for
build time, which is measured and small.

**A sidecar binds the same database and its own secrets.** The database is
shared because a sidecar is a module of that tenant, not a separate tenant. The
secrets are not shared, and this is deliberate: `HARNESS_SECRET` signs the
confirm and unsubscribe links every module mints, so a sidecar holding it could
forge them for the host's modules, and `ADMIN_TOKEN` would open the host's admin
endpoints. Nothing in the code needs sharing, because each module signs and
verifies its own tokens (ADR 0006). Each Worker is provisioned its own secrets
and rotates them independently. The caller's `Authorization` stops at the
boundary (issue #131): the host authorizes admin paths under a mount with its
own token, and the gate re-materializes the sidecar's own admin token only for
requests whose gateway stamp carries that verdict, so neither Worker ever holds
the other's secret.

**Validation moves to the first request.** `HarnessBuilder::build` never sees
`Env`; `Runtime::provides()` is a static declaration and real binding presence
is discovered in `Cloudflare::ports()`. A missing service binding therefore
cannot be a build error the way a missing port is. Sidecar mounts are validated
on the first request per isolate, and a failure degrades **that prefix only**,
returning `503`, while every other module keeps serving.

**The contract is checked on every response, not cached at cold start.** An
isolate can outlive a sidecar redeploy, so a handshake cached at startup would
keep reporting a contract that no longer holds. Every harness response carries
`x-harness-api` and `x-harness-module`; the host checks them on each forwarded
response. This costs no extra subrequest and catches a redeploy within one
request.

## Scope
This narrows two statements rather than reversing them. ARCHITECTURE §2
principle 2, "the wasm binary contains exactly those modules", becomes "exactly
those modules it serves in-process". §12's non-goal of runtime plugin loading is
**unchanged**: Cloudflare's `WebAssembly.instantiate()` accepts only
pre-compiled modules, so nothing is loaded at request time, and a sidecar is a
separately deployed Worker rather than a plugin. ADR 0008's tenant isolation is
untouched: one tenant, one database, and sharing a build artifact is not sharing
a deployment.

Cloudflare requires a bound Worker to be on the same account as its caller.
In the customer-account deployment mode this is what makes the promise work:
both Workers are the customer's, and they deploy the sidecar with their own
credentials. In a hosted mode it does not hold, because `Workers Scripts: Edit`
is account-scoped with no per-script resource, so a credential given to one
customer would reach every other Worker in that account. **The hosted-mode
mechanism is deferred to #67** and is not decided here.

## Consequences
- A sidecar carries its own copy of core and the runtime. At a few MB against a
  64 MiB uncompressed script limit, size is not a constraint.
- The host spends one subrequest per sidecar call, against 10,000 per invocation
  on the paid plan. The sidecar's own D1 queries count against the sidecar's
  invocation budget, not the host's.
- The in-process event bus does not cross the boundary; #62 decides what
  replaces it. Until then a sidecar can neither emit events the host hears nor
  subscribe to the host's.
- Every schema tool walks `harness.modules()` and so cannot see a sidecar. Its
  migrations, the duplicate-table check and `fz data export` all need explicit
  work before a sidecar may own tables; #66.
- A sidecar cannot serve `well_known()` routes, because the host nests it only
  under `/v1/<name>`. The auth service, which needs the root-level
  `/.well-known` routes added in #46, therefore cannot be a sidecar.
- A sidecar must not be publicly routable. The host's rate limiting, captcha and
  request-id trust key off the `cf-connecting-ip` it forwards; a directly
  reachable sidecar would accept a client-supplied one. Issue #131 turned that
  from an operational rule into an enforced one — see the amendment below.

## Amendment (issue #131): the trust boundary

The Decision above shipped a forwarder. Unfiltered headers made the mount a
leak: a caller's `Authorization` — the venture's admin bearer — crossed to a
Worker with its own secrets, a client-forged `cf-connecting-ip` reached the
sidecar's abuse controls, a sidecar's `set-cookie` could plant cookies on the
venture's origin, and a publicly reachable sidecar answered the open internet
because nothing at the seam said otherwise. #131 writes down the boundary:

- **Request allowlist.** Method, path, query and body cross. Of headers, only
  `content-type`, `content-length`, `accept`, `accept-language` and
  `user-agent`. The host then stamps its own `x-request-id`, a
  `cf-connecting-ip` resolved from the actual inbound request, and — when
  `SIDECAR_GATEWAY_SECRET` is configured — an `x-harness-gateway` token: an
  HMAC under the shared secret, purpose-bound (`sidecar-gateway`, so a
  confirm-link token can never pass and vice versa) and 120 s lived. A
  request the host authorized as admin is stamped under a second, disjoint
  purpose, `sidecar-gateway-admin` — see **Admin** below.
  `authorization` and `cookie` never cross; neither does anything unlisted.
- **Response allowlist.** `content-type`, `location`, `cache-control`, `etag`,
  `last-modified`, `vary`, `retry-after`, `content-disposition`,
  `x-harness-api`, `x-harness-module` and `x-request-id` return. `set-cookie`
  stops at the host.
- **The gateway.** A sidecar that sets `SIDECAR_REQUIRE_GATEWAY` answers `401
  sidecar-unauthorized` for every guarded route — `/v1/*` and `/__surface` —
  whose token it cannot verify; requiring the gate without a usable secret
  fails closed with `503`. Probes and the sidecar's own UI stay reachable, so
  a directly-routable sidecar protects its API even while remaining operable.
  A verified token's subject (the mount name) is forensic, not checked: a
  sidecar cannot know the name a host chose for it.
- **Admin.** `/admin` paths under a mount are authorized by the host, against
  the host's own `ADMIN_TOKEN`, before forwarding. The gateway token is the
  host's assertion that this happened, and it carries that assertion in the
  MAC: only then is the stamp minted under `sidecar-gateway-admin`, and only
  that purpose lets the gate re-materialize the *sidecar's own* admin token
  for the module routes behind it. The distinction is load-bearing, because
  every proxied request carries a stamp — were the plain one enough, a single
  captured stamp would be an admin credential for its whole lifetime. Each
  Worker keeps checking its own secret, as the Decision promised, and no
  bearer ever crosses in either direction.
- **Abuse.** Forwarded writes (`POST`, `PUT`, `PATCH`, `DELETE`) pass the
  host's rate limiter and fail closed. Captcha stays with the module that
  serves the route and verifies its single-use token once; the boundary is
  not a second chance to consume it.
- **Surface merge.** A sidecar's `/__surface` is fetched with the gateway
  stamp, byte-capped before parsing, contract-checked, limited to exactly the
  mounted module's public part (a second or foreign entry rejects the whole
  document), declaration-capped, validated, and stripped of
  captcha-demanding actions on a production host that has no `Captcha` port.
  A bad or oversized answer contributes nothing and is logged.
- **One Worker.** `HARNESS_ONE_WORKER` truthy alongside a non-empty
  `HARNESS_SIDECARS` is a configuration error where the table is read: a
  one-Worker deployment serves everything in-process and can mount nothing.
