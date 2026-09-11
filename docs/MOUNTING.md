# Compile it in, or run it as a sidecar

A module can be linked into the venture's Worker or run in its own,
reached over a service binding at the same `/v1/<name>`. A caller cannot
tell which (ADR [0009](adr/0009-sidecar-modules-over-service-bindings.md)).

**Compile it in.** That is the default and it is right almost always.

**Run it as a sidecar only when the source must stay with its owner.**
Someone will not hand you the code, and you still want the module in
their API. That is the whole reason. If you can hold the source, hold it.

Everything below justifies those three lines.

## Not a reason: build time

Adding a module crate to a warm build costs **5.3 s**; a cold build with
nothing cached is **26.7 s** ([BUILD-COST.md](BUILD-COST.md), measured
for issue #58). "It avoids a rebuild" is not an argument for anything at
that scale, and no issue, document or site copy may make it.

## Not a reason on their own

| Tempting reason | What to do instead |
| :--- | :--- |
| "It has its own release cycle." | Version the crate and bump the dependency. A separate deploy is a cost, not a feature. |
| "Its dependencies are heavy." | Measure. The wasm is 3.50 MB with every current module, the UI renderer and the admin pages in it, and `opt-level = "s"` cuts about 30% ([BUILD-COST.md](BUILD-COST.md)). |
| "It is customer-specific." | Compile it in for that customer. The artifact is a function of the module set, so customers with the same set still share one. |
| "It is latency-sensitive." | Then compile it in. A sidecar adds a subrequest; in-process adds nothing. |

## What a sidecar costs

| | In-process | Sidecar |
| :--- | :--- | :--- |
| Call | A function call | One subrequest over a service binding. Cloudflare runs the bound Worker on the same thread of the same server, so no network and no extra billing. |
| Binary | One wasm, every module in it (3.50 MB today) | Two wasm binaries, each carrying its own copy of core and the runtime. Two copies of core is the floor, whatever the module weighs |
| Deploys | One | Two, in either order |
| Contract check | At build: a module compiled against another `HARNESS_API` cannot link | On **every response**, via `x-harness-api`. Not cached: an isolate can outlive a redeploy, so a handshake taken at cold start would keep reporting a contract that no longer holds |
| Secrets | Shared with the venture | Its own. `HARNESS_SECRET` signs the links every module mints, so a sidecar holding the host's could forge them. Each Worker is provisioned separately and rotates separately |
| Account | n/a | **The bound Worker must be on the same Cloudflare account as its caller.** That is what makes "you deploy it yourself, we never see the source" true in the customer-account mode, and false in a hosted one, where an account-scoped `Workers Scripts: Edit` credential would reach every other customer (issue #67) |
| Logs | One trail | Two, tied together by one `x-request-id`: the host forwards the caller's id and answers with it, whatever the sidecar does |
| Failure | A module cannot be missing | Missing binding, no dispatcher, or no answer degrades **that prefix only**: `503 sidecar-unavailable`. A contract mismatch is `503 sidecar-contract-mismatch`. Every other module keeps serving |

The host's own `/__health` lists each mounted sidecar with the contract
number, module name and version it last reported, and the verdict of the
last probe: `ok`, `mismatch` or `unreachable` (issue #61). The probe is
lazy and cached for a short window — it exists so an operator can see
both contract numbers without reading logs, not as the check itself;
that remains the stamp read on every forwarded response above.

## What a sidecar cannot do

Each of these is otherwise discovered the hard way.

- **Serve `/.well-known`.** The host nests a sidecar under `/v1/<name>`
  and nothing else. A module that needs root-level discovery documents —
  the OIDC `openid-configuration` and `jwks.json` of the auth module
  (issue #46) — cannot be a sidecar.
- **Take a venture template override.** `.template("<module>/<id>", ..)`
  names a registered module; a sidecar is not one.
- **Emit an event the host hears.** Forwarding is inbound only (ADR
  0017): the host posts its emissions to each sidecar, and a sidecar does
  not emit back. A sidecar's own `emit_in` reaches its own handlers and
  stops there — and warns when nothing heard it, rather than dropping it
  in silence. *Hearing* a host event does work; see below.
- **Use a token another module minted.** Separate signing keys, by
  design. Anything relying on the host's `Signer` is out.
- **Be seen by the schema tooling.** `fz migrations collect`, the
  runtime table-collision check and `fz data export` all walk
  `harness.modules()`, which cannot see a sidecar. Its migrations and
  its rows are its own repository's problem. The tools no longer pretend
  otherwise: pass the mount table (`--sidecars '<json>'`, or
  `HARNESS_SIDECARS` in the environment) and `fz doctor` warns that it
  cannot check those modules, while `fz data export` **refuses** rather
  than write an artifact that looks complete. Acknowledge the gap with
  `--without-sidecar-tables` and the manifest records which modules were
  left out. The cross-boundary collision check still needs the sidecar to
  declare its tables (#61).

What a sidecar **can** do, and is easy to assume it cannot: serve its UI.
The host fetches each mounted sidecar's `/__surface` and merges the
public part, so a sidecar module's forms render at `/ui/<module>/<action>`
like any other (issue #76, [UI.md](UI.md)). The merge is capped and
validated — see the boundary below (issue #131).

## Hearing the host's events

A subscription written against the bus works the same compiled in or
mounted out (issue #62, [ADR 0017](adr/0017-events-cross-the-sidecar-boundary-inbound-only.md)).
The host forwards every emission to each mounted sidecar's
`POST /__events`, inside the emitting request's `wait_until`; the sidecar
answers `202` and runs its own handlers in its **own** `wait_until`, so a
slow subscriber holds nothing open on the host.

What you get is what the in-process bus already promised, and no more:

| | |
| :--- | :--- |
| Delivery | at most once, per mount |
| Retry | none — a retry would be the durable queue #62 rules out |
| Ordering | none |
| A sidecar that errors, 500s or never answers | logged; the emitting request keeps its own response |
| A mount the deployment has no binding for | skipped, not dialled |
| Direction | host → sidecar only |

Two consequences worth stating plainly. `202` means *accepted*, never
*handled* — when it is written the handlers have not run, and no status
could tell the host otherwise, because the work outlives the response on
the far side. And the route exists only where a gateway secret does: it
is inside the guarded set, and a deployment without the shared secret
does not mount it at all, because an unauthenticated event trigger would
let a stranger forge the payloads handlers act on.

## The trust boundary

A mount is a seam inside one deployment's trust, not a network hop
between tenants. What crosses it is written down (issue #131, ADR 0009
amendment), and both Workers enforce it.

| | Crosses | Stops at the host |
| :--- | :--- | :--- |
| Request | Method, path, query, body; `content-type`, `content-length`, `accept`, `accept-language`, `user-agent`; the host's `x-request-id`; `cf-connecting-ip` **as the host resolved it** | `authorization`, `cookie`, anything unlisted — and a client-forged `cf-connecting-ip`, which is replaced, never copied |
| Response | `content-type`, `location`, `cache-control`, `etag`, `last-modified`, `vary`, `retry-after`, `content-disposition`, `x-harness-api`, `x-harness-module`, `x-request-id` | `set-cookie` and anything unlisted: a sidecar cannot plant cookies on the venture's origin |

**The gateway makes "not publicly routable" enforceable.**
`SIDECAR_GATEWAY_SECRET` (at least 32 bytes) goes on **both** ends of a
mounted pair; it is its own secret — `HARNESS_SECRET` never crosses, by
the same forging argument as above. The host stamps every forwarded
request with a short HMAC token (`x-harness-gateway`, purpose
`sidecar-gateway`, 120 s lifetime). A sidecar that also sets
`SIDECAR_REQUIRE_GATEWAY` refuses every `/v1/*` and `/__surface` request
whose token it cannot verify (`401 sidecar-unauthorized`). `/__health`
and the sidecar's own `/ui` stay open — probes must probe. Require the
gate without a usable secret and the sidecar fails **closed** with `503`:
a broken deploy must never quietly serve the open internet. `fz doctor`
warns when a mount table is present without `SIDECAR_GATEWAY_SECRET`.

**Admin stays the host's plane.** An `/admin` path under a mount is
authorized by the host, against the host's own `ADMIN_TOKEN`, before
anything is forwarded; the caller's bearer never crosses. A sidecar
behind the gateway re-materializes its **own** token for module routes
behind the gate — so the host's admin secret never enters the sidecar
and the sidecar's never enters the host, and a mounted module's admin
plane is only reachable over the gateway, which is the only channel that
says "the host checked".

**Abuse controls run on the host.** Forwarded writes (`POST`, `PUT`,
`PATCH`, `DELETE`) pass the venture's rate limiter and fail closed: the
sidecar cannot resolve the caller's address better than the host just
did. Captcha stays with the module that serves the route — a single-use
token is verified once, by whoever owns the form.

**The merged surface is treated as hostile.** A sidecar's `/__surface`
is byte-capped (256 KiB) before it is parsed, contract-checked, allowed
to speak for exactly the module it is mounted as, validated (bad paths
and oversized action lists reject the whole document), and — on a
production host with no `Captcha` port — stripped of captcha-demanding
actions the host could not render anyway.

**One Worker and mounts are a contradiction.** A truthy
`HARNESS_ONE_WORKER` (`1`, `true`, `yes` or `on`) with a non-empty
`HARNESS_SIDECARS` is rejected where the table is read — by the runtime,
which then serves no sidecars (the table is logged and dropped), and by
`fz`, which says so plainly.

## Moving a module between mounts

The point of the epic is that this needs no change to the module. It is
configuration on the host and, for a sidecar, a second deployment.

**In-process → sidecar.** Remove the crate from the composition and name
the binding instead:

```diff
--- a/src/harness.rs
+++ b/src/harness.rs
@@
     Harness::builder()
         .venture(Venture::new("acme", "acme.example").public_url("https://acme.example"))
         .module(EmailSignup::new())
-        .module(AcmePricing::new())
         .runtime(Cloudflare::new().db("DB").mailer(Resend::from_env()))
```

```diff
--- a/wrangler.toml
+++ b/wrangler.toml
@@
+[[services]]
+binding = "ACME_PRICING"
+service = "acme-pricing"
+
 [vars]
+HARNESS_SIDECARS = '{"acme-pricing":"ACME_PRICING"}'
```

The mount table is **runtime configuration, not a builder call**: one
wasm serves customers with and without sidecars, so the artifact stays a
function of the module set. A mount that collides with a compiled-in
module is ignored and logged; shipped code always keeps its prefix.

Then deploy the sidecar itself: a one-module Worker built from the same
crate, with its own `HARNESS_SECRET`, its own `ADMIN_TOKEN` and the same
database binding.
[`examples/sidecar-module-template`](../examples/sidecar-module-template/)
is that Worker, ready to copy — its README walks the five things that
are silent if left to the reader (no public route, its own secrets, its
own cron, its own migration stream, the duplicated `Venture`). Its
migrations are applied by whoever owns it, from
its own stream: two streams share one database cleanly, provided they
are applied one after the other and never in parallel
([MIGRATION-STREAMS.md](MIGRATION-STREAMS.md)).

**Sidecar → in-process.** The reverse: add the crate back, delete the
binding and the `HARNESS_SIDECARS` entry. The tables are already in the
venture's database, so nothing moves — but **carry the migration's file
name across**: put the name the sidecar's stream used into the host's
`.harness-lock.json` before running `fz migrations collect`, or the host
writes a new number, wrangler sees a name it has never applied, and runs
the migration a second time ([MIGRATION-STREAMS.md](MIGRATION-STREAMS.md)
§3). Moving the other way has the same hazard in reverse. Rows only ever
move when the venture itself moves database
([DATA-MOVE.md](DATA-MOVE.md)).

## Before you ship either way

The conformance kit runs both mounts for every module and asserts the
answers are identical — status, problem body byte for byte, the caller's
request id — so "a caller cannot tell" is checked rather than believed
(issue #64, [MODULE-AUTHORING.md](MODULE-AUTHORING.md) step 7). If your
module genuinely cannot be sidecar-mounted, say why in code:
`conformance_in_process_only(module, "serves /.well-known")`.
