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

## What a sidecar cannot do

Each of these is otherwise discovered the hard way.

- **Serve `/.well-known`.** The host nests a sidecar under `/v1/<name>`
  and nothing else. A module that needs root-level discovery documents —
  the OIDC `openid-configuration` and `jwks.json` of the auth module
  (issue #46) — cannot be a sidecar.
- **Take a venture template override.** `.template("<module>/<id>", ..)`
  names a registered module; a sidecar is not one.
- **Emit an event the host hears, or hear one the host emits.** The bus
  is in-process. Crossing it is issue #62 and undecided.
- **Use a token another module minted.** Separate signing keys, by
  design. Anything relying on the host's `Signer` is out.
- **Be seen by the schema tooling.** `fz migrations collect`, the
  table-collision check and `fz data export` all walk
  `harness.modules()`, which cannot see a sidecar. Its migrations,
  collisions and rows are its own problem until issue #66 lands. This is
  the sharpest edge on the list.

What a sidecar **can** do, and is easy to assume it cannot: serve its UI.
The host fetches each mounted sidecar's `/__surface` and merges the
public part, so a sidecar module's forms render at `/ui/<module>/<action>`
like any other (issue #76, [UI.md](UI.md)).

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
database binding. Its migrations are applied by whoever owns it, from
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
