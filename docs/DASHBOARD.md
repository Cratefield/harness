# The account dashboard

Issue #11 — "The account dashboard: manage a live venture". The module is
`cratefield-dashboard`, mounted at `/v1/dashboard`, composed in
`crates/control-plane/src/lib.rs` next to the console.

## What it shows

**`/` — the venture list.** Every venture the signed-in account owns, each
with its lifecycle status, its subdomain, and a health verdict. The verdict
is a real fetch of `https://<subdomain>/__health` over the harness http
port, made while the page renders:

| Verdict | Meaning |
|---|---|
| `answering /__health` | the venture answered with a success status |
| `FAILING /__health — HTTP nnn` | it answered with a failure status |
| `FAILING /__health — unreachable: …` | the fetch itself failed |
| `not running — /__health not checked` | draft/provisioning/archived: nothing should answer, so nothing was fetched |

There is deliberately no "checking" or "loading" state. This repository
shipped a bug where a failing call looked like an empty state, and issue
#11 calls it out by name: **a degraded venture reads as DEGRADED**, with
its recorded provisioning failure, on both the list and the detail page.

**`/v1/dashboard/ventures/{id}` — one venture.**

- Status, subdomain, health verdict (as above).
- The module set (the resolved content key the artifact is a function of).
- Provisioning progress: the last completed step, or the recorded failure
  from `provision_progress` — read from the provisioning engine's own
  table, never paraphrased into something optimistic.
- Connections, from the `connection` table. That table holds metadata
  only — kind, state, a non-secret hint — by that table's own design, so
  the dashboard cannot leak a credential by rendering it.

**Archiving** (`POST /ventures/{id}/archive`, issue #11 §3): stops the
venture by moving it to `Archived` through the accounts repository's
lifecycle state machine, keeping the record. Re-archiving is idempotent;
illegal moves get `409`.

## What it deliberately does not show — and why

- **Secret names.** Issue #11 asks for secrets "as names and versions
  only, never values". The screen will do exactly that — but the secrets
  store is reached through a KMS, and the control plane has no KMS wired
  yet (that wiring belongs to the live deploy pipeline). Rather than read
  the `harness_secrets` table around the secrets layer, the screen says
  plainly that it has nothing truthful to list. No secret value is ever
  printed, logged or rendered by this module.
- **The audit trail.** Issue #11 asks for "who touched what" per venture.
  No such record is queryable yet: the only audit table is the console's
  allowlist audit (account-level, not venture-level), and the secrets log
  is tracing-only until the append-only audit log lands. The screen shows
  no audit rows rather than made-up ones.

## The not-built half

Issue #11 is blocked by the provisioning engine: there is no live
`Deployer` onto Cloudflare, so no venture in the control plane is
actually deployed, and today the health verdict for a "live" venture will
honestly read unreachable. Everything on this screen is built and tested
against the read-only half that exists — venture records, provisioning
progress, connection metadata, archiving — and the health check makes a
real request and reports what it really saw. When the deploy pipeline
lands, no dashboard code changes; the data it renders simply starts to
exist.
