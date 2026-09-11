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

The checks are **polled together, not queued**: the verdicts are
independent, so awaiting them one after another would have made the page
cost the sum of every venture's timeout. Each carries its own tightened
`HttpPolicy` — **3 seconds** and 4 KiB, against the port's 10-second,
4 MiB default — because a health endpoint that has not answered in three
seconds is not healthy, and "unreachable" is the truthful verdict about
it. The bound is enforced by `BoundedHttpClient`, which both runtimes
wrap `ports.http` in, through the `Clock` port.

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

**The module set** (`POST /ventures/{id}/modules`, issue #11 §2). The
venture carries a content key like `cms+waitlist`, which is not something
a person can act on, so the screen renders **the whole curated catalogue**
with that venture's set ticked: what is *available* is as visible as what
is on.

Saving re-provisions. The deployed artifact is a function of the module
set (ADR 0009), so writing a new key into the column and stopping there
would leave the database claiming a venture carries a module its running
Worker has never heard of. Three things make that hold:

1. The selection is **resolved through the catalogue**, which orders
   dependencies before dependants and refuses a slug it does not offer —
   so a hand-made POST cannot put an unknown module into a venture.
2. The recorded progress is **cleared first**. `Engine::provision` resumes
   from the step after the last one that completed, so a `Live` venture —
   every step done — would otherwise be marked live again without
   rebuilding anything.
3. The engine then **runs for real**, against `Unwired`: the deployer the
   control plane has today, which is none. The first step fails, the
   reason is recorded against the venture, and this screen shows it. That
   is not the same as refusing the button or pretending it worked — the
   venture's recorded state afterwards is exactly true, and the day a real
   `Deployer` is passed instead, nothing else changes.

A selection identical to the current one re-provisions nothing: the
comparison is between *sets*, not strings, because ticking the same
modules in a different order produces a different content key for the same
venture and would otherwise tear down a working one to rebuild the
artifact it already has.

**Retrying** (`POST /ventures/{id}/reprovision`). A run that stops leaves
the venture in `Provisioning` — which is *not* a run in flight, and
treating it as one would lock the module set behind the very failure the
operator came to fix. A stopped venture keeps its editor and gains a
retry.

`Live -> Provisioning` had to be added to the venture lifecycle for any of
this to be expressible: it allowed "a first run or a retry" and not "a
change", so the engine refused the move outright.

**Archiving** (`POST /ventures/{id}/archive`, issue #11 §3): stops the
venture by moving it to `Archived` through the accounts repository's
lifecycle state machine, keeping the record. Re-archiving is idempotent;
illegal moves get `409`.

## How it looks

The screens render inside `cratefield-chrome`, which is the control
plane's own page shell: cratefield.com's tokens (the same ground, the one
signal-blue accent, Archivo and IBM Plex Mono), the same `.dash__*`
component vocabulary as the preview published at
[/dashboard/](https://cratefield.com/dashboard/), and one stylesheet
served once at `/v1/chrome/chrome.css` and linked by every control-plane
screen. Ported rather than imported: the site is a separate repository and
a static build, and a Worker cannot link its stylesheet.

That is deliberately **not** `cratefield-ui`'s `cf.css`. That one is
venture-facing — it renders a customer's own signup form inside the
customer's own site, and must not drag Cratefield's colours in with it.
This one is Cratefield's surface and is branded on purpose.

One consequence worth stating: the chips are uppercased by CSS, but
`DEGRADED` is spelled out **in the markup**. A rule in a stylesheet is not
something a test, a screen reader, or a saved page can see, and that word
is the one this screen exists to make unmissable.

Navigation items that name a screen the design has and the product does
not — Deploys, Logs, Domains, Backups, Billing — render dim and inert
rather than as links to a 404.

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
`Deployer` onto Cloudflare, so no venture in the control plane is actually
deployed, and today the health verdict for a "live" venture will honestly
read unreachable and every re-provision will stop on its first step. When
the deploy pipeline lands, no dashboard code changes: the same engine call
is made with a real deployer instead of `Unwired`, and every venture
resumes from the step it stopped at with no migration and no special case.

Against issue #11's four acceptance boxes:

- [x] A dashboard listing an account's ventures with real status, degraded
      shown as degraded.
- [x] Changing the module set re-provisions through the engine, not by
      hand — through the engine, which currently stops for want of a
      deployer.
- [ ] Secrets as names and versions; the audit trail visible. Neither is
      queryable yet, and both are named as absent rather than faked.
- [ ] Archiving shreds keys before dropping the database. The *stop it,
      keep the record* half is built; the offboarding shred
      (`harness#42`'s mechanism, `harness#36`'s runbook) is not wired.
