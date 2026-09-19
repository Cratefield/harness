# Starter kits and the deploy button

**Date: 19 September 2026. Status: for review. The harness half of
[harness#161](https://github.com/Cratefield/harness/issues/161).**

## What this is

The second audience — builders working with AI tools — adopts what its
tools already know how to scaffold. That is a starter a generator fills
in, a project template its rules engine reads, and a button that takes a
repository to a running venture. Issue #161 asks for all three, in a new
public repository `Cratefield/starters`. The colony cannot create a
repository, which is why #161 carries `needs-human`; this document
specifies what it contains, and harness delivers the one artifact it
owns here: `docs/llms.txt`.

## What the starters repo contains

`Cratefield/starters`, public, MIT, one top-level directory per starter
so a generator can take a single directory without the rest:

```
nextjs/          Next.js starter (App Router, server components)
sveltekit/       SvelteKit starter (load functions)
expo/            Expo starter (React Native client)
claude-code/     Claude Code project template
cursor/          Cursor project template
venture.json     the shared example venture manifest
.env.example     the one variable every starter reads
README.md        the deploy button, and how to point a starter at a venture
```

The three starters share the example manifest — a two-module venture,
`waitlist` and `email-signup` — so the smoke test is the same everywhere.

## The contract every starter meets

The same five points, all three frameworks:

1. Ship a `venture.json` at the repo root, matching the shared example:
   name, host, and the two module slugs.
2. Talk to a deployed venture over its public URL. No starter runs or
   embeds the harness; it is a client of a venture somebody deployed.
3. Read `GET /__surface` at startup (or the generated client, once
   #155 publishes) instead of hardcoding module, action or field names;
   a name the surface does not list is a bug in the starter.
4. Carry `.env.example` with the venture URL and nothing secret. The
   variable is `VENTURE_URL`; a starter holds no credentials, tokens or
   keys, because a venture's admin token belongs to whoever deployed it.
5. Pass a stated smoke test, run as `npm run smoke`: fetch
   `$VENTURE_URL/__surface`, assert the two modules appear, and submit
   the waitlist join action on a venture deployed for the purpose.

What is per-framework: routing and data fetching. Next.js reads the
surface in server components and posts from route handlers; SvelteKit
reads it in load functions; Expo fetches in the client and takes the URL
from app config. What is shared: the manifest, the surface contract, the
env contract, the smoke test.

## The AI-tool templates

The Claude Code template ships three things: a `CLAUDE.md` that tells an
agent what the project is and that `docs/llms.txt` is the contract for
every `fz` and surface question; the `llms.txt` file itself, copied from
`docs/llms.txt` and kept in step with it; and an MCP server entry once
#160 lands. The entry's shape (the package name is #160's to decide):

```json
{
  "mcpServers": {
    "cratefield": {
      "command": "npx",
      "args": ["-y", "<package #160 publishes>"]
    }
  }
}
```

That entry is target state: the MCP half of both templates is blocked
on #160, and until it publishes they ship `llms.txt` and `CLAUDE.md`.

The Cursor template ships the same content as project rules, recast for
Cursor's rules format, and the same `llms.txt`. One contract, two formats.

## The deploy button

A starter's README ends with the button. Its markdown points at the
control plane's create route, which today is `GET /new`, the wizard:

```markdown
[![Deploy to Cratefield](https://cratefield.com/deploy-button.svg)](https://<control-plane-host>/new?repo=<https-url-of-this-repo>&starter=nextjs)
```

The query parameters a repo-seeded flow needs, proposed: `repo`, the
repository's `https://` clone URL (required); `starter`, which template
seeded it; `ref`, a branch or tag, defaulting to the default branch.
The end-to-end flow the button promises:

1. A builder clicks the button in a starter's README.
2. The control plane's sign-in gate runs first, exactly as for a typed
   URL: Google SSO, then the allowlist decision.
3. The wizard opens pre-seeded from the repository's `venture.json`:
   name, host, module set, config.
4. The builder confirms; a venture is created and enters the fixed
   provisioning pipeline — artifact, database, worker, schema, secrets,
   route, health — resumable at each recorded step.
5. The builder points their clone's `VENTURE_URL` at the new subdomain
   and runs the smoke test.

### What is missing before that flow works

Every step above after the sign-in gate is specification, not behavior.
The button works today in the weakest sense — `/new` renders a wizard
and ignores the query parameters — and cannot work as described until:

| Prerequisite | Where it lands |
| :--- | :--- |
| A component that consumes a git repository URL: clone, read `venture.json`, seed the wizard | New work; nothing in the repo consumes a repository URL today |
| A real `Deployer` behind the port | `crates/control-plane-provisioning/src/lib.rs`, whose only impl is `Unwired`, refusing every step |
| Release digests that are content addresses, not placeholders | Catalog pins and the linker (`crates/control-plane-linker/src/lib.rs`) |
| Hosted provisioning end to end | Roadmap B1, [cp#26](https://github.com/Cratefield/control-plane/issues/26) |
| An admitted account, so an anonymous click provisions nothing | `crates/control-plane-access/src/lib.rs`: invite-only, Google SSO |

## Security notes

A repository URL is untrusted input. Before the control plane fetches
one: admit the session first; accept only `https://`; pin the ref; cap
the fetch size; and treat everything read out of the repository —
`venture.json` included — as data that pre-fills a form, nothing more.

No secret travels in a query parameter: the URL lands in access logs,
referrers and browser history, and the flow needs none.

The button grants nothing. It carries no authority: the click lands on
the same gate as a typed URL, and admission is decided against the
verified SSO identity, not anything the repository claims.

## Acceptance criteria

#161 closes when:

- [x] `docs/llms.txt` exists — the artifact harness owns, delivered by
      this change.
- [x] This specification exists.
- [ ] A human creates `Cratefield/starters` with the layout above.
- [ ] Each of the three starters passes its smoke test against a
      deployed venture.
- [ ] Both templates ship `llms.txt`; the MCP entry follows #160.
- [ ] The button markdown ships in the starters' READMEs; the repo-seeded
      flow behind it follows the table above, and B1.
