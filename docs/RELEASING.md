# Releasing `cratefield-*` to crates.io

The pipeline is wired; the only things left are one-time crates.io
setup steps that need a human with the owner account. This page is the
exact list (issue #15). Everything here is **for the owner** — the
credential-gated steps below run from this repository's CI only once it
is configured. The one exception that needs nothing: the `crates.io
resolve` workflow already runs daily with no credentials, checking the
published set on its own (see "The published set" below).

## How the pipeline works

`.github/workflows/release.yml` runs on every push to `main`:

1. `release-plz release-pr` collects the conventional commits since the
   last release and opens (or updates) a release PR: per-crate version
   bumps, per-crate `CHANGELOG.md`, rewritten workspace dependency
   requirements.
2. Merging that release PR triggers `release-plz release` on the
   resulting push to `main`: it publishes every crate whose version is
   not yet on crates.io — in dependency order (`cratefield-core` first) —
   and tags `<crate>-v<version>` with a GitHub release per crate.

Configuration lives in `release-plz.toml` (per-crate versioning,
conventional-commit changelogs, `publish = false` for `examples/*` and
the CLI acceptance crate).

`cratefield-tables` also carries `publish = false`, and is held back from
crates.io until the CRUD layer and the first in-repo consumer land.
Nothing depends on it yet and its public surface is still moving, which a
0.1 on crates.io would pin permanently. When it is ready its first
publish is manual, the same as every other new crate: add it to the
ordered list in step 2 below, then enable its trusted publisher and drop
the `publish = false` entry.

`cratefield-push-auth` (issue #178) carries `publish = false` in its own
manifest for the same reason, but with one difference that matters to the
order below: two **published** crates already depend on it —
`cratefield-adapter-apns` and the `cratefield` facade (behind its
`push-auth` feature). So it must be first-published *before* either of
them, or their `cargo publish` fails resolving a crate that is not on
crates.io. It is in the ordered list below in that position; drop its
`publish = false` at the same time.

`cratefield-adapter-fcm` (issue #179) and `cratefield-adapter-webpush`
(issue #180) inherit the same rule for the same reason. Each carries
`publish = false`, and the `cratefield` facade depends on both behind optional
`fcm` and `webpush` features — an **optional** dependency still has to resolve
on crates.io when the facade is packaged, so `cargo publish -p cratefield`
fails until each is first-published. Both are in the ordered list below, after
`cratefield-adapter-apns`; drop each `publish = false` at the same time.

`cratefield-push-wiring` (issue #191) carries `publish = false` because it
depends on those two, and it binds harder than they do: `cratefield-cli`
depends on it **not** optionally (`fz doctor` reads the push environment
through it, which is the point — one reader), and the two runtimes and the
facade depend on it behind optional `push`/`push-wiring` features. So it must
be first-published before `cratefield-cli`, both runtimes and the facade, and
it cannot be first-published before `cratefield-adapter-fcm` and
`cratefield-adapter-webpush`. It is in the ordered list below in that
position; drop its `publish = false` at the same time.

`cratefield-i18n` (issue #190), `cratefield-module-privacy` and
`cratefield-module-notifications` (issue #182) were wired into the facade
after this list was written, and the list was not updated. All three carry
`publish = false`, all three are optional dependencies of the facade, and an
optional dependency still has to resolve on crates.io when the facade is
packaged — so today the last line of the list cannot run at all:

```
$ cargo publish --dry-run --no-verify -p cratefield
error: failed to prepare local package for uploading

Caused by:
  no matching package named `cratefield-adapter-fcm` found
  location searched: crates.io index
```

`adapter-fcm` is only the first name it reaches; `adapter-webpush`,
`push-wiring`, `i18n`, `module-privacy` and `module-notifications` are behind
it. Seven first publishes stand between the current state and a facade
release, and crates.io rate-limits new crates, so it is not one sitting.

**`cratefield-module-notifications` also depends on `cratefield-auth-client`**,
which is the edge easiest to miss: it leaves the `cratefield-*` namespace for
the auth stack (ADR 0013), it is not optional, and `cratefield-auth-client`
carries `publish = false` like the rest of those crates. It depends on nothing
but `cratefield-core`, so it can be first-published as soon as core is; it is
in the ordered list below in that position.

What does **not** constrain the order: `cratefield-module-privacy` is a
dev-dependency of `module-email-signup`, `module-waitlist` and
`module-notifications`, and those are path-only by the rule above, so they are
stripped from the packaged manifests. Those three published while
`module-privacy` did not exist on crates.io, which is the proof. Only the
facade's real (optional) dependency on it constrains anything.

`fz push` (issue #184) adds three more edges into `cratefield-cli`, and the
ordered list below already satisfies all of them: it depends on
`cratefield-push-auth` and `cratefield-adapter-webpush` **not** optionally
(`fz push vapid keygen` mints the key with the same signer the adapters
present, and `fz push inspect-subscription` validates with the Web Push
adapter's own rules), and on `cratefield-runtime-native` behind the optional
`push-send` feature — which still has to resolve on crates.io when the CLI is
packaged, for the reason the facade's optional dependencies do.

Authentication is **trusted publishing**: the workflow exchanges the
GitHub Actions OIDC token (`id-token: write`) for a short-lived
crates.io token. No `CARGO_REGISTRY_TOKEN` is stored anywhere.

Both steps are **switched off** until the owner setup below is done, so
an unfinished setup leaves `main` green with an annotation instead of a
red X on every merge.

Step 1 runs only with a token GitHub lets create pull requests. The
built-in `GITHUB_TOKEN` usually may not: the API answers *"GitHub
Actions is not permitted to create or approve pull requests"* (403)
unless the repository setting allows it. Two ways to fix it, and the
first is better:

- **A `RELEASE_PLZ_TOKEN` secret** — a fine-grained PAT or GitHub App
  token with *contents: write* and *pull requests: write* on this
  repository. It sidesteps the setting, and the release PR it opens
  **runs CI**, which a `GITHUB_TOKEN`-authored PR never does (GitHub
  suppresses workflow triggers on those, so version bumps would merge
  unverified).
- **The repository setting** — *Settings* → *Actions* → *General* →
  *Workflow permissions* → tick *Allow GitHub Actions to create and
  approve pull requests*, then set the repository variable
  `ACTIONS_MAY_OPEN_PRS` to `true` so the workflow knows. Note the
  setting also lets any workflow in this repository *approve* PRs.

Step 2 runs only when the repository variable
`CRATES_IO_READY` is `true`. A crate's trusted publisher cannot be
configured before the crate exists, so until the first manual publish
every `release` run would fail on authentication and leave `main` red.
`release-pr` always runs; it needs no registry credentials.

The workflow also takes a manual run (Actions → Release → *Run
workflow*) with a `dry_run` checkbox, on by default, so the pipeline
can be exercised without publishing.

## Breaking bumps: bump the crate, not the workspace table

Sometimes a crate's next version is decided by hand — release-plz missed
a breaking marker, or the bump is deliberate. Bump **only that crate's
own `version`** and leave the `[workspace.dependencies]` requirement
alone (`cargo set-version -p cratefield-core 0.6.0` from `cargo-edit`,
or by hand), and land the commit with a conventional breaking marker
(`feat(core)!:` or a `BREAKING CHANGE:` footer) so the changelog flags
it. release-plz then rewrites the workspace requirement itself, and
because it made the edit it also patch-bumps every published crate that
depends on the bumped one, transitively, and publishes them all in the
same release PR, in dependency order. Per-crate versioning does not
strand the published set on its own — but only while the requirement is
left to release-plz.

Hand-editing the workspace requirement defeats the cascade, silently and
permanently: with the requirement already correct in-tree, release-plz
has nothing to rewrite, so no dependent moves — and it never re-checks
either, `release-pr` reports the dependents "already up to date" on
every later run. That is how the core 0.5 bump landed: PR #336 edited
the crate and the workspace table in the same commit (issue #462 is the
consequence; issue #466 is where this was established).

**If a requirement was already hand-edited and dependents are stranded:**
patch-bump the affected published crates — their own versions only; their
core requirement already comes from the workspace table — and let
`release-plz release` publish them. If the release step is still off
(`CRATES_IO_READY` is not `true` yet), fall back to the manual ordered
`cargo publish` list in step 2 of Owner setup above.

Three boundaries on the cascade. A compatible bump (0.5.0 to 0.5.1) does
not cascade, and does not need to — the caret requirement already accepts
it. Dependents get a patch bump even where the requirement move is
breaking for their own users (release-plz#1599, wontfix). And the
cascade lives entirely in `release-pr`: if the release-PR gate is off
(no `RELEASE_PLZ_TOKEN`, `ACTIONS_MAY_OPEN_PRS` not `true`),
propagation never runs at all.

## Owner setup (once)

Step 0 is about GitHub; the rest need the crates.io account that will
own the `cratefield-*` names.

0. **Let the release PR be opened.** Either add a `RELEASE_PLZ_TOKEN`
   secret (preferred, and the release PR then runs CI) or tick the
   repository setting and add the variable `ACTIONS_MAY_OPEN_PRS=true`,
   as described above. Verify with Actions → *Release* → *Run workflow*
   (leave `dry_run` checked): the release PR appears.
 A crate's trusted publisher can only be configured **after the
crate exists**, so the very first release of each crate is manual:

1. **Create a scoped token, on an account with a verified email.**
   Sign in to crates.io → *Account settings* → *API Tokens* → *New
   token*. Scope: **Publish new crates**. This token exists only for the
   first publishes; revoke it afterwards.

   crates.io refuses to publish from an account whose email address is
   unverified, and it refuses **at upload**, after packaging and the
   verification build have both succeeded:

   ```
   error: failed to publish cratefield-core v0.3.0 to registry at https://crates.io
   Caused by:
     the remote server responded with an error (status 400 Bad Request):
     A verified email address is required to publish crates to crates.io.
   ```

   A `--dry-run` cannot catch this, because a dry run stops before the
   upload. Check <https://crates.io/settings/profile> first: the address
   must be present *and* confirmed through the mail crates.io sends.
2. **First-publish each crate manually**, in dependency order, from a
   checkout of `main` at the version being released:

   ```sh
   export CARGO_REGISTRY_TOKEN=...   # the scoped token from step 1
   cargo publish --dry-run -p cratefield-core   # then without --dry-run
   cargo publish -p cratefield-kms
   cargo publish -p cratefield-adapter-sqlite
   cargo publish -p cratefield-adapter-postgres
   cargo publish -p cratefield-adapter-resend
   cargo publish -p cratefield-adapter-turnstile
   cargo publish -p cratefield-adapter-anthropic
   cargo publish -p cratefield-push-auth      # before adapter-apns
   cargo publish -p cratefield-adapter-apns
   cargo publish -p cratefield-adapter-fcm    # before the facade
   cargo publish -p cratefield-adapter-webpush  # before the facade
   cargo publish -p cratefield-secrets
   cargo publish -p cratefield-push-wiring    # before the runtimes and the CLI
   cargo publish -p cratefield-runtime-cloudflare
   cargo publish -p cratefield-runtime-native
   cargo publish -p cratefield-testing
   cargo publish -p cratefield-module-telemetry
   cargo publish -p cratefield-module-email-signup
   cargo publish -p cratefield-module-waitlist
   cargo publish -p cratefield-module-cms
   cargo publish -p cratefield-module-changelog
   cargo publish -p cratefield-i18n           # before module-notifications
   cargo publish -p cratefield-auth-client      # before module-notifications
   cargo publish -p cratefield-module-privacy # before the facade
   cargo publish -p cratefield-module-notifications  # needs both of those
   cargo publish -p cratefield-ui
   cargo publish -p cratefield-cli
   cargo publish -p cratefield            # the facade: depends on all of them
   ```

   Twenty-six crates, and the order is the dependency order: `--dry-run` for
   a crate whose upstream `cratefield-*` dependencies are not on crates.io
   yet resolves against the registry and fails until those are published.
   Regenerate the list with the topological sort in
   [COMPATIBILITY.md](COMPATIBILITY.md) if a crate is added.

   `cargo publish` resolves **dev**-dependencies against crates.io too,
   which is why every internal dev-dependency in this workspace is
   declared path-only rather than `workspace = true` (see the note in the
   root `Cargo.toml`). Cargo strips a path-only dev-dependency from the
   packaged manifest, so `cratefield-ui` can dev-depend on the unpublished
   `module-hello` example, and the
   `adapter-postgres -> module-* -> testing -> adapter-postgres` dev cycle
   never has to be broken with `--no-verify`. If you ever find yourself
   reaching for `--no-verify`, a dev-dependency has grown a version.
3. **Enable trusted publishing per crate.** For each published crate:
   crates.io → crate page → *Settings* → *Trusted publishing* → add
   repository `Cratefield/harness`, workflow `release.yml`,
   environment *(leave empty)*. From then on the release workflow
   publishes that crate with OIDC and no token.
4. **Switch publishing on.** Repository → *Settings* → *Secrets and
   variables* → *Actions* → *Variables* → *New repository variable*:
   name `CRATES_IO_READY`, value `true`. Until this exists the release
   step is skipped and the run says so in an annotation. Verify with a
   manual dry run: Actions → *Release* → *Run workflow*, leave
   `dry_run` checked; the release step should now execute and report
   what it *would* publish.
5. **Revoke the token from step 1.**
6. **Add the team owner.** On each crate page → *Owners* → add a
   GitHub team from the `Cratefield` org (the org that owns this
   repository), so a second human can recover the crates.

If trusted publishing ever needs to be bypassed temporarily: create a
token with the *Update crates* scope and add it as the GitHub Actions
secret `CARGO_REGISTRY_TOKEN` — release-plz picks it up automatically
and skips OIDC. Remove the secret when done.

Two traps in the workflow itself, both commented where they bite:

- The action is pinned to an exact version (`release-plz/action@v0.5.x`).
  It moved from `MarcoIeni/release-plz-action` and publishes no floating
  major tag, so `@v0` does not resolve and the job never starts.
- Its `dry_run` input is tested with `[[ -n ... ]]`, so **any** non-empty
  value turns a dry run on, the string `false` included. The workflow
  passes an empty string for a real release; do not "simplify" it to
  `false` or nothing will ever be published.

## Prerelease flow (0.x, `-rc.N`)

While pre-1.0 a minor bump may break (that is what the caret ranges in
[COMPATIBILITY.md](COMPATIBILITY.md) guard). To cut a prerelease, e.g.
`0.2.0-rc.1`:

1. On a branch, set the candidate versions
   (`cargo set-version -p cratefield-core 0.2.0-rc.1` from `cargo-edit`,
   or by hand) and land the change on `main` with a message like
   `chore(release): prepare cratefield-core 0.2.0-rc.1`.
2. The next `release-plz release` run publishes any version that is not
   on crates.io yet — including the `rc`. (Verify the release run's
   logs; if release-plz skipped it, publish the `rc` manually as in
   step 2 above — same trusted publishing / token rules.)
3. Consumers opt in explicitly: prerelease versions never match a caret
   range, so a venture must pin
   `cratefield-core = "=0.2.0-rc.1"` while testing.
4. The final `0.2.0` follows the normal release-PR flow; the `rc`
   commits appear in its changelog.

## The published set: what runs on its own, what is still by hand

One check of the published set now runs on its own: the `crates.io
resolve` workflow (`.github/workflows/crates-io-resolve.yml` running
`tools/crates-io-resolve.sh`). It resolves this repository's crates the
way a stranger does: every publishable crate that exists on crates.io is
added — no version pin, no path override — to a fresh project in a temp
directory outside this workspace; the resolution is asserted to hold one
copy of each in-repo crate (`cargo tree --duplicates`; two copies of one
of ours is the `expected cratefield_core::Module, found
cratefield_core::Module` failure downstream); and the result is compiled
(`cargo check`). A crate whose first publish is still pending is skipped
with a notice, not failed on — a pending first publish is a gap being
filled (Owner setup above), not a broken published set.

It runs daily on a schedule, after a real release (the Release workflow
calls it once a publishing run actually happened, dry runs excepted), and
on manual dispatch. The schedule is the point: crates.io can become
incoherent without a single commit here — one publish that half-succeeds
is enough — and only a scheduled run is both guaranteed to notice and
guaranteed to rerun after it. It is deliberately not on push or
pull_request: a broken published set should redden the release pipeline,
not every unrelated pull request.

This retires the old one-shot advice to re-run `cargo add
cratefield-core` from an empty project after the first release (issue #15
acceptance): the workflow now does that for every published crate,
together, every day.

Still manual, and **not** run by anything in `.github/workflows/` — a
human runs these when it matters:

- `cargo publish --dry-run -p cratefield-core`: packages and
  verification-builds the crate with only registry dependencies.
- `cargo package --list` for every crate: the packaged file list is
  exact (`include` lists), so the migration SQL and mail templates ship
  and no repo-root file (`BUILD-BRIEF.md`, `PROGRESS.md`, `target/`)
  can leak into a package.
