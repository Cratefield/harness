# Releasing `cratefield-*` to crates.io

The pipeline is wired; the only things left are one-time crates.io
setup steps that need a human with the owner account. This page is the
exact list (issue #15). Everything here is **for the owner** — nothing
below runs from this repository's CI until it is configured.

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
   cargo publish -p cratefield-push-auth      # before adapter-apns
   cargo publish -p cratefield-adapter-apns
   cargo publish -p cratefield-adapter-fcm    # before the facade
   cargo publish -p cratefield-adapter-webpush  # before the facade
   cargo publish -p cratefield-secrets
   cargo publish -p cratefield-runtime-cloudflare
   cargo publish -p cratefield-runtime-native
   cargo publish -p cratefield-testing
   cargo publish -p cratefield-module-email-signup
   cargo publish -p cratefield-module-waitlist
   cargo publish -p cratefield-module-cms
   cargo publish -p cratefield-ui
   cargo publish -p cratefield-cli
   cargo publish -p cratefield            # the facade: depends on all of them
   ```

   Twenty-one crates, and the order is the dependency order: `--dry-run` for
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

## What CI checks without credentials

- `cargo publish --dry-run -p cratefield-core` (definition of done in
  CI's absence: it packages and verification-builds the crate with only
  registry dependencies).
- `cargo package --list` for every crate: the packaged file list is
  exact (`include` lists), so the migration SQL and mail templates ship
  and no repo-root file (`BUILD-BRIEF.md`, `PROGRESS.md`, `target/`)
  can leak into a package.
- After the first real release, `cargo add cratefield-core` from an empty
  project (issue #15 acceptance) should be re-run by hand once.
