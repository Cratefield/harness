# Releasing `factory0-*` to crates.io

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
   not yet on crates.io — in dependency order (`factory0-core` first) —
   and tags `<crate>-v<version>` with a GitHub release per crate.

Configuration lives in `release-plz.toml` (per-crate versioning,
conventional-commit changelogs, `publish = false` for `examples/*` and
the CLI acceptance crate).

Authentication is **trusted publishing**: the workflow exchanges the
GitHub Actions OIDC token (`id-token: write`) for a short-lived
crates.io token. No `CARGO_REGISTRY_TOKEN` is stored anywhere.

## Owner setup (once)

These steps need the crates.io account that will own the `factory0-*`
names. A crate's trusted publisher can only be configured **after the
crate exists**, so the very first release of each crate is manual:

1. **Create a scoped token.** Sign in to crates.io → *Account settings*
   → *API Tokens* → *New token*. Scope: **Publish new crates**. This
   token exists only for the first publishes; revoke it afterwards.
2. **First-publish each crate manually**, in dependency order, from a
   checkout of `main` at the version being released:

   ```sh
   export CARGO_REGISTRY_TOKEN=...   # the scoped token from step 1
   cargo publish --dry-run -p factory0-core   # then without --dry-run
   cargo publish -p factory0-testing
   cargo publish -p factory0-adapter-sqlite
   cargo publish -p factory0-adapter-resend
   cargo publish -p factory0-adapter-turnstile
   cargo publish -p factory0-runtime-cloudflare
   cargo publish -p factory0-module-email-signup
   cargo publish -p factory0-module-waitlist
   cargo publish -p factory0-cli
   ```

   (`--dry-run` for a crate whose upstream `factory0-*` dependencies
   are not on crates.io yet resolves against the registry and fails
   until those are published first — hence the order.)
3. **Enable trusted publishing per crate.** For each published crate:
   crates.io → crate page → *Settings* → *Trusted publishing* → add
   repository `Cratefield/harness`, workflow `release.yml`,
   environment *(leave empty)*. From then on the release workflow
   publishes that crate with OIDC and no token.
4. **Revoke the token from step 1.**
5. **Add the team owner.** On each crate page → *Owners* → add the
   Factory Zero GitHub org team, so a second human can recover the
   crates.

If trusted publishing ever needs to be bypassed temporarily: create a
token with the *Update crates* scope and add it as the GitHub Actions
secret `CARGO_REGISTRY_TOKEN` — release-plz picks it up automatically
and skips OIDC. Remove the secret when done.

## Prerelease flow (0.x, `-rc.N`)

While pre-1.0 a minor bump may break (that is what the caret ranges in
[COMPATIBILITY.md](COMPATIBILITY.md) guard). To cut a prerelease, e.g.
`0.2.0-rc.1`:

1. On a branch, set the candidate versions
   (`cargo set-version -p factory0-core 0.2.0-rc.1` from `cargo-edit`,
   or by hand) and land the change on `main` with a message like
   `chore(release): prepare factory0-core 0.2.0-rc.1`.
2. The next `release-plz release` run publishes any version that is not
   on crates.io yet — including the `rc`. (Verify the release run's
   logs; if release-plz skipped it, publish the `rc` manually as in
   step 2 above — same trusted publishing / token rules.)
3. Consumers opt in explicitly: prerelease versions never match a caret
   range, so a venture must pin
   `factory0-core = "=0.2.0-rc.1"` while testing.
4. The final `0.2.0` follows the normal release-PR flow; the `rc`
   commits appear in its changelog.

## What CI checks without credentials

- `cargo publish --dry-run -p factory0-core` (definition of done in
  CI's absence: it packages and verification-builds the crate with only
  registry dependencies).
- `cargo package --list` for every crate: the packaged file list is
  exact (`include` lists), so the migration SQL and mail templates ship
  and no repo-root file (`BUILD-BRIEF.md`, `PROGRESS.md`, `target/`)
  can leak into a package.
- After the first real release, `cargo add factory0-core` from an empty
  project (issue #15 acceptance) should be re-run by hand once.
