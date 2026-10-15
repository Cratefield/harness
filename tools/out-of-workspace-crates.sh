#!/usr/bin/env bash
# The crates the workspace `exclude`s — the venture-side `fz` binaries,
# the cli-acceptance fixture and the spikes — keep their own Cargo.lock,
# and a workspace dependency bump leaves those lockfiles stale (issue
# #856). Every release PR is such a bump: release-plz rewrites crate
# versions and workspace requirements, but only in the workspace, so the
# `standalone crate` jobs fail `--locked` on the release PR until the
# out-of-workspace lockfiles are refreshed too.
#
# Discovery is every directory holding a git-tracked Cargo.toml, minus
# the packages the root workspace resolves (its `members` globs minus
# its `exclude` list); the root manifest's directory drops out because
# it defines the workspace rather than a crate. It is re-derived on every
# call, so a new crate outside the workspace is covered without editing
# this script or a workflow. The CI `out-of-workspace crate discovery`
# job and the release workflow both call it.
#
# Usage:
#   tools/out-of-workspace-crates.sh                  # JSON array of dirs
#   tools/out-of-workspace-crates.sh --refresh-locks  # bring each lock up to its manifest
set -euo pipefail

cd "$(dirname "$0")/.."

die() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

for tool in cargo git python3; do
  command -v "$tool" >/dev/null || die "out-of-workspace-crates needs $tool, which is not installed or not on PATH."
done

dirs_json() {
  python3 - <<'PY'
import json, os, subprocess

tracked = subprocess.run(
    ["git", "ls-files", "*Cargo.toml", ":!:**/node_modules/**"],
    check=True, capture_output=True, text=True,
).stdout.splitlines()
tracked_dirs = {d for f in tracked if (d := os.path.dirname(f))}

members = json.loads(subprocess.run(
    ["cargo", "metadata", "--no-deps", "--format-version", "1"],
    check=True, capture_output=True, text=True,
).stdout)
member_dirs = {
    os.path.relpath(os.path.dirname(p["manifest_path"]))
    for p in members["packages"]
}

out = sorted(tracked_dirs - member_dirs)
if not out:
    raise SystemExit(
        "no out-of-workspace Cargo.toml found: the discovery query is broken"
    )
print(json.dumps(out))
PY
}

case "${1:-}" in
  "")
    dirs_json
    ;;
  --refresh-locks)
    # `cargo metadata` rewrites a lock that no longer matches its manifest
    # (or the path dependencies it points into) and leaves a current one
    # alone, without building anything.
    dirs_json | python3 -c 'import json, sys; print("\n".join(json.load(sys.stdin)))' |
      while read -r dir; do
        (cd "$dir" && cargo metadata --format-version 1 >/dev/null)
      done
    ;;
  *)
    die "unknown argument: $1 (usage: tools/out-of-workspace-crates.sh [--refresh-locks])"
    ;;
esac
