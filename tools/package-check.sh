#!/usr/bin/env bash
# Issues #489, #490, #491, #493, #495, #499: package the publishable crates
# the way `cargo publish` will, before a release rather than during one.
#
# Every build in this repository reads the source tree, so a crate whose
# `include` list drops a file that `include_str!` or `include_bytes!` reads
# still compiles here, and fails only once packaged, when the file is not
# in the tarball (#499). No source-tree build can notice. So this script
# checks, in order: that the manual first-publish list in
# docs/RELEASING.md names exactly the publishable set in dependency order;
# that each crate in UNPACKAGEABLE still fails to package; that no packaged
# file list carries a repo-local file; and, last and slowest, that every
# packageable crate builds from its own extracted tarball.
#
# Usage: tools/package-check.sh [--no-verify]
#   --no-verify  skip the verification build (the slow step, about half
#                an hour cold) for a fast local run.
set -euo pipefail

cd "$(dirname "$0")/.."

die() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

verify=1
case "${1:-}" in
  "") ;;
  --no-verify) verify=0 ;;
  *) die "usage: tools/package-check.sh [--no-verify] (got '$1')" ;;
esac

for tool in cargo jq awk; do
  command -v "$tool" >/dev/null || die "package-check needs $tool, which is not installed or not on PATH."
done

# Crates that cannot be packaged yet, each because of a path-only internal
# dependency that has no version for crates.io to resolve, as `crate:dep`
# with the dependency cargo names first. Each fix removes its entry; the
# check below fails once an entry packages, or fails for another reason, so
# this list cannot outlive the reason for it.
UNPACKAGEABLE=(
  cratefield-runtime-native:cratefield-auth-client
  cratefield-runtime-cloudflare:cratefield-auth-client
  # Also path-only: cratefield-introspect.
  cratefield-cli:cratefield-client-ts
  cratefield:cratefield-tables-api
)

metadata=$(cargo metadata --no-deps --format-version 1) || \
  die "cargo metadata failed (its error is above): the workspace manifest itself is broken."

# --- 1. The publishable set ------------------------------------------------
#
# `publish: null` in cargo metadata, minus every `[[package]]` block that
# release-plz.toml marks `publish = false` or `release = false` —
# release-plz holds those back even when the crate's own manifest does not.
mapfile -t held_back < <(awk '
  /^\[/ {
    if (name != "" && held) print name
    name = ""; held = 0; in_pkg = ($0 ~ /^\[\[package\]\]/); next
  }
  in_pkg && /^[[:space:]]*name[[:space:]]*=/ {
    name = $0; sub(/^[^"]*"/, "", name); sub(/".*/, "", name)
  }
  in_pkg && /^[[:space:]]*(publish|release)[[:space:]]*=[[:space:]]*false/ { held = 1 }
  END { if (name != "" && held) print name }
' release-plz.toml)

declare -A publishable=()
while IFS= read -r name; do publishable["$name"]=1; done \
  < <(jq -r '.packages[] | select(.publish == null) | .name' <<<"$metadata")
for name in "${held_back[@]}"; do unset "publishable[$name]"; done
[ "${#publishable[@]}" -gt 0 ] || die "the publishable set is empty; cargo metadata or release-plz.toml parsing is broken."
mapfile -t crates < <(printf '%s\n' "${!publishable[@]}" | sort)
echo "package-check: ${#crates[@]} publishable crate(s)"

# --- 2. The first-publish list in docs/RELEASING.md ------------------------
#
# The list is the order a human publishes in, so it has to name every
# publishable crate once, nothing else, and each after its own publishable
# dependencies: normal and build, optional included (an optional dependency
# still has to resolve on crates.io), and dev-dependencies that carry a
# version. Path-only dev-dependencies are stripped when packaging, so they
# do not count. The list is the fenced block in step 2, the one that
# exports CARGO_REGISTRY_TOKEN.
doc=docs/RELEASING.md
block=$(awk '
  /^[[:space:]]*```/ {
    if (in_fence && found) { printf "%s", buf; exit }
    in_fence = !in_fence; buf = ""; found = 0; next
  }
  in_fence { buf = buf $0 "\n"; if ($0 ~ /CARGO_REGISTRY_TOKEN=/) found = 1 }
' "$doc")
[ -n "$block" ] || die "$doc has no fenced block exporting CARGO_REGISTRY_TOKEN, so the first-publish list in step 2 cannot be found."
problems=()
declare -A position=()
index=0
while IFS= read -r name; do
  index=$((index + 1))
  if [ -n "${position[$name]:-}" ]; then
    problems+=("$doc lists $name more than once in the first-publish list.")
  else
    position["$name"]=$index
  fi
done < <(sed -nE 's/^[[:space:]]*cargo publish (--dry-run )?-p ([A-Za-z0-9_-]+).*/\2/p' <<<"$block")

for name in "${crates[@]}"; do
  [ -n "${position[$name]:-}" ] || problems+=("$name is publishable but missing from the first-publish list in $doc.")
done
for name in "${!position[@]}"; do
  [ -n "${publishable[$name]:-}" ] || problems+=("$doc lists $name, which is not publishable (publish = false in its manifest or release-plz.toml, or not a workspace package).")
done
while read -r name dep; do
  # Crates outside the set, or missing from the list, are reported above.
  if [ -z "${publishable[$name]:-}" ] || [ -z "${publishable[$dep]:-}" ]; then continue; fi
  if [ -z "${position[$name]:-}" ] || [ -z "${position[$dep]:-}" ]; then continue; fi
  if [ "${position[$name]}" -lt "${position[$dep]}" ]; then
    problems+=("$doc publishes $name before $dep, which it depends on: move $name below $dep.")
  fi
done < <(jq -r '.packages[] | .name as $n | .dependencies[]
  | select(.kind == null or .kind == "build" or (.kind == "dev" and .req != "*"))
  | "\($n) \(.name)"' <<<"$metadata" | sort -u)
if [ "${#problems[@]}" -gt 0 ]; then
  printf '::error::%s\n' "${problems[@]}" >&2
  exit 1
fi
echo "package-check: $doc lists all ${#crates[@]} in dependency order"

# --- 3. UNPACKAGEABLE is still true ----------------------------------------
declare -A skip=()
for entry in "${UNPACKAGEABLE[@]}"; do
  name=${entry%%:*} dep=${entry#*:}
  [ -n "${publishable[$name]:-}" ] || die "UNPACKAGEABLE names $name, which is not publishable; remove it."
  skip["$name"]=1
  if output=$(cargo package --no-verify --no-metadata --allow-dirty -p "$name" 2>&1); then
    rm -f "${CARGO_TARGET_DIR:-target}/package/$name"-*.crate
    die "$name packages now; remove it from UNPACKAGEABLE in tools/package-check.sh (and its note in $doc)."
  fi
  grep -q "dependency \`$dep\` does not specify a version" <<<"$output" || {
    printf '%s\n' "$output" >&2
    die "$name fails to package, but not for the path-only dependency on $dep that UNPACKAGEABLE records; the recorded reason is stale. Cargo's error is above: update the entry, or fix what it names."
  }
done
echo "package-check: ${#UNPACKAGEABLE[@]} crate(s) in UNPACKAGEABLE still fail to package"

# --- 4. Nothing repo-local leaks into a package ----------------------------
#
# Paths are relative to the crate root. A build directory, agent scratch
# (BRIEF.md, BUILD-BRIEF.md, any *-BRIEF.md, PROGRESS.md) and any dotenv
# file must never ship.
deny='(^|/)(target/|[^/]*BRIEF\.md$|PROGRESS\.md$|\.env[^/]*$)'
leaks=()
for name in "${crates[@]}"; do
  files=$(cargo package --list --allow-dirty -p "$name") || die "cargo package --list -p $name failed (its error is above)."
  while IFS= read -r path; do
    leaks+=("$name packages $path")
  done < <(grep -E "$deny" <<<"$files" || true)
done
if [ "${#leaks[@]}" -gt 0 ]; then
  printf "::error::%s: tighten its \`include\` list.\n" "${leaks[@]}" >&2
  exit 1
fi
echo "package-check: no packaged file matches the deny-list"

# --- 5. Verification build -------------------------------------------------
#
# One invocation for all of them: multi-package `cargo package` overlays
# the freshly packaged workspace crates as a local registry, so a crate
# resolves its unpublished siblings, and each builds from its extracted
# tarball, where a file missing from `include` is missing for real.
if [ "$verify" = 0 ]; then
  echo "package-check: verification build skipped (--no-verify)"
  exit 0
fi
args=()
for name in "${crates[@]}"; do
  [ -n "${skip[$name]:-}" ] || args+=(-p "$name")
done
cargo package --no-metadata --allow-dirty "${args[@]}" || \
  die "the verification build failed (cargo's error is above). A \"couldn't read\" from include_str! or include_bytes! means the crate's \`include\` list misses that file (#499); \"must have a version requirement\" means a path-only dependency, which belongs in UNPACKAGEABLE until it is fixed."
echo "package-check: $(( ${#args[@]} / 2 )) crate(s) packaged and built from their tarballs"
