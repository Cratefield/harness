#!/usr/bin/env bash
# Issue #466: resolve this repository's published crates the way a stranger
# does — from crates.io, with no path overrides.
#
# In-tree, everything compiles against path dependencies and a
# workspace-level `version = "0.5"` requirement on cratefield-core, and
# nothing in this repository ever downloads its own crates from the
# registry. So a publish that leaves the published set unresolvable — say,
# core 0.5.0 landing while every published dependent still requires ^0.4 —
# is invisible here, and surfaces only when someone outside tries `cargo
# add` and cannot. This script is that stranger: it takes every publishable
# crate, skips the ones whose first publish has not happened yet, and
# resolves and compiles them together in a throwaway project outside the
# workspace. It fails when no satisfiable version set exists, and it fails
# when the satisfiable set contains two copies of one of our crates — the
# state that produces `expected cratefield_core::Module, found
# cratefield_core::Module` in a downstream build, because every type in
# core is an identity per copy.
#
# Issue #708: resolving what crates.io holds also says nothing about
# what this tree holds, so a workspace version that was never published
# passes here silently. Every crate that exists on the registry must
# therefore have the version this workspace names published too.
#
# Usage: tools/crates-io-resolve.sh [crate ...]
#   With no arguments every publishable crate in the workspace is used;
#   with arguments, exactly those (so a subset can be checked by hand).
set -euo pipefail

cd "$(dirname "$0")/.."

die() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

for tool in cargo jq curl; do
  command -v "$tool" >/dev/null || die "crates-io-resolve needs $tool, which is not installed or not on PATH. GitHub runners ship it; elsewhere, install it first."
done

# The workspace's own view of itself: `cargo metadata` reports `publish:
# null` for a publishable package and `publish: []` for one marked
# `publish = false`, so null is the publishable filter. Read even when the
# crate list comes from the arguments — the target-kind check below needs
# it either way.
metadata=$(cargo metadata --no-deps --format-version 1) || \
  die "cargo metadata failed (its error is above): the workspace manifest itself is broken, which is a different problem than the published set."

# --- 1. The crate list ---------------------------------------------------
if [ "$#" -gt 0 ]; then
  # Arguments verbatim, deduplicated only so one invocation of
  # `cargo add` cannot name the same crate twice.
  mapfile -t crates < <(printf '%s\n' "$@" | sort -u)
else
  mapfile -t crates < <(jq -r '.packages[] | select(.publish == null) | .name' <<<"$metadata" | sort -u)
fi
[ "${#crates[@]}" -gt 0 ] || die "the crate list is empty — with no arguments, cargo metadata named no publishable package (every package is publish = false?), and that is a failure here, not a pass."

# --- 2. Keep only crates that exist on crates.io -------------------------
#
# A crate whose first publish has not happened yet is a gap being filled
# (docs/RELEASING.md, "Owner setup"), not a broken published set, so it is
# skipped with a notice rather than failed on. Existence is checked against
# the sparse index, the thing cargo itself resolves against, not the
# crates.io JSON API, which carries a user-agent and rate-limit policy the
# index does not. The path mirroring is cargo's own rule: 1-char names
# under 1/, 2-char under 2/, 3-char under 3/<first>/, everything else
# under <first two>/<chars 3-4>/.
# The scratch directory is made here rather than at the resolve stage
# because the index body of the existence probe is kept in it: the release
# lag check below reads that same body, so no crate is asked about twice.
scratch=$(mktemp -d /tmp/crates-io-resolve.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
existing=()
# Filled in below and reported at the very end: `name local-version
# (crates.io has <newest>)` for every crate whose workspace version the
# registry has never published.
lagged=()
for name in "${crates[@]}"; do
  case ${#name} in
    1) path="1/$name" ;;
    2) path="2/$name" ;;
    3) path="3/${name:0:1}/$name" ;;
    *) path="${name:0:2}/${name:2:2}/$name" ;;
  esac
  # The HTTP status is read, not curl's exit code: `-sf` collapses every
  # 4xx and 5xx, and every DNS/connect/timeout failure, into the same
  # "not found" as a genuine 404, and a registry hiccup mid-loop would
  # then shrink the checked set and let a subset pass as the whole — a
  # false green on the exact check this script exists to perform.
  # `|| true` only keeps `set -e` from killing the script on the capture
  # itself; the branch below is what decides. A 000 (or empty) status
  # means curl never got a response at all.
  status=$(curl -s -o "$scratch/index.json" -w '%{http_code}' --retry 2 --retry-connrefused -m 30 "https://index.crates.io/$path") || true
  if [ "$status" = 200 ]; then
    existing+=("$name")
    # Issue #708. The stages below resolve whatever the registry holds,
    # so a crate whose newest version exists only in this tree resolves
    # cleanly and reads as healthy: nothing in a stranger's build points
    # back at a version that was never published. The index body just
    # fetched is one JSON object per line, so `vers` is read off it with
    # jq instead of asking the registry a second time — `==` compares
    # whole strings, so 0.2.0 cannot pass for 0.2.01, and a yanked
    # version still counts as published (it resolved; it was withdrawn).
    # A crate named on the command line that this workspace does not
    # build has no workspace version to compare and is left alone.
    local_version=$(jq -r --arg n "$name" '.packages[] | select(.name == $n) | .version' <<<"$metadata")
    if [ -n "$local_version" ] && ! jq -s -e --arg v "$local_version" 'any(.[]; .vers == $v)' "$scratch/index.json" >/dev/null; then
      newest=$(jq -r 'select(.yanked | not) | .vers' "$scratch/index.json" | tail -n 1)
      lagged+=("$name $local_version (crates.io has ${newest:-no version})")
    fi
  elif [ "$status" = 404 ]; then
    printf '::notice::skipping %s: not on crates.io yet. Its first publish is still pending, so the published set cannot include it (docs/RELEASING.md, Owner setup).\n' "$name" >&2
  else
    die "could not reach the sparse index to check $name (HTTP status ${status:-none}, after --retry re-asked the transient statuses). This is deliberately fatal rather than a skip: treating an unreachable registry as \"not published yet\" would shrink the checked set and pass a subset as the whole. Nothing about the published set was learned — run again once the registry answers."
  fi
done
# The lag list is reported here, where it is collected, rather than at the
# end: the stages below can fail first on their own terms — the duplicate
# assertion of issue #466 is red today — and an error this run found must
# reach the log whatever else it finds, or it is lost behind the next one.
# Only the non-zero exit waits for the end.
if [ "${#lagged[@]}" -gt 0 ]; then
  for entry in "${lagged[@]}"; do
    printf '::error::%s: the workspace version was never published\n' "$entry" >&2
  done
  printf '::error::the workspace carries a version crates.io has never published. Either a release run failed part-way or publishing is switched off for these crates (docs/RELEASING.md). Everything checked below is the published set, so a run that passes while this stands has verified an older set than this tree builds, and a stranger pulling these crates gets the older versions.\n' >&2
fi
[ "${#existing[@]}" -gt 0 ] || die "none of the requested crates exists on crates.io yet — every name answered a plain 404, so there is no published set to resolve. That is what a first publish still pending looks like: run this again after publishing. A registry outage cannot land here; it dies in the loop above."

echo "crates-io-resolve: resolving ${#existing[@]} published crate(s): ${existing[*]}"

# --- 3. Resolve like a stranger ------------------------------------------
#
# A fresh project outside the workspace, the crates added with no version
# and no path override, so cargo picks the same latest releases a stranger
# picking up the published set would get.
cd "$scratch"
cargo new --quiet cf-resolve
cd cf-resolve
# One invocation, one resolution of the whole set: `cargo add` resolves
# after the manifest edit, and a set with no satisfiable combination fails
# here with cargo naming the conflicting requirements.
if ! cargo add --quiet "${existing[@]}"; then
  die "cargo add failed (cargo's own error above is the authoritative diagnosis, and it says which kind of failure this is). The likely case is the one this script exists to catch (issue #466): crates.io now holds a combination of published versions with no satisfiable resolution — typically one crate republished at a new version while its published dependents still require the previous range — and the fix is to publish updated dependents (docs/RELEASING.md), not to weaken this check. If cargo's error is a network failure instead, the registry was unreachable mid-run: transient, and nothing about the published set was learned."
fi

# --- 4. No two copies of a crate of ours ---------------------------------
#
# Cargo happily resolves two semver-incompatible versions of the same crate
# into one graph, and a build that holds both then fails — or worse,
# compiles — with `expected cratefield_core::Module, found
# cratefield_core::Module`, because each copy's types are distinct
# identities. This assertion runs BEFORE `cargo check` so the loud, named
# failure comes before the confusing compiler one. Duplicates of
# third-party crates are ordinary and must not fail; a duplicate counts
# only when its name is one this run added, which is exactly the "belongs
# to this repository" test, read straight off the crate list. The edges
# are scoped to `--edges normal`: `--duplicates` defaults to counting
# build and dev edges too, but a duplicate arriving only through those
# never puts two copies of the crate in a downstream build's type graph,
# so counting them would fail a build that is actually fine.
# Stderr is silenced because `cargo tree --duplicates` answers an empty
# graph with "warning: nothing to print", which reads like a failure in the
# middle of this script's own output. It is not: empty means one copy of
# everything, which is the pass this assertion wants.
if ! dup_output=$(cargo tree --duplicates --edges normal 2>/dev/null); then
  die "cargo tree --duplicates failed: run it by hand in a scratch project to see why. The resolved graph could not be printed, so the duplicate assertion cannot run."
fi
declare -A added=()
for name in "${existing[@]}"; do added["$name"]=1; done
# Each duplicated package opens its own block with `name vX.Y.Z` in column
# zero; everything beneath it is an indented tree branch.
offending=()
while IFS= read -r name; do
  [ -z "$name" ] && continue
  if [ -n "${added[$name]:-}" ]; then offending+=("$name"); fi
done < <(awk '/^[A-Za-z0-9_-]+ v[0-9]/ { print $1 }' <<<"$dup_output" | sort -u)

if [ "${#offending[@]}" -gt 0 ]; then
  {
    echo "$dup_output"
    printf '\n'
    printf '::error::the published set resolved, but with duplicate copies of: %s. Two copies of one of our crates in one build produce the `expected cratefield_core::Module, found cratefield_core::Module` error downstream — the two copies'"'"' types are distinct identities, so a module built against one cannot talk to a runtime built against the other. This is the state issue #466 exists to catch: a publish left the dependents on crates.io requiring one version of the crate while this set resolved another. Publish updated dependents (docs/RELEASING.md) until the set resolves to one copy each.\n' "${offending[*]}"
  } >&2
  exit 1
fi

# --- 5. Compile the resolved set ------------------------------------------
#
# A published crate with no library target (lib, rlib or proc-macro) can be
# *resolved* but offers nothing to compile *against*: cargo builds only the
# library of a dependency, so a bin-only one contributes resolution and no
# code. The whole set has already taken part in the resolution and the
# duplicate assertion above; before `cargo check`, the bin-only ones are
# removed so the check compiles exactly what a downstream crate could link
# against.
bin_only=()
for name in "${existing[@]}"; do
  kinds=$(jq -r --arg n "$name" '.packages[] | select(.name == $n) | .targets[].kind[]' <<<"$metadata" | sort -u)
  if ! grep -qx -e lib -e rlib -e proc-macro <<<"$kinds"; then
    bin_only+=("$name")
  fi
done
if [ "${#bin_only[@]}" -gt 0 ]; then
  echo "crates-io-resolve: removing bin-only crate(s) before the check (resolved above, nothing to compile against): ${bin_only[*]}"
  cargo remove --quiet "${bin_only[@]}"
fi

cargo check --quiet
if [ "${#bin_only[@]}" -gt 0 ]; then
  echo "crates-io-resolve: ${#existing[@]} published crate(s) resolved together, one copy each — $(( ${#existing[@]} - ${#bin_only[@]} )) of them compiled, the ${#bin_only[@]} bin-only one(s) contributing resolution only (removed above, nothing to compile against)."
else
  echo "crates-io-resolve: ${#existing[@]} published crate(s) resolved and compiled together, one copy each."
fi

# --- 6. The workspace version is on crates.io ------------------------------
#
# Reported back in stage 2, where it is collected; only the verdict is
# left to run last. The stages in between still run, and still report
# their own findings, when the list is not empty — a version that was
# never published is a release process problem whose diagnosis does not
# need the resolve or compile stages' verdict, but suppressing what they
# found would hide the more urgent of the two.
[ "${#lagged[@]}" -eq 0 ] || exit 1
