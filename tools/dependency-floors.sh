#!/usr/bin/env bash
# Issue #712: an internal requirement must have a floor that is built on the
# same cratefield-core as this tree.
#
# Every build here resolves `cratefield-core` through a path dependency, so
# the workspace compiles whatever the published requirements say. What
# crates.io sees is different: release-plz cascades a breaking core minor to
# its dependents as *patch* bumps (cratefield-auth-client 0.2.0 -> 0.2.1) and
# leaves the root `[workspace.dependencies]` requirement at `"0.2"`, so a
# published dependent requires auth-client `^0.2` — whose lowest published
# version, 0.2.0, still requires core `^0.6`. A venture with an existing
# lockfile keeps auth-client at 0.2.0 and ends up with two copies of core,
# and every type in core is an identity per copy.
#
# `cargo update -Z minimal-versions` cannot see this: in-tree the internal
# dependency resolves through `path`, so the published floor is never read,
# and the flag drags every third-party crate to its floor as well. So this
# asks the sparse index directly, the thing cargo itself resolves against.
#
# For every internal requirement (crate D, req R) a publishable member
# declares, it finds the lowest non-yanked published version of D satisfying R
# — the floor a stranger's resolver is free to pick — and checks that floor's
# own internal requirements sit in the same caret-compatibility bucket as this
# tree's. `0.x` compares by minor, `0.0.x` by patch, `>=1` by major, which is
# what decides whether a second copy of a crate of ours enters the graph.
#
# Usage: tools/dependency-floors.sh
#   CRATES_INDEX_URL  index base to read (default https://index.crates.io),
#                     overridable so the check can run against a fixture.
set -euo pipefail

cd "$(dirname "$0")/.."

die() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

for tool in cargo jq curl sort; do
  command -v "$tool" >/dev/null || die "dependency-floors needs $tool, which is not installed or not on PATH. GitHub runners ship it; elsewhere, install it first."
done

index_base=${CRATES_INDEX_URL:-https://index.crates.io}

# --- Version arithmetic ----------------------------------------------------
#
# The requirement shapes here are a leading `^`, `=`, `~` or bare (`0.8`,
# `0.2.1`) — what `[workspace.dependencies]` writes, since a bare requirement
# is a caret in cargo. Anything else (a comma list, a bound) is declined
# rather than guessed at, and the requirement is skipped with a notice.

# Normalise a requirement into an inclusive lower bound and an exclusive
# upper one, three components each. Declines (`return 1`) a shape it cannot
# read exactly.
req_range() {
  local req=$1 op v maj min pat precision=1 upper
  case $req in
    *,* | *'>'* | *'<'*) return 1 ;;
    ^*) op='^'; v=${req#^} ;;
    '~'*) op='~'; v=${req#\~} ;;
    '='*) op='='; v=${req#=} ;;
    *) op='^'; v=$req ;;
  esac
  v=${v// /}
  [[ $v =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || return 1
  IFS=. read -r maj min pat <<<"$v"
  min=${min:-0}
  pat=${pat:-0}
  [[ $v == *.* ]] && precision=2
  [[ $v == *.*.* ]] && precision=3
  case $op in
    '=') upper="$maj.$min.$((pat + 1))" ;;
    '~')
      # ~1.2.3 is >=1.2.3, <1.3.0; ~1 is >=1.0.0, <2.0.0.
      if [ "$precision" = 1 ]; then upper="$((maj + 1)).0.0"; else upper="$maj.$((min + 1)).0"; fi
      ;;
    '^')
      # ^0.0 is >=0.0.0, <0.1.0 — a missing patch stays wildcarded — while
      # ^0.0.3 stops at 0.0.4.
      if [ "$maj" -gt 0 ]; then
        upper="$((maj + 1)).0.0"
      elif [ "$precision" -lt 3 ]; then
        upper="0.$((min + 1)).0"
      elif [ "$min" -gt 0 ]; then
        upper="0.$((min + 1)).0"
      else
        upper="0.0.$((pat + 1))"
      fi
      ;;
  esac
  printf '%d.%d.%d %s\n' "$maj" "$min" "$pat" "$upper"
}

vle() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }
vlt() { vle "$1" "$2" && [ "$1" != "$2" ]; }

# The bucket two requirements can coexist in without producing two copies of
# the crate, read off the lower bound — the version a fresh resolve lands on.
bucket_of_req() {
  local range lower maj min pat
  range=$(req_range "$1") || return 1
  read -r lower _ <<<"$range"
  IFS=. read -r maj min pat <<<"$lower"
  if [ "$maj" -gt 0 ]; then printf 'major %s\n' "$maj"
  elif [ "$min" -gt 0 ]; then printf '0.%s\n' "$min"
  else printf '0.0.%s\n' "$pat"; fi
}

# --- The workspace's own view of itself ------------------------------------
metadata=$(cargo metadata --no-deps --format-version 1) || \
  die "cargo metadata failed (its error is above): the workspace manifest itself is broken."

declare -A member=()          # crate -> version, every workspace member
declare -A publishable=()     # crate -> 1
while IFS=$'\t' read -r name version is_published; do
  member["$name"]=$version
  [ "$is_published" = yes ] && publishable["$name"]=1
done < <(jq -r '.packages[] | [.name, .version, (if .publish == null then "yes" else "no" end)] | @tsv' <<<"$metadata")
[ "${#member[@]}" -gt 0 ] || die "cargo metadata named no workspace package; the workspace manifest itself is broken."

# One table of every internal dependency edge, so it is read once.
mapfile -t edges < <(jq -r '.packages[] | .name as $owner | .dependencies[]
  | [$owner, (.package // .name), .req, (.kind // "normal")] | @tsv' <<<"$metadata")

# The requirement this tree declares on each internal crate. Every member
# inherits it from the root table, so the first edge seen is the one; a
# versionless (`*`) entry is a path-only dependency that no publishable member
# may carry, which is package-check's business rather than this check's.
declare -A tree_req=()
for edge in "${edges[@]}"; do
  IFS=$'\t' read -r _owner dep req kind <<<"$edge"
  [ -n "${member[$dep]:-}" ] || continue
  [ "$kind" = dev ] && continue
  [ "$req" = '*' ] && continue
  [ -n "${tree_req[$dep]:-}" ] || tree_req["$dep"]=$req
done

# Every distinct (internal crate, requirement) a publishable member declares.
# Dev-dependencies are stripped when a crate is packaged, and a path-only
# requirement has no published floor to disagree with.
declare -A used_by=()
for edge in "${edges[@]}"; do
  IFS=$'\t' read -r owner dep req kind <<<"$edge"
  [ -n "${publishable[$owner]:-}" ] || continue
  [ -n "${member[$dep]:-}" ] || continue
  [ "$kind" = dev ] && continue
  [ "$req" = '*' ] && continue
  used_by["$dep"$'\t'"$req"]+="$owner "
done
[ "${#used_by[@]}" -gt 0 ] || die "no publishable member declares a versioned internal dependency; the read of cargo metadata above is broken."

# --- The index, fetched once per crate -------------------------------------
scratch=$(mktemp -d /tmp/dependency-floors.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
declare -A fetched=()

# The path mirroring is cargo's own rule: 1-char names under 1/, 2-char under
# 2/, 3-char under 3/<first>/, everything else under <first two>/<chars
# 3-4>/. The HTTP status is read rather than curl's exit code, because `-f`
# collapses a DNS or timeout failure into the same "not found" as a genuine
# 404, and a registry hiccup must not shrink the checked set and let a subset
# pass as the whole.
#
# The path comes back in $index_path, not on stdout, and that is load bearing:
# called as `index_file "$dep" || continue`, a `die` inside a command
# substitution exits only the substitution and its status is eaten by `||`,
# so an unreachable registry would skip every crate and report a pass having
# learned nothing. The same subshell would also drop the $fetched writes, and
# a crate with two requirements of it would be fetched twice.
index_file() {
  local name=$1 path status
  case ${#name} in
    1) path="1/$name" ;;
    2) path="2/$name" ;;
    3) path="3/${name:0:1}/$name" ;;
    *) path="${name:0:2}/${name:2:2}/$name" ;;
  esac
  case ${fetched[$name]:-} in
    ok) index_path=$scratch/$name; return 0 ;;
    missing) return 1 ;;
  esac
  status=$(curl -s -o "$scratch/$name" -w '%{http_code}' --retry 2 --retry-connrefused -m 30 "$index_base/$path") || status=000
  case $status in
    200) fetched["$name"]=ok; index_path=$scratch/$name ;;
    404)
      fetched["$name"]=missing
      printf '::notice::skipping %s: not on crates.io yet, so no published floor of it can be stale (docs/RELEASING.md, Owner setup).\n' "$name" >&2
      return 1
      ;;
    *) die "could not reach $index_base to read $name (HTTP status ${status:-none}, after --retry re-asked the transient statuses). This is deliberately fatal rather than a skip: an unreachable registry is not \"not published yet\", and nothing about the published set was learned. Run again once the registry answers." ;;
  esac
}

# The versions of a crate satisfying a requirement, oldest first. Pre-releases
# are skipped: a caret range never admits one, and a requirement written on a
# pre-release floor is a transient state a release PR resolves.
versions_within() {
  local file=$1 req=$2 range lower upper vers
  range=$(req_range "$req") || return 1
  read -r lower upper <<<"$range"
  while IFS= read -r vers; do
    [[ $vers == *-* ]] && continue
    vle "$lower" "$vers" && vlt "$vers" "$upper" && printf '%s\n' "$vers"
  done < <(jq -r 'select(.yanked == false) | .vers' "$file") | sort -V
}

# The internal requirements of one published version, one per line as
# "<crate>\t<requirement>". Dev-dependencies are absent from a package; the
# rest count, optional and build included, because each still has to resolve.
version_deps() {
  jq -r --arg v "$1" 'select(.vers == $v) | .deps[]
    | select(.kind == null or .kind == "normal" or .kind == "build")
    | [(.package // .name), .req] | @tsv' "$2"
}

# Print every internal requirement of this published version that cannot share
# a bucket with the one this tree declares; fail if there is one.
mismatches() {
  local vers=$1 file=$2 inner req declared inner_bucket tree_bucket bad=0
  while IFS=$'\t' read -r inner req; do
    declared=${tree_req[$inner]:-}
    # A crate this tree takes without a version is unpublishable today and has
    # no bucket to compare against; package-check holds that door.
    [ -n "$declared" ] || continue
    inner_bucket=$(bucket_of_req "$req") || continue
    tree_bucket=$(bucket_of_req "$declared") || continue
    if [ "$inner_bucket" != "$tree_bucket" ]; then
      printf '%s: published %s requires "%s" (%s), this tree requires "%s" (%s)\n' \
        "$inner" "$vers" "$req" "$inner_bucket" "$declared" "$tree_bucket"
      bad=1
    fi
  done < <(version_deps "$vers" "$file")
  return "$bad"
}

# --- Check each requirement's floor ---------------------------------------
checked=0
problems=()
while IFS= read -r record; do
  dep=${record%%$'\t'*}
  req=${record#*$'\t'}
  index_file "$dep" || continue
  file=$index_path
  mapfile -t candidates < <(versions_within "$file" "$req")
  if [ "${#candidates[@]}" -eq 0 ]; then
    # Either the requirement is a shape this script does not read, or a
    # release PR has raised it ahead of the publish. Nothing published falls
    # inside the range, so nothing can disagree with this tree.
    if ! req_range "$req" >/dev/null; then
      printf '::notice::skipping "%s" on %s: dependency-floors reads only ^, ~, = and bare version requirements, not this shape.\n' "$req" "$dep" >&2
    else
      printf '::notice::%s has no published version satisfying "%s" yet, so it has no stale floor (this tree holds %s).\n' "$dep" "$req" "${member[$dep]}" >&2
    fi
    continue
  fi
  checked=$((checked + 1))
  floor=${candidates[0]}
  detail=$(mismatches "$floor" "$file") && continue

  # The floor is stale. The fix is the lowest published version of the
  # dependent inside the range built on the same crates; failing that, the
  # dependent's own version, which nothing has published yet.
  fix=
  for candidate in "${candidates[@]}"; do
    # Output to /dev/null: this is a search, and its findings are reported
    # once from $detail above rather than once per candidate examined.
    if mismatches "$candidate" "$file" >/dev/null; then fix=$candidate; break; fi
  done
  # Inside the release PR the versions are already computed, so this is where
  # the requirement moves; ahead of it, release-plz reads "no change needed"
  # as "no dependent release" and suppresses the cascade (release-plz.toml).
  if [ -n "$fix" ]; then
    remedy="Raise the root [workspace.dependencies] requirement on $dep to version = \"$fix\", the lowest published version inside \"$req\" whose internal requirements all match this tree."
  else
    remedy="No published version inside \"$req\" matches, so raise it to version = \"${member[$dep]}\" and publish that first: it is the only one built on the same core."
  fi
  problems+=("$dep \"$req\" (used by: ${used_by[$record]% }): the lowest published version inside that range is $floor, built on a different cratefield-core:
${detail//$'\n'/$'\n    '}
  $remedy Do the edit in the release PR, not ahead of it: release-plz keys the dependent round on the rewrite, so a requirement raised before the release suppresses the cascade for everything behind it (release-plz.toml).")
done < <(printf '%s\n' "${!used_by[@]}" | sort)

if [ "${#problems[@]}" -gt 0 ]; then
  printf '::error::%s\n' "${problems[@]}" >&2
  die "${#problems[@]} internal requirement(s) admit a published floor built on a different cratefield-core, so a downstream resolve can pull in two copies of core (issue #712)."
fi

# A pass over nothing. The sibling script holds the same line for the same
# reason — a set that resolved to nothing is not a set that resolved — and
# the case is real: an index base, or a path rule, that answers 404 to
# everything skips every requirement and prints this as a clean run.
[ "$checked" -gt 0 ] || die "no internal requirement had a published version inside it, so this run checked nothing: every crate was either not published yet or had no published version inside the requirement this tree declares. A first publish still pending looks like this (docs/RELEASING.md, Owner setup) — run this again once it has happened. An index base answering 404 to everything looks identical, so check CRATES_INDEX_URL before believing it."

echo "dependency-floors: $checked internal requirement(s) of publishable crates, every published floor built on the same core this tree is"