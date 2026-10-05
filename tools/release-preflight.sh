#!/usr/bin/env bash
# Issue #719: the crates.io trusted-publisher gate the release pipeline
# cannot give itself.
#
# A trusted publisher can only be configured *after* a crate exists on
# crates.io, so the very first publish of every crate is manual
# (docs/RELEASING.md, Owner setup). Release-plz does not know that: with
# CRATES_IO_READY set it walks the publish order and uploads, and a crate
# whose first version has never been published fails there — after the
# crates before it are already live, so the round is left half-published
# and the next run resumes into the same wall.
#
# So this runs immediately before the release step, on dry runs too: it is
# the run where the owner checks what a real release would do, and the
# cheapest possible answer to "would this round half-publish?" is a list
# of names rather than a failure halfway through the sequence.
#
# Usage: tools/release-preflight.sh
set -euo pipefail

cd "$(dirname "$0")/.."

die() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

for tool in cargo jq curl; do
  command -v "$tool" >/dev/null || die "release-preflight needs $tool, which is not installed or not on PATH. GitHub runners ship it; elsewhere, install it first."
done

# `publish: null` in cargo metadata is a publishable package and
# `publish: []` is one marked `publish = false`, so null is the
# publishable filter. The `[[package]]` blocks release-plz.toml marks
# `publish = false` or `release = false` are subtracted the way
# tools/package-check.sh subtracts them: release-plz holds those back
# even when the crate's own manifest does not, so their absence from
# crates.io is not a release that would half-publish.
metadata=$(cargo metadata --no-deps --format-version 1) || \
  die "cargo metadata failed (its error is above): the workspace manifest itself is broken, which is a different problem than the registry."
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
mapfile -t crates < <(printf '%s\n' "${!publishable[@]}" | sort)
[ "${#crates[@]}" -gt 0 ] || die "the publishable set is empty; cargo metadata or release-plz.toml parsing is broken."
echo "release-preflight: ${#crates[@]} crate(s) a release run would publish"

# Existence is checked against the sparse index, the thing cargo itself
# resolves against, not the crates.io JSON API, which carries a
# user-agent and rate-limit policy the index does not. The path
# mirroring is cargo's own rule: 1-char names under 1/, 2-char under 2/,
# 3-char under 3/<first>/, everything else under <first two>/<chars
# 3-4>/.
missing=()
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
  # then be reported as a crate that needs its first publish — advice
  # that sends the owner to crates.io to do work the registry had
  # already finished. `|| true` only keeps `set -e` from killing the
  # script on the capture itself; the branch below is what decides.
  # A 000 (or empty) status means curl never got a response at all.
  status=$(curl -s -o /dev/null -w '%{http_code}' --retry 2 --retry-connrefused -m 30 "https://index.crates.io/$path") || true
  case "$status" in
    200) ;;
    404) missing+=("$name") ;;
    *)
      die "could not reach the sparse index to check $name (HTTP status ${status:-none}, after --retry re-asked the transient statuses). This is deliberately fatal rather than counted as a first publish still pending: nothing about the registry was learned, and reporting a crate as unpublished on the strength of an unreachable registry would send the owner to publish work that may already be done. Run again once the registry answers."
      ;;
  esac
done

if [ "${#missing[@]}" -gt 0 ]; then
  for name in "${missing[@]}"; do
    printf '::error::%s is not on crates.io, so its trusted publisher cannot be configured yet. Publish it once by hand with the scoped token, then enable its trusted publisher (docs/RELEASING.md, Owner setup, steps 2 and 3). Until then a release run cannot publish it over OIDC.\n' "$name" >&2
  done
  die "${#missing[@]} of the ${#crates[@]} crate(s) a release run would publish have never been published: ${missing[*]}. Trusted publishing cannot create a crate, so release-plz would upload the crates before these and then stop here, leaving the round half-published. First-publish these by hand (docs/RELEASING.md, Owner setup, steps 2 and 3), or leave CRATES_IO_READY unset so the release step stays off until they are done."
fi

echo "release-preflight: all ${#crates[@]} crate(s) exist on crates.io, so every one of them can be published over OIDC."