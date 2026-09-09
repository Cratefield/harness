#!/usr/bin/env bash
# Issue #34: the never-edit rule, enforced where it can still be fixed.
#
# A checksum mismatch at boot is the last line of defence and it fires in
# production. This is the first line: the pull request. It rejects an edit
# to a migration that has already been applied somewhere, a renamed or
# deleted one, and a sequence that skips or repeats a number.
#
# Usage: tools/migration-guard.sh <base-ref>
set -euo pipefail

BASE="${1:?usage: migration-guard.sh <base-ref>}"
failures=()

fail() { failures+=("$1"); }

# Every migration directory the repo ships: modules, ventures, examples.
mapfile -t dirs < <(git ls-files '*/migrations/*.sql' | xargs -r -n1 dirname | sort -u)

# --- 1. An applied migration is never edited, renamed or deleted --------
#
# `git diff --name-status` against the merge base: M, D and R on a file
# that already existed are all the same rule broken.
while IFS=$'\t' read -r status path rest; do
  [ -z "${status:-}" ] && continue
  case "$path" in */migrations/*.sql) ;; *) continue ;; esac
  case "$status" in
    M*)
      fail "$path was edited. Applied migrations are never edited: revert the change and write a new migration instead (docs/MODULE-AUTHORING.md, step 3)."
      ;;
    D*)
      fail "$path was deleted. A migration that has been applied cannot be withdrawn; write a new migration that reverses it."
      ;;
    R*)
      fail "$path was renamed to ${rest:-?}. A migration's filename is its identity in the tracking table; renaming it makes the applied row unmatchable."
      ;;
  esac
done < <(git diff --name-status --find-renames "$(git merge-base "$BASE" HEAD)"...HEAD -- '*/migrations/*.sql')

# --- 2. Sequences are contiguous; dialect overrides are not sequences ---
#
# A `migrations/postgres/` directory is deliberately sparse: ADR 0004 says
# the Postgres set differs from the SQLite one only where the SQL truly
# differs, so it holds overrides and the module's array reuses the SQLite
# file for every other id. Requiring it to be contiguous would be
# requiring a copy of every file. What it must satisfy instead is that
# each override answers to a real migration — an override whose id or
# name has no SQLite counterpart is a file nothing loads.
for dir in "${dirs[@]}"; do
  mapfile -t names < <(git ls-files "$dir/*.sql" | xargs -r -n1 basename | sort)
  [ "${#names[@]}" -eq 0 ] && continue

  case "$dir" in
    */migrations/postgres)
      canonical="${dir%/postgres}/sqlite"
      for name in "${names[@]}"; do
        if ! git ls-files --error-unmatch "$canonical/$name" >/dev/null 2>&1; then
          fail "$dir/$name overrides a migration that does not exist: there is no $canonical/$name. A dialect override answers to a migration id and name in the canonical set (ADR 0004)."
        fi
      done
      continue
      ;;
  esac

  expected=1
  for name in "${names[@]}"; do
    seq="${name%%_*}"
    case "$seq" in [0-9][0-9][0-9][0-9]) ;; *) continue ;; esac
    n=$((10#$seq))
    if [ "$n" -lt "$expected" ]; then
      fail "$dir has two migrations numbered $seq. A sequence number is an identity, not a label."
    elif [ "$n" -gt "$expected" ]; then
      fail "$dir jumps from $(printf '%04d' $((expected - 1))) to $seq. Migrations are contiguous from 0001 so a missing one is never mistaken for an unapplied one."
    fi
    expected=$((n + 1))
  done
done

# --- 3. Card data never enters a schema (#44) --------------------------
#
# The non-goal is enforced where the column would be created, not after.
card_pattern='\b(pan|cardholder|card_number|cardnumber|cvv|cvc|card_cvv|expiry_month|expiry_year|track2)\b'
while IFS= read -r path; do
  if hits=$(grep -inE "$card_pattern" "$path" 2>/dev/null); then
    fail "$path names card data: ${hits%%$'\n'*}. Storing it is a non-goal (#44); the PSP holds the card and the harness holds its token."
  fi
done < <(git ls-files '*/migrations/*.sql')

# --- 4. No connection string is ever checked in ------------------------
while IFS= read -r path; do
  if hits=$(grep -inE '(postgres|postgresql|mysql)://[^[:space:]"'"'"']*:[^[:space:]"'"'"']*@' "$path" 2>/dev/null); then
    fail "$path contains a connection string with credentials: line ${hits%%:*}. A DSN is resolved from the secrets store, never written into SQL."
  fi
done < <(git ls-files '*/migrations/*.sql')

if [ "${#failures[@]}" -gt 0 ]; then
  printf '::error::%s\n' "${failures[@]}" >&2
  printf '\n%s\n' "migration guard: ${#failures[@]} problem(s)." >&2
  exit 1
fi

echo "migration guard: ${#dirs[@]} migration directories, no problems."
