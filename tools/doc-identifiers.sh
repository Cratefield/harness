#!/usr/bin/env bash
# Every snake_case identifier a document cites still exists in the tree.
#
# `tools/doc-commands.sh` keeps documented *commands* true by running them.
# This is the same idea for the names a document points at: a test it says
# pins a guarantee, a column it says is ordinary data, a function it says
# does the checking. Those rot silently — a rename leaves the document
# pointing at nothing, and a reader who follows the pointer cannot tell
# whether the guarantee is unpinned or merely renamed.
#
# It found two on the day it was written: `docs/TENANT-ONBOARDING.md`
# named `an_archived_tenant_cannot_be_resurrected_or_re_flown`, which had
# become `a_retired_...`, and `docs/CARD-DATA.md` listed a fourth Stripe
# identifier the guard test did not carry.
#
# Scope is deliberately narrow: backticked, lowercase, snake_case, at
# least three parts. That shape is a Rust or SQL name this repository owns
# rather than English prose, and it is what a stale pointer looks like.
#
# Crate READMEs are covered too — rustdoc includes them, so a stale
# pointer there ships in the published documentation. They were all clean
# when this was written (34 citations, none dangling), which is the
# cheapest possible moment to start checking them.
set -euo pipefail

cd "$(dirname "$0")/.."

# Names that are real and are not ours. Each needs a reason, so the list
# cannot become a place to silence a finding.
declare -A EXTERNAL=(
  [pg_stat_statements]="a PostgreSQL extension, named in TENANT-ROUTING.md as an operator's tool"
)

failures=()
while IFS= read -r doc; do
  # Listed but gone from disk: a deletion not yet staged. Nothing to check.
  [ -f "$doc" ] || continue
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    if [ -n "${EXTERNAL[$name]:-}" ]; then
      continue
    fi
    # Markdown is excluded from the search, and so is this script. Both
    # were self-satisfying: a crate README lives under `crates/`, so a
    # name it cited matched itself and that half of the check could never
    # fail; and `pg_stat_statements` was "found" in the allowlist entry
    # below, so the allowlist proved its own exemption unnecessary. A
    # pointer has to land on something that is not prose about the
    # pointer. Both were caught by breaking the check on purpose and
    # finding it still green.
    #
    # `--untracked` for the same reason the document list below takes
    # `--others`: a new doc citing a name from a new, not-yet-added source
    # file would otherwise be red locally and green once committed.
    if ! git grep -q --untracked -- "$name" -- crates tools ventures examples ':!*.md' ':!tools/doc-identifiers.sh' 2>/dev/null; then
      failures+=("$doc names \`$name\`, which is nowhere in the tree. A document that points at a name nothing defines cannot be followed: rename the pointer, or add the thing back.")
    fi
  done < <(grep -oE '`[a-z][a-z0-9]*(_[a-z0-9]+){2,}`' "$doc" | tr -d '`' | sort -u)
# Untracked (but not ignored) documents too. Tracked-only was a false
# green on exactly the doc being written: it is untracked until committed,
# so the check passed having read nothing of it (issue #445). `sort -u`
# because an unmerged path is listed once per stage.
done < <(git ls-files --cached --others --exclude-standard -- 'docs/*.md' 'docs/**/*.md' 'crates/*/README.md' 'README.md' | sort -u)

if [ "${#failures[@]}" -gt 0 ]; then
  printf '::error::%s\n' "${failures[@]}" >&2
  printf '\n%s\n' "doc-identifiers: ${#failures[@]} stale pointer(s)." >&2
  exit 1
fi

echo "doc-identifiers: every name the documents cite exists."
