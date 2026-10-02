#!/usr/bin/env bash
# Refresh tests/fixtures/owlpost-send-email-request.schema.json from a local
# checkout of the Owlpost backend. The canonical schema lives in the private
# repository Owlpost-to/backend:crates/owlpost-core, which this repository
# cannot fetch, so the committed fixture is authored from the
# Resend-compatible shape Owlpost speaks. Run this when you do have a
# checkout to replace the fixture with the upstream file.
#
# Usage:
#   scripts/refresh-fixture.sh /path/to/Owlpost-to/backend
#   OWLPOST_BACKEND=/path/to/Owlpost-to/backend scripts/refresh-fixture.sh
#
# Environment:
#   OWLPOST_SCHEMA_SRC  Source file inside the checkout, relative to its root.
#                       Default: crates/owlpost-core/send-email-request.schema.json
#                       (falling back to the crate's request.schema.json).
#
# The copy is byte-for-byte; the recorded provenance is the source file's own.
# It refuses a file that is not valid JSON, so a wrong path cannot clobber the
# fixture.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
dest="$repo_root/crates/adapter-owlpost/tests/fixtures/owlpost-send-email-request.schema.json"

backend="${1:-${OWLPOST_BACKEND:-}}"
if [ -z "$backend" ] || [ ! -d "$backend" ]; then
  echo "usage: $0 <path-to-Owlpost-to/backend>" >&2
  echo "   or: OWLPOST_BACKEND=<path> $0" >&2
  exit 2
fi

src="${OWLPOST_SCHEMA_SRC:-}"
if [ -z "$src" ]; then
  for candidate in \
    "crates/owlpost-core/send-email-request.schema.json" \
    "crates/owlpost-core/request.schema.json"; do
    if [ -f "$backend/$candidate" ]; then
      src="$candidate"
      break
    fi
  done
fi
if [ -z "$src" ] || [ ! -f "$backend/$src" ]; then
  echo "no schema found under $backend" >&2
  echo "set OWLPOST_SCHEMA_SRC to the file path inside the checkout" >&2
  exit 1
fi

# Validate before replacing: a non-JSON file must not reach the fixture.
if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$backend/$src"; then
  echo "not valid JSON, refusing to overwrite the fixture: $backend/$src" >&2
  exit 1
fi

cp "$backend/$src" "$dest"
echo "wrote $dest from $backend/$src"

# Record the source commit, so provenance is auditable from the fixture alone.
if commit="$(git -C "$backend" rev-parse --short HEAD 2>/dev/null)"; then
  echo "source commit: $commit"
fi
