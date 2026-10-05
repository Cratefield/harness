#!/usr/bin/env bash
# Smoke test for one deployed auth instance (auth#41, issue #777): the health
# check and the OIDC discovery documents must all answer 200 over TLS, and
# the discovery document must name this instance as its issuer.
#
#   ./smoke.sh https://auth.<app-domain>
set -euo pipefail

BASE="${1:?usage: smoke.sh <base-url>}"
BASE="${BASE%/}"

paths=(
  /__health
  /.well-known/openid-configuration
  /.well-known/jwks.json
)

for path in "${paths[@]}"; do
  code="$(curl -fsS -o /dev/null -w '%{http_code}' "${BASE}${path}" || true)"
  if [ "$code" != "200" ]; then
    echo "FAIL ${path} -> ${code}"
    exit 1
  fi
  echo "ok   ${path}"
done

# A token minted by this instance must name it, not some other instance.
issuer="$(curl -fsS "${BASE}/.well-known/openid-configuration" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("issuer",""))')"
if [ "${issuer%/}" != "$BASE" ]; then
  echo "FAIL issuer is ${issuer:-<missing>}, expected ${BASE}"
  exit 1
fi
echo "ok   issuer ${issuer}"

echo "smoke passed against ${BASE}"
