#!/usr/bin/env bash
# Smoke test for the deployed control plane: liveness, D1 reachability and
# the console's own login page must all answer 200 over TLS.
#
#   ./smoke.sh https://console.cratefield.com
#
# `/v1/console/login` is the check that matters most: in production the
# harness answers every `/v1` route `not-production-ready` (503) when a
# readiness control is missing (a rate limiter that did not resolve, a
# signer with no HARNESS_SECRET), while `/__health` stays 200 regardless.
#
# The first deploy of a Custom Domain takes a while to resolve and to get
# its certificate, so each path is retried for up to ATTEMPTS x DELAY
# seconds before the smoke fails.
set -euo pipefail

BASE="${1:?usage: smoke.sh <base-url>}"
BASE="${BASE%/}"
ATTEMPTS="${SMOKE_ATTEMPTS:-30}"
DELAY="${SMOKE_DELAY:-10}"

paths=(
  /__health
  /__ready
  /v1/console/login
)

for path in "${paths[@]}"; do
  code=""
  for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' "${BASE}${path}" || true)"
    if [ "$code" = "200" ]; then
      break
    fi
    if [ "$attempt" -lt "$ATTEMPTS" ]; then
      echo "wait ${path} -> ${code:-no answer} (attempt ${attempt}/${ATTEMPTS})"
      sleep "$DELAY"
    fi
  done
  if [ "$code" != "200" ]; then
    echo "FAIL ${path} -> ${code:-no answer}"
    # The body names the reason (problem+json); it carries no secrets.
    curl -sS "${BASE}${path}" | head -c 2000 || true
    echo
    exit 1
  fi
  echo "ok   ${path}"
done

echo "smoke passed against ${BASE}"
