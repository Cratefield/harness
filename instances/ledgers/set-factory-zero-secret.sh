#!/usr/bin/env bash
# Sets the Factory Zero client secret for the Ledgers auth Worker. The value is read from stdin and passed straight
# to `wrangler secret put`, so it never appears in argv, shell history or the process list. Nothing is written to
# disk and nothing is echoed.
#
#   printf '%s' "$FZ_CLIENT_SECRET" | bash set-factory-zero-secret.sh             # staging (default)
#   printf '%s' "$FZ_CLIENT_SECRET" | bash set-factory-zero-secret.sh production
#
# The secret name is AUTH_OIDC_FACTORY_ZERO_CLIENT_SECRET. The client id is a var in wrangler.toml, not a secret.
# Run it yourself, once per environment, after the client is registered on Factory Zero (docs/venture-linking.md).
set -euo pipefail

ENVIRONMENT="${1:-staging}"
case "$ENVIRONMENT" in
  staging) ENV_ARGS=() ;;
  production) ENV_ARGS=(--env production) ;;
  *) echo "usage: printf '%s' \"\$SECRET\" | bash $(basename "$0") [staging|production]" >&2; exit 2 ;;
esac

# A secret typed into a terminal is the wrong way in: refuse rather than read it from the keyboard.
if [ -t 0 ]; then
  echo "pipe the client secret on stdin; refusing to read it from a terminal" >&2
  exit 2
fi

cd "$(dirname "$0")"
exec bunx wrangler secret put AUTH_OIDC_FACTORY_ZERO_CLIENT_SECRET "${ENV_ARGS[@]}"
