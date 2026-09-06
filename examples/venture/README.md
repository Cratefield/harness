# venture (example)

The smallest complete Factory Zero venture: `factory0-core` +
`factory0-runtime-cloudflare`, three modules (`sample` row round-trip,
`email-signup`, `waitlist`), one Worker, one local D1.

CI builds it to wasm with `worker-build --release` so a native-only
dependency can never slip into a module, then boots it under
`wrangler dev --local` and curls `/__health`, `/__ready` and the sample
round-trip.

```text
bunx wrangler d1 migrations apply venture-example --local
printf 'HARNESS_SECRET=%s\n' "$(openssl rand -hex 32)" > .dev.vars
bunx wrangler dev --local --port 8792
curl -fsS http://127.0.0.1:8792/__health
curl -fsS http://127.0.0.1:8792/__ready
```

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full walkthrough and
[docs/VENTURE-GUIDE.md](../../docs/VENTURE-GUIDE.md) for the template-to-
production path this example mirrors. The guide-built module
[`factory0-module-hello`](../module-hello/) is its documentation-focused
sibling.
