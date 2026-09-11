# Error taxonomy

Every problem slug the harness can emit, generated from
`cratefield-core`'s registry by `cargo run -p cratefield-core --example
errors-doc` and checked in CI for drift. Responses are RFC 9457
`application/problem+json` with `type` =
`https://factory0.ventures/problems/<slug>` and `instance` = the
request id.

| Slug | Status | Title | Description |
|---|---|---|---|
| `admin-forbidden` | 403 | Admin token rejected | The presented admin token is wrong. |
| `admin-unauthorized` | 401 | Admin access unauthorized | Admin endpoints are disabled or the request has no bearer token. |
| `captcha-failed` | 400 | Captcha verification failed | The captcha token was missing or rejected; retry the challenge. |
| `internal` | 500 | Internal error | Unhandled error; no internals are exposed in the body. |
| `invalid-token` | 400 | Invalid or expired token | A signed link or token is malformed, tampered with, or expired. |
| `mail-not-configured` | 503 | Mail is not configured | No sending domain is verified; use the direct address shown by the form. |
| `not-found` | 404 | Not found | No route matched the request. |
| `not-production-ready` | 503 | Not ready for production traffic | This deployment declares production but cannot satisfy the abuse controls its routes declare. |
| `not-ready` | 503 | Service not ready | Readiness probe failed: the database is missing, erroring or too slow. |
| `rate-limited` | 429 | Rate limit exceeded | Too many requests from this IP or address; retry after the pause. |
| `request-too-large` | 413 | Request body too large | The request body exceeded the 64 KiB limit for /v1 endpoints. |
| `sidecar-contract-mismatch` | 503 | Sidecar contract mismatch | A sidecar answers a different HARNESS_API than this harness speaks. |
| `sidecar-unauthorized` | 401 | Unauthorized sidecar caller | A request to a sidecar-guarded route could not be established as coming from the trusted gateway. |
| `sidecar-unavailable` | 503 | Sidecar module unavailable | A sidecar-mounted module could not be reached; other modules are unaffected. |
| `tenant-degraded` | 503 | Tenant is degraded | The tenant's schema is behind or its database is unreachable; its neighbours are unaffected. |
| `unknown-product` | 400 | Unknown product | The named product is not on this waitlist. |
| `unknown-tenant` | 404 | Unknown tenant | The request's host resolves to no tenant in the registry. |
| `validation-failed` | 400 | Request validation failed | The request body or query did not deserialize into a valid request. |
