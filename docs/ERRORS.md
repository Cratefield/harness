# Error taxonomy

Every problem slug the harness can emit, generated from
`factory0-core`'s registry by `cargo run -p factory0-core --example
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
| `not-ready` | 503 | Service not ready | Readiness probe failed: the database is missing, erroring or too slow. |
| `rate-limited` | 429 | Rate limit exceeded | Too many requests from this IP or address; retry after the pause. |
| `request-too-large` | 413 | Request body too large | The request body exceeded the 64 KiB limit for /v1 endpoints. |
| `unknown-product` | 400 | Unknown product | The named product is not on this waitlist. |
| `validation-failed` | 400 | Request validation failed | The request body or query did not deserialize into a valid request. |
