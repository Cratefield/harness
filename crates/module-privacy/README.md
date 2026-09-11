# cratefield-module-privacy

Subject access over whatever a venture composed.

The module knows no venture's schema. Every table it reads is one another
module declared through `Module::personal_data`, composed at build into a
catalog. Compose it and a deployment can answer "what do you hold about me"
with no per-venture wiring.

- `GET /v1/privacy/manifest` — what this deployment holds, per table: the kind,
  what erasure would do, and the sentence the owning module wrote.
  Unauthenticated: it describes the deployment, not a person.
- `GET /v1/privacy/export?subject=<id>` — every row every module holds for one
  subject. Admin-guarded. A column the owning module declared as `redacted` is
  named and printed as `[redacted]` rather than copied: a push token or a Web
  Push endpoint is a bearer capability, and an export is a file somebody
  forwards.
- `POST /v1/privacy/erase` — what erasure would do, per table, with row counts
  and a short-lived signed token. Writes nothing.
- `POST /v1/privacy/erase/confirm` — carries it out, in one batch, and counts
  the rows again afterwards rather than trusting the statements. The subject
  comes from the token, never from the body.

What it can reach is exactly what the composed modules declared. A module that
owns a table and declares nothing about it is outside all four routes, which is
why `cratefield_testing::conformance` fails one that does (issue #244).
