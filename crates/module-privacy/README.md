<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-module-privacy.png" alt="cratefield-module-privacy — Answer the request." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-module-privacy"><img src="https://img.shields.io/crates/v/cratefield-module-privacy.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-module-privacy on crates.io"></a>
  <a href="https://docs.rs/cratefield-module-privacy"><img src="https://img.shields.io/docsrs/cratefield-module-privacy?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-module-privacy documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-module-privacy

Subject access and erasure over whatever a venture composed.

The module knows no venture's schema. Every table it reads is one another
module declared through `Module::personal_data`, composed at build into a
catalog. Compose it and a deployment can answer "what do you hold about me"
— and erase it — with no per-venture wiring.

An app's own Postgres or CRM is outside that catalog, so the routes also
reach **external providers**: HTTP endpoints the venture registers with
`Privacy::new().provider(…)` and that hold personal data the harness never
sees. The protocol, a TypeScript reference provider and the error kinds are
in [docs/PRIVACY.md](../../docs/PRIVACY.md#external-providers).

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

What it can reach locally is exactly what the composed modules declared — plus
any external providers registered on it. A module that owns a table and
declares nothing about it is outside the routes, which is why
`cratefield_testing::conformance` fails one that does (issue #244).

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
