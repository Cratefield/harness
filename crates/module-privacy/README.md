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
  subject. Admin-guarded.

Erasure is not here yet: it is the destructive half and wants its own review.
