# cratefield-cli-acceptance

Acceptance tests for the `fz` CLI (`cratefield-cli`): a fixture venture
(`fixture/`, a standalone crate with two modules), then real `fz`
subprocess runs against it — `migrations collect` (file names +
`.harness-lock.json` pinning, content-hash edit detection), `doctor`
(portable-SQL, captcha-in-production, contract checks) and `modules`.

A separate workspace crate rather than dev-dependencies of
`cratefield-cli`, because `cargo publish` resolves dev-dependencies
against crates.io — a published `cratefield-cli` could never verify
against an unpublished fixture (issue #15). `publish = false`, no
library target, so unlike the published crates it carries no rustdoc
README include.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
