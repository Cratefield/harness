# Factory Zero harness — private modules

Private modules for the [Factory Zero harness](https://github.com/Factory-Zero/harness).
Same layout and tooling as the public repo. Crates are `fz-*` and are **never
published**; ventures consume them as pinned git dependencies (harness ADR 0005):

```toml
[dependencies]
fz-module-admin = { git = "ssh://git@github.com/Factory-Zero/harness-private", tag = "fz-module-admin-v0.1.0" }
```

Modules here obey the same `Module` trait as public ones and pass the same
`factory0-testing` conformance kit. The only differences are the prefix and
the distribution channel.

## Consuming from a venture repo

- Locally: your SSH key with read access to this repo.
- In GitHub Actions: a read-only deploy key for this repo stored as a secret in the venture repo, loaded with `webfactory/ssh-agent`, and `CARGO_NET_GIT_FETCH_WITH_CLI=true`.

## Layout (target)

```
crates/
  module-admin/     # candidate first module: cross-module ops endpoints
```
