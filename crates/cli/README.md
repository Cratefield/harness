# factory0-cli (`fz`)

The venture CLI: `fz migrations collect`, `fz doctor`, `fz modules`.

`fz` links against your venture's compiled-in harness, so it runs as a bin
target **inside the venture repo** — the pattern the venture template
ships:

```toml
# venture Cargo.toml
[[bin]]
name = "fz"
path = "src/fz_main.rs"

[dependencies]
factory0-cli = "0.1"
```

```rust
// venture src/fz_main.rs
fn main() { factory0_cli::main_for(my_venture::harness); }
```

Then:

```
cargo run --bin fz -- migrations collect
cargo run --bin fz -- doctor
cargo run --bin fz -- modules
```

## `fz migrations collect [--dialect sqlite] [--out migrations]`

Walks the harness's modules in config order and writes
`migrations/<GGGG>_<module>_<NNNN>_<name>.sql` — the format
`wrangler d1 migrations apply` executes in lexical (apply) order.
`migrations/.harness-lock.json` pins `<module>/<migration-id>` to the
global file name plus a sha256 of its content:

- locked entries are never renamed or renumbered;
- new migrations append with the next `GGGG`;
- exits non-zero when a locked file is missing or was edited after being
  applied (restore the file or add a new migration instead).

`--dialect postgres` arrives with `factory0-adapter-postgres` (phase 3).

## `fz doctor [--out migrations]`

Fails when:

- a module with `public_writes()` runs in a `production` venture without
  the Captcha port (section 11);
- any module migration is not collected yet, a locked file is missing or
  edited;
- a migration contains non-portable SQL: `AUTOINCREMENT`, `datetime(`,
  `SERIAL`, `NOW()`, `json_extract`, or backtick quoting.

## `fz modules`

Prints `name version /v1/<name> emits=[…] tables=[…]` per module.

## Applying migrations (wrangler)

Staging and production run the same commands from the venture repo:

```
# staging (first time / new migrations)
wrangler d1 migrations apply <database-name> --remote --env staging

# production
wrangler d1 migrations apply <database-name> --remote --env production
```

Locally: `wrangler d1 migrations apply <database-name> --local`.
