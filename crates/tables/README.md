<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-tables"><img src="https://img.shields.io/crates/v/cratefield-tables.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-tables on crates.io"></a>
  <a href="https://docs.rs/cratefield-tables"><img src="https://img.shields.io/docsrs/cratefield-tables?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-tables documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-tables

The schema a venture declares in its manifest. One declaration, several
artifacts: the SQLite and Postgres DDL, the row validator, and a JSON
Schema view for anyone who wants one.

Pure logic. No I/O, no database driver, no clock and no randomness, so it
builds for `wasm32-unknown-unknown` alongside `cratefield-core`.

## The schema type

```rust
use cratefield_tables::{FieldDef, FieldKind, Schema, TableDef, TextFormat};

let schema = Schema::new(vec![TableDef::new(
    "subscriber",
    "id",
    vec![
        FieldDef::new("id", FieldKind::Uuid).required(),
        FieldDef::new(
            "email",
            FieldKind::Text { min_len: Some(3), max_len: Some(254), format: Some(TextFormat::Email) },
        )
        .required()
        .unique(),
        FieldDef::new("signed_up_at", FieldKind::Timestamp).required().indexed(),
    ],
)]);

schema.validate().expect("the declaration itself is valid");
```

## Rules the declaration must satisfy

`Schema::validate` reports every violation together, the way
`cratefield_core::Venture` does:

- identifiers match `[a-z][a-z0-9_]*`, hold no double or trailing
  underscore, and are at most 63 characters, which is what Postgres
  accepts without truncating;
- a name is not a reserved SQL word, does not start with a prefix the
  harness keeps (`harness_`, `sqlite_`, `pg_`, `cf_`), and is not shaped
  like card data;
- no table name repeats, and no field name repeats inside a table;
- the primary key is non-empty and names declared fields;
- a foreign key names a declared field and points at a declared table
  whose primary key is a single column of the same kind;
- an enum declares at least one value, with no duplicates;
- bounds are the right way round, and a default is a value its own field
  would accept.

Identifiers are rejected rather than quoted. That is deliberate: it is
what lets the generated DDL leave every identifier unquoted, the way the
hand-written module migrations do.
