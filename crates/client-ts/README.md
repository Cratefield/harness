# cratefield-client-ts

The **TypeScript client generator** (issue #155): a `/__surface` contract
in, the files of a typed `@cratefield/client` package out.

```text
GET /__surface  ──►  cratefield_client_ts::generate  ──►  package.json
                                                          tsconfig.json
                                                          README.md
                                                          src/index.ts
                                                          src/runtime.ts
                                                          src/types.ts
```

A venture's declared tables are already a contract — the Tables module
publishes, per table, exactly the routes it serves, the audience each one
is for, and the table's own JSON Schema on every write. This crate turns
that document into the TypeScript a customer imports, so the types always
match the venture they were generated from: a table the contract publishes
no write for gets no write method, and a table whose key is more than one
column gets no single-row call at all. Compile-time absence is the point.

## Shape

The public API is one function and the result around it, mirroring
`cratefield_manifest::generate`:

- `generate(&SurfaceDocument)` — the pure step. No disk, no clock, no
  network; the caller writes the files.
- `GeneratedPackage` — the venture, the package name, `files` in a stable
  order, and a `composition_hash`: sha256 over each file's path and
  contents, the same construction the manifest generator uses, so a
  pipeline can pin and re-verify the artifact.
- `GenerateError` — a contract this generator cannot honour: a document
  that speaks a different `surface_api`, no `tables` module in it, or a
  Tables action whose name, method or path does not match the verb shape
  the module publishes.

Determinism is the contract with the pipeline: the same document always
generates byte-identical files, so the hash is stable and a republish is
a no-op unless the venture changed.

## What the generated client gives the caller

Per table, an accessor on the client whose methods are exactly the
actions the contract publishes — `list`, and wherever the contract has
them, `get`, `create`, `replace`, `delete`. Typed rows from the
contract's JSON Schema; an equality-only query builder over the page
(`where` / `sort` / `after` / `page`) with an async iterator that walks
`next` to the end; a `PublicClient` that only reaches tables the contract
marks `public` and an `AuthenticatedClient` that adds the rest; and
problem+json answers surfaced as one error class carrying the stable
slug. The only runtime dependency is `fetch`, and even that can be
injected.

## The known gap

A `public-read` table publishes `list-*` and `read-*` and **no** write,
and the write is where a row schema travels. So a read-only table's
surface entry carries no schema at all, and there is nothing in the
contract to type its rows from. The generator does not fail over this:
the table is generated with a row type of `Record<string, unknown>`, a
TypeScript doc comment saying exactly why, and no typed filters or sort.
Widen it with the venture's own knowledge of the table instead of
guessing here. The same fallback applies to any table whose contract
entry carries no schema, so generation is total.

## Compilable by construction

The generated package is checked by a test in this crate: the fixture is
written to a scratch directory and type-checked with `tsc --strict
--noEmit`. The test skips itself, with the reason printed, on a machine
with no TypeScript toolchain (`tsc`, `bunx` or `npx`), so CI without
Node still passes.

```ts
// what generation is for — the customer's side:
const client = createClient({ baseUrl: venture.url, token });
const page = await client.note.where({ done: false }).sort("-created").page();
```

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
