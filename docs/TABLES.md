# Declared tables

A venture declares its own tables in its manifest and gets a working data
API — migrations, CRUD routes, a published contract — without writing a
module crate (issue #153).

This is the author-facing guide. The crate docs
(`crates/tables`, `crates/tables-api`) carry the reasoning behind each
decision; this carries the shape.

## The rule that bounds a declaration

**Anything that has to read another row or another request is a function,
not a field.**

A declaration covers required, length, range, format, enum, uniqueness,
foreign keys, defaults and indexes. Overlap checks, state machines,
totals that depend on other rows, anything that calls out — those belong
in a module or a sidecar.

The rule exists so the manifest stays a description of shape. A manifest
that can express "this booking must not overlap another" is a manifest
that has become a programming language with no type checker, no tests and
no debugger, and every venture that leans on it is stuck there.

The same instinct bounds what a *caller* may ask of a declared table:
filters are equality on a declared column, and access is four words. Both
stay vocabularies.

## Declaring a table

```json
{
  "tables": {
    "note": {
      "primary_key": "id",
      "fields": [
        { "name": "id", "kind": "uuid", "required": true },
        { "name": "author", "kind": "text", "required": true },
        { "name": "body", "kind": "text", "max_len": 400 }
      ]
    }
  }
}
```

`kind` is one of `text`, `integer`, `real`, `boolean`, `timestamp`,
`uuid`, `json`, `enum`. A primary key may be one column or several.

The kinds are a small purpose-built set rather than JSON Schema, because
JSON Schema is sprawling and says nothing about how a field becomes a
SQLite or Postgres column. JSON Schema is emitted as a derived view for
anyone who wants one, and it is what `/__surface` publishes as a write's
body.

## Saying what each table holds

Required, with no default:

```json
{
  "table_privacy": {
    "note": {
      "holds": "personal",
      "subject": "author",
      "kind": "content",
      "disposition": "erase",
      "description": "The notes you wrote, and who wrote them."
    },
    "tier": { "holds": "nothing", "reason": "Plan tiers; nobody is in them." }
  }
}
```

Both available defaults are wrong. *Nothing personal unless you say
otherwise* puts a venture's tables outside `fz data export`, outside
subject access and outside erasure, silently. *Personal unless you say
otherwise* deletes a venture's reference data the first time somebody
asks for an erasure.

`description` is published verbatim to the person asking, so write it for
them. `reason` is what makes "holds nothing" a decision rather than a
silence.

## Saying who may reach each table

Required, with no default, one of four:

| level | reads | writes |
|---|---|---|
| `public-read` | anybody | nobody |
| `owner` | a signed-in caller, their own rows | the same |
| `tenant-members` | any signed-in caller, every row | the same |
| `admin` | an admin token | the same |

```json
{ "table_access": { "note": "owner", "tier": "public-read" } }
```

`tenant-members` admits any caller the deployment's verifier accepts. It
does not check membership, because the harness has no membership fact:
nothing in a verified credential says which tenant a caller belongs to.
On a venture `fz build` generates that is the same set — there is one
tenant — and issue #385 is where it stops being one.

`owner` matches a caller against the column the table's privacy block
names as its subject, so declaring it on a table that holds nothing
personal is a manifest error — there is no column to match against.

It stays a vocabulary. A policy language in a manifest is a second
program deciding who sees what, with nothing to check it; four words the
harness evaluates are four things a reviewer can read.

## What gets served

Under the generated module's mount — `/v1/tables` for a venture that
declares them:

| route | answers |
|---|---|
| `GET /{table}?after=&sort=&<column>=` | a page, and `next` when there is another |
| `POST /{table}` | `201` and the row it created |
| `GET /{table}/{key}` | one row |
| `PUT /{table}/{key}` | `200` and the row it replaced |
| `DELETE /{table}/{key}` | `204` |
| `POST /__batch` | several reads in one round trip |

The three routes naming one row need a primary key of one column. A key
of several is refused rather than joined with a separator that could
occur inside one of the values, so a table declaring `primary_key =
["tenant", "member"]` is paged and written and never addressed one row at
a time — and `/__surface` publishes only the two routes it has. Issue
#387 is whether that stays true.

A row that is not the caller's is **not found**, never forbidden: a `403`
is an answer about a row they were never in a position to learn exists.

`next` is the cursor and `?after=` takes it back exactly as it was given.
Every other query parameter is an equality filter on a declared column;
one that names a column the table does not have is a `400`, not a
parameter ignored. A batch read carries its filters as JSON rather
than text, so it is the only one that can ask for a column that is
**unset** — `"where": {"body": null}` finds those rows rather than none.

## What a venture needs wired

A venture that declares any table which is not `public-read` needs an
auth service: `AUTH_ISSUER` and `AUTH_CLIENT_ID`. `fz build` wires the
runtime to read them, and `fz doctor` reports a production venture that
cannot identify a caller.

With them unset the deployment still starts and still serves its public
tables; every route that needs a caller answers `503`, and the boot log
names what is missing.

## Changing a declaration

Both commands run **inside the venture**, using the `fz` binary `fz build`
generated there: they read the compiled-in harness to know what the
venture actually mounts. From anywhere else they refuse and say so.

```
fz tables diff --from main.json
```

`--to` defaults to `venture.json`, so the common case names only the
manifest you are comparing against.

It reports what the edit costs — `expand`, `contract` or `rewrite`, the
vocabulary of `docs/ROLLBACK.md` §5 — **and** what it changes about who
may reach the tables. Flipping one table from `owner` to `public-read`
changes no column, so a diff that compared schemas alone would call it no
change.

```
fz tables drift --dialect postgres --url <connection string>
```

Reports where a live database differs from the declaration. Read-only:
what a drift costs is the author's decision, and three of the four
answers are not "apply this".

## What is not built yet

- No generated TypeScript client (#155), so no Zod half of the
  conformance corpus.
- A batch runs its reads in sequence, not in parallel: they share the
  request's one database handle. What it saves is the round trips.
- Sorting is one column. A second is a tiebreaker and the primary key is
  already that.
