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

A `text` value may not hold U+0000: SQLite stores it and PostgreSQL
refuses the statement, so a declaration that allowed it would behave
differently on the two engines. The same goes for a control character in
a declared `default` or an `enum` member, which reach the schema file
itself.

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

`subject` names the column holding whose each row is, and it is `text`
or `uuid`: what goes in it is a caller's id out of a verified credential,
and a column of another kind cannot hold one.

`description` is published verbatim to the person asking, so write it for
them. It is plain text: it also becomes a string literal in generated
source, and a carriage return or a codepoint that changes reading
direction is refused here rather than as a compiler error in a file you
were told not to edit. Newlines and tabs are fine. `reason` is what makes "holds nothing" a decision rather than a
silence.

## Saying who may reach each table

Required, with no default, one of four:

| level | reads | writes |
|---|---|---|
| `public-read` | anybody | nobody |
| `owner` | a signed-in caller, their own rows | the same |
| `tenant-members` | any signed-in caller, every row; with a tenant registry, nobody | the same |
| `admin` | an admin token | the same |

```json
{ "table_access": { "note": "owner", "tier": "public-read" } }
```

`tenant-members` admits any caller the deployment's verifier accepts. It
does not check membership, because the membership fact still does not
exist: nothing in a verified credential says which tenant a caller
belongs to. On a venture `fz build` generates — a deployment with no
tenant registry — that is the same set and the level serves as it always
did: there is one tenant, so every verified caller is a member of it
because there is no other to belong to.

On a deployment with a registry the tenant comes from the `Host` header
and the verifier does not, so the two sets come apart, and the level is
refused at every host — the caller's own included — with a `500`
(`no-membership-fact`). It is a `500` and not a `403` because nothing
the caller did is wrong and no credential of theirs fixes it. That is
the level being switched off where it cannot be honoured, not a
membership check: the fact that would make one, a tenant claim on the
subject that the verifier fills in, is issue #385, and #385 is still
open.

The published surface cannot reflect this: `/__surface` lists a
`tenant-members` table as needing a signed-in caller whatever the
deployment's tenancy, because the surface is built from the manifest
alone and the manifest does not know the tenancy either.

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
| `GET /{table}/__by?<column>=<value>&…` | one row, its key named in the query |
| `PUT /{table}/__by?…` | `200` and the row it replaced |
| `DELETE /{table}/__by?…` | `204` |
| `POST /__batch` | several reads in one round trip |

`/{table}/{key}` addresses a row when the primary key is one column. A
composite key does not fit in one path segment, and that route refuses
it (`400 composite-key`) rather than join its values with a separator
that could occur inside one of the values — and names the route that
does answer: `/{table}/__by?<column>=<value>&…`, the key written as the
query, one parameter per primary-key column (ADR 0018). A membership
table keyed by `tenant` and `member` reads one row at
`/v1/tables/membership/__by?tenant=acme&member=ada`. The columns are
named, not positional, so reordering the declaration cannot quietly
change what an existing URL means, and the three methods answer exactly
as the path routes do: a read returns the row, a replace takes the row
and answers the replaced one, a remove answers `204` and nothing.

The query names primary-key columns and nothing else. Naming some but
not all is `400 partial-key` — a row is addressed by its whole key, not
by every row sharing a prefix. Naming a column outside the key is `400
not-a-key-column`; to narrow by another column, read the page and
filter it. Values are parsed exactly as a path segment's is, so a
`real`, `boolean` or `json` key column stays refused (`400 bad-key`).

`after` and `sort` are the harness's parameters on this sub-path and
can never name a key column, so a table whose primary key uses one of
those names has no address here. The page, the create and `__batch`
still serve it.

`__by` answers for **every** declared table, not only composite-key
ones, because a static segment beats `{key}` in the router: on a
single-column-key table a row whose key value is literally `__by` is
unreachable by path, and `/{table}/__by?id=__by` is that row's address.
`/__surface` publishes all five actions either way and says where the
key goes — an `__by` path carries no placeholder, so a read or a delete
publishes the key columns as its input schema, and a replace publishes
the row body with the key columns beside it under `x-cf-query`.

A row that is not the caller's is **not found**, never forbidden: a `403`
is an answer about a row they were never in a position to learn exists.

`next` is the cursor and `?after=` takes it back exactly as it was given.
Every other query parameter is an equality filter on a declared column;
one that names a column the table does not have is a `400`, not a
parameter ignored. A batch read carries its filters as JSON rather
than text, so it is the only one that can ask for a column that is
**unset** — `"where": {"body": null}` finds those rows rather than none. A
`json` column cannot be filtered on at all — its stored text depends on
the order its keys were written in — though asking whether one is unset
still works.

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
