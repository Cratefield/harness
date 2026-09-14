# cratefield-tables-api

The HTTP API over the tables a venture declares in its manifest's
`[tables]` section (issue #153), with the access level each one declares.

**Not a module crate**, which is why it is not named like one. A
`crates/module-*` crate provides a `Module` and the conformance kit runs
against every one of them. This crate provides what a venture's
*generated* tables module calls — that module has to be generated source,
because `personal_data()` is `&'static` all the way down and cannot be
assembled from a manifest read at runtime.

## What is here today

The **access decision**: given a declared table, the caller the `Auth`
port identified, and the outcome of the admin check, which rows this
request reaches.

```rust
match may_read(&api, &caller, admin)? {
    Reach::Everything => /* the whole table */,
    Reach::OwnedBy { column, subject } => /* rows where column = subject */,
}
```

It is a function of values with no HTTP in it, which is deliberate: it is
the part that decides who sees whose rows, so every case is a test that
reads as a sentence rather than as a request.

## Reading

`page` and `one` apply that decision against a database. Both carry the
scope into the `WHERE` rather than filtering rows already fetched: a
filter applied afterwards turns a `LIMIT 50` into a page of however many
survived, and the shortfall is a count of the rows the caller was not
allowed to see.

They take a `&dyn Database`, and the routes hand them a `TenantConn` —
never `ctx.ports.db`, which is the same handle for every request whoever
asked. Taking the trait is what lets them be exercised against a real
database without an HTTP stack; `TenantConn` has no constructor, which is
the point of it.

| answer | when |
|---|---|
| `404 no-such-table` | the venture declares no table by that name |
| `404 no-such-row` | there is no such row **or** it is not the caller's |
| `401 unauthenticated` | no credential where one is needed, or one that did not verify |
| `503 verifier-unavailable` | a credential was presented and could not be checked |
| `500 table-misdeclared` | `owner` with no subject column to match against |

The two 404s are the same answer on purpose.

## The routes

| route | answers |
|---|---|
| `GET /{table}?after=&<column>=` | a page of rows, and `next` when there is another |
| `POST /{table}` | `201` and the row it created |
| `GET /{table}/{key}` | one row by its primary key |
| `PUT /{table}/{key}` | `200` and the row it replaced |
| `DELETE /{table}/{key}` | `204`, and nothing |

These are the five the surface publishes, and
`every_published_action_is_a_route_that_exists` is what keeps the two
lists the same. A published action whose route does not exist is worse
than an unpublished one: a generated UI renders the form and the
submission 405s.

A create answers `201` rather than `200`, because a create that answers
`200` is indistinguishable from an update to a client watching status
codes. A delete answers `204` with no body: there is nothing left to
describe, and inventing one (`"deleted": true`) is a second thing to keep
true.

Mounted under the generated module's name, so a venture's `note` table is
at `/v1/tables/note`.

This is the layer that insists on a `TenantConn`. `page` and `one` take
the trait so they can be exercised without an HTTP stack; the extractor
can only hand back the handle the resolution layer resolved for *this*
request's tenant.

A key in a path is one segment, so a table whose primary key is more than
one column is refused (`400 composite-key`) rather than addressed through
an invented separator — which would make a key containing that separator
unaddressable, silently, and only for the rows that contain it. A `real`,
`boolean` or `json` key is refused too: a float compared with `=` is a key
that sometimes matches nothing, for reasons the caller cannot see.

## Paging

`next` is the cursor, and `?after=` takes it back **exactly as it was
given** — the same JSON, percent-encoded. One shape, because two would
mean every client carries the translation between them, and the only
place that knowledge exists is here.

It is not parsed by `key_from_path`. That exists for a *path segment*,
which can carry one value, so it refuses a composite key — and refusing
there made a composite-key table unpageable past its first page over
HTTP, while `select_page` could express the query perfectly well.

A cursor that is not JSON, is not an object, omits a key column, or names
one with a value that is not its kind, is a `400 bad-cursor` that says
which.

## Several reads in one request

`POST /{mount}/__batch` with `{"reads":[{"table":"note","where":{...},"after":...}]}`
answers them in the order they were asked, at most 20 per batch.

What it buys is **one round trip**. Not parallelism: the reads run in
sequence against the request's one database handle, because that is what
a handle is. Claiming otherwise would have a caller sizing their batches
by the wrong number.

**A batch cannot ask for what the caller could not ask alone.** Each read
is decided on its own, against the same access level it would face
singly.

**One refused read refuses the whole batch**, naming which. A `200`
carrying a refusal per result is a success that is not one, and every
client would have to remember to look inside it.

`__batch` can never collide with a declared table: a table name starts
with a lowercase letter and may not contain `__`. The route is registered
first anyway — "cannot collide" is a fact about a validator somewhere
else — and a test asserts the name is not a legal identifier.

## Ordering a page

`?sort=column` or `?sort=-column`, one column. A second is a tiebreaker
and the primary key is already that — and every column a page is ordered
by has to appear in the cursor, so the vocabulary that stays small is the
one whose cursor stays readable.

The key always follows the sort column in the same direction, so two rows
with the same value cannot land in an order that changes between pages.
The cursor names both, and a cursor short of either is `400 bad-cursor`;
a column that is not declared, or is optional, is `400 bad-sort`.

An optional column cannot be sorted by at all: SQLite sorts `NULL` first
and Postgres sorts it last, so the page would differ between two
deployments of one declaration.

A batch read takes `"sort"` too, or the batch is a second-class way to
ask the same question.

## Narrowing a page

Every query parameter but `after` is a filter, named for the column it
narrows. **Equality, and nothing else.** #153's rule bounds the
declaration surface — *anything referencing another row or another
request is a function, not a field* — and the same instinct bounds what a
caller may ask of one: ranges, prefixes and `LIKE` are queries a module
writes, not vocabulary a manifest grows into.

A parameter naming a column the table does not declare is a `400`, not a
parameter ignored. Ignoring it answers a question the caller did not ask,
with more rows than they asked for — and a client that misspells a column
would get a page that looks right. The value is checked against the
column's kind for the same reason.

**A filter cannot widen an `owner` scope.** The subject condition and the
filters are all in the same `WHERE`, so filtering on the subject column
narrows the caller's own rows and reaches nobody else's.

## Writing

`create`, `replace` and `remove`. `may_write` is a **separate** decision
from `may_read`, because `public-read` reads for everybody and writes for
nobody — one function answering both would need a parameter saying which,
and the day somebody passes the wrong one a public table becomes
writable.

| level | may write |
|---|---|
| `public-read` | **nobody** (`403 table-read-only`) |
| `tenant-members` | any signed-in caller, any row |
| `owner` | a signed-in caller, their own rows |
| `admin` | an admin token |

**`tenant-members` means any verified caller, not a member of this
tenant.** There is no membership fact to check: a `Caller` carries an id,
a session and an address, and `Ports::tenants` is not a `Port`, so a
module cannot ask which tenant it is serving either. On a deployment
without a registry — every venture `fz build` generates — the two are the
same set, because there is one tenant. On one with a registry they are
not, and issue #385 carries the analysis.

**A row a caller writes is a row they own.** Under `owner` the subject
column is settled by the harness, not taken from the body: absent or null
is filled in with the caller's id, already theirs is left alone, and
somebody else's is **refused** rather than quietly corrected. Overwriting
would be safe — the row would still be the caller's — but the client
asked for something and got something else without being told, which is
how a bug in a client becomes data nobody can explain.

**Changing or deleting a row that is not yours reports no such row.** Not
a 403, for the reason a read gives the same answer. The scope is part of
the `UPDATE`'s and `DELETE`'s `WHERE`, so the row matches nothing and
zero rows changed is the refusal.

`replace` writes every declared non-key field. A merge would make "unset
this field" unexpressible: an absent key and a null one would both have
to mean "leave it".

## What the venture publishes

`surface(&tables)` is what `/__surface` carries for the declared tables:
two actions per readable table and three more for a writable one. A table
that is served and absent from it is a venture whose published contract
is smaller than the venture.

A surface says a route exists, what it takes, and whether a credential is
needed. It does **not** say which rows the caller gets — that is decided
per request against their own id. So `owner` and `tenant-members` both
publish as `Audience::Subject`, a variant added for them: calling `owner`
public would render a form for rows the caller cannot reach, and calling
it admin would hide it from the person whose rows they are.

A `public-read` table publishes its reads and no writes, because there
are none. The body schema on a write is the table's own JSON Schema — the
same bytes the row validator enforces, so a generated form and the route
it posts to cannot disagree about what a row is.

## What a declared table's privacy block actually does

`tests/privacy.rs` mounts a declared-tables module beside
`cratefield-privacy` and asks the questions a subject would:

- a subject's `/v1/privacy/export` carries their rows from the declared
  table, and the sentence the author wrote is published with them;
- a table declared to hold nobody is in no subject's export;
- `/v1/privacy/manifest` names both, and publishes the reason the second
  holds nobody;
- an erasure removes the subject's rows and leaves another subject's
  alone;
- and leaves the table that holds nobody alone, which is the failure that
  would delete a venture's reference data the first time anybody asked.

A declaration that never reaches an export is decoration, and it is
decoration that reads as compliance. These are what make it not that.

## The rules, and why each is that way

| level | anonymous | signed in | reaches |
|---|---|---|---|
| `public-read` | yes | yes | everything |
| `tenant-members` | **401** | yes | everything |
| `owner` | **401** | yes | only rows whose subject column is theirs |
| `admin` | the admin check's own answer | same | everything |

**An anonymous caller gets 401, not an empty page.** "No rows" and "you
are not signed in" are different answers and only one of them tells the
caller what to do about it.

**`owner` is a scope, not a filter.** The subject condition joins the
`WHERE`; it is not applied to rows already fetched. A post-filter paired
with a `LIMIT` hands back a short page, and the shortfall is a count of
rows the caller was not allowed to see.

**A row belonging to somebody else is not found, not forbidden.** A `403`
is an answer about a row the caller was never in a position to learn
exists. The scope produces that by construction: the subject condition
and the key are in the same `WHERE`, so the row does not match.

**`admin` keeps the admin check's own refusal.** "Admin endpoints are
disabled or you sent no token" and "the token you sent is wrong" are
different facts — a 401 and a 403. Re-deciding them here collapses them.

**`owner` on a table with no subject column refuses with a 500.**
`fz build` will not produce such a manifest, so reaching it means the
deployment is running a composition its manifest would not have made.
With no column to match against, "everything" and "nothing" are both
wrong and one of them is a leak. The column is checked against the
table's fields at request time as well as at build time, because a table
edited under a stale privacy block would otherwise produce
`WHERE nope = 'ada'`.

**A level this build does not understand is refused.** `Access` is
`#[non_exhaustive]`; a level added later arrives at that arm rather than
falling into one of the four above, and the safe answer is no.
