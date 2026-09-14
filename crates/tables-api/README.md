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

The two 404s are the same answer on purpose. Writes are the next piece.

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
