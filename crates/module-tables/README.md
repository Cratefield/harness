# cratefield-module-tables

Serves the tables a venture declares in its manifest's `[tables]` section
(issue #153), with the access level each one declares.

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

The routes that call it are the next piece. Nothing serves a declared
table yet.

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
