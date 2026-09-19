# ADR 0018: A composite key is addressed by query, not by path

Status: accepted, 2026-09-19. Issue #387, child of epic #153 (declared
tables). Records the decision the interim in #388 deferred.

## Context

A declared table's primary key has always been allowed to be more than
one column. `PrimaryKeyWire` parses both spellings
(`crates/tables/src/manifest.rs`), `validate_primary_key` checks that
the columns are declared, required or defaulted and not repeated, and
never counts them, and docs/TABLES.md says it in a sentence: "A primary
key may be one column or several." Every layer below the routes handles
the shape whole: the migration creates it, the row validator enforces
it, `select_page` orders by all of it and `cursor_from_query` carries
all of it in the cursor — which is why a composite-key table pages
without a corner case.

Three of the five routes cannot follow. `key_from_path`
(`crates/tables-api/src/routes.rs`) turns one path segment into the
table's primary key, and a key of more than one column is refused there
with `400 composite-key`. The refusal is right, and this decision
leaves it standing: a separator would have to be a character that
cannot occur inside a value, and every character can occur inside a
value, so the rows whose keys contain it would become unaddressable —
silently, and only those rows.

What the gap costs is not the edge of the shape but its centre. A
composite-key table is paged, created, and then never read by key,
never replaced, never removed. The tables most likely to declare a
composite key are membership and join tables, where create-and-delete
*is* the usage: a row is written when somebody joins and removed when
they leave, and the page is bookkeeping. The missing half is the
important half.

The interim in #388 stopped the published contract promising what does
not answer: `addressable()` (`crates/tables-api/src/surface.rs`)
publishes only the page and the create for a composite-key table, so
`/__surface` says what is there. The question itself stayed open, and
two facts about the router bound every answer to it.

**The router is one shared router.** `router()` registers generic
patterns — `/{table}` and `/{table}/{key}` — once, not one router per
declared table. The patterns are written without seeing any table, so
no pattern can be written for one table's key shape.

**A static segment beats a dynamic one.** Register any static segment
under `/{table}/` and it shadows `{key}` for *every* table at once,
because there is one router to shadow it in. `/{table}/by` does not
collide with a row keyed `by`; it captures it.

## Decision

**The key is named in the query, not the path.**
`/{table}/__by?<column>=<value>&…` answers `GET`, `PUT` and `DELETE`
with the bodies and statuses the path routes answer: a read returns the
row, a replace takes the row and answers the replaced one, a remove
answers `204` and nothing. One route whatever the key's arity, no
separator to escape, and the columns are named rather than positional —
reordering a declaration cannot quietly change what an existing URL
means. `after` and `sort` are the harness's parameters on this
sub-path, not key names: `after` can never be a column, and `sort` can
— the page route's own overlap, already carried and not decided here.

**The segment is `__by`, not `by`.** A bare `by` reads better, and the
issue argued for it; it loses to the second router fact, that a static
segment beats a dynamic one — so does `__by`, and that is what a
reservation is. The difference is which row it strands. `by` would
strand any row whose key is the word `by`, a plausible value in a table
of slugs or tags, and nothing in a URL would say why it stopped
resolving. `__by` strands the value `__by` — which cannot be a
declared table name and is rarely a key value — and the strand is the
reservation, stated rather than discovered. `__` is already the
harness's namespace in a path — `/__health`, `/__ready`, `/__surface`,
`/__batch`, `/__events` — so this adds no new reserved word; it extends
one. Stated as a rule: **under a table mount, a segment beginning `__`
belongs to the harness.**

**It answers for every declared table, not only composite-key ones.**
`/{table}/{key}` stays as the shorthand it is for a single-column key.
This is not two ways to do one thing, and the reason is the same
shadowing: reserving `__by` is what makes the row whose key is
literally `__by` unreachable by path, and serving `__by` for
single-column tables too is precisely what gives that row a way back —
`/{table}/__by?id=__by`. Serving the route only where it is needed
would leave that row with no address at all.

**A partial key is a `400`, and so is a column the key does not have.**
A query naming some of the primary-key columns is refused, matching the
refusal `select_one` already makes rather than matching every row that
shares the given prefix; one naming a column outside the key is refused
the way a page filter naming an undeclared column is, because ignoring
it answers a question the caller did not ask. Values are parsed exactly
as `key_from_path` parses them, so a `real`, `boolean` or `json` key
stays refused for the reason it already is.

**When it ships, `/__surface` publishes the three single-row actions
for a composite-key table again**, against this sub-path:
`addressable()` goes away, and the two tests that pin it
(`a_composite_key_table_publishes_only_the_routes_it_has` and
`a_single_column_key_still_publishes_all_five`) change with it. Until
then the contract keeps saying what is there — this ADR ships no
behaviour, and `every_published_action_is_a_route_that_exists` keeps
the surface and the router the same meanwhile.

## Rejected

**1. A segment per key column: `/{table}/{tenant}/{member}`.** The
honest, hierarchical shape, and the arity *is* known for it — from the
declaration, at build time. It loses to the first router fact, that
there is one shared router: the patterns are registered once for every
table, so serving it means one registered pattern per arity, with no
natural bound and a contract that grows with the longest key anybody
declares. The key becomes positional, so reordering a declaration
changes what every existing URL means, and the second segment is spent
forever, foreclosing any later `/{table}/{key}/<sub-resource>`.

**2. A bare `by` segment.** It reads much better, and it is what the
issue argued for — `/{table}/by?tenant=acme&member=ada` is the shape
this decision ships with two underscores bolted on. It loses to the
second router fact, a static segment beats a dynamic one: one shared
router means a static `by` captures the row keyed `by` on every
single-column table too, and `__by` captures the row keyed `__by` —
rarer, and now the harness's own `__` reservation rather than a
coincidence of English.

**3. The key in the body of `PUT` and `DELETE` on the collection
route.** Symmetric with the page's filters and no new segment to
reserve. It loses because a `DELETE` with a body is handled
inconsistently by caches and proxies, and `GET` cannot carry a body at
all — so the read would still need a different answer, and one table
would end up with two addressing schemes, one of them broken in the
middle.

**4. Refusing a composite key in `fz build`.** The smallest change: one
arity check beside `validate_primary_key` and the gap closes by never
opening. It loses because it takes away a shape that declares, migrates,
pages and writes correctly today: the DDL renders `PRIMARY KEY (a, b)`
(`crates/tables/src/ddl.rs`), `select_page` orders by every key column
(`crates/tables/src/sql.rs`), and `cursor_from_query` was written to
carry a multi-column key through a page. And `docs/TABLES.md` promised
the shape in the guide's first commit — "A primary key may be one column
or several." Refusing it in `fz build` withdraws a documented, working
capability from every venture that declares one, to close a gap in one
layer. Turning a working declaration into a manifest error is not
closing a gap; it is evicting the table.

**5. Joining the values with a separator.** What `key_from_path`
already refuses, and the test that pins it
(`a_composite_key_is_refused_rather_than_joined_with_a_separator`)
stays. The separator has to be a character that cannot occur in a
value, and there is no such character, so the rows containing it do not
get an error — they get a key that parses into the wrong columns and
matches the wrong row, or no row, with nothing to tell the caller
which. The tree runs the experiment already: `waitlist_send_cooldown`
holds its subject as one joined value, `<email>:<product>`, and the
comment above its `PersonalDataSet::unreachable` entry records the
cost — `WHERE subject = ?` with a bare address never matches, the
value's format being the problem (`crates/module-waitlist/src/lib.rs`).
A joined value strands exactly the rows it joins.

## Consequences

- Nothing ships here. `key_from_path`, `addressable()` and `/__surface`
  are unchanged in behaviour, and the three single-row routes stay a
  `400 composite-key` until the sub-path is built.
- The generated client (#155) can emit one addressing method per table,
  chosen by arity at generation time: a composite-key table gets the
  query form, and no client ever joins or positions a key again.
- The `__` reservation under a table mount is now explicit, so any
  future harness sub-path takes the same prefix instead of negotiating
  its own.
- `docs/TABLES.md` now says "composite key" where it read "a key of
  several" — the docs and the decision name the shape the same way.
- The refusal's title — "This table's rows are not addressable by path"
  — stops being true the day the sub-path lands, and its description
  should then say where the key goes instead.

## References

Issue #387; epic #153; the interim in #388;
`crates/tables-api/src/routes.rs`, `crates/tables-api/src/surface.rs`,
`crates/tables/src/manifest.rs`;
`docs/PRIVACY.md`; the generated client of #155; ADR 0010 (an action
names a route the module already serves).
