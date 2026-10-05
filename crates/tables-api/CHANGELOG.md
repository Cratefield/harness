# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/cratefield-tables-api-v0.1.0) - 2026-10-05

### Added

- *(tables-api)* a composite key gets its single-row routes at `/{table}/__by` ([#153](https://github.com/Cratefield/harness/pull/153)) ([#475](https://github.com/Cratefield/harness/pull/475))
- *(tables-api)* `?sort=` on the page route and in a batch read ([#383](https://github.com/Cratefield/harness/pull/383))
- *(tables-api)* several declared reads in one request ([#381](https://github.com/Cratefield/harness/pull/381))
- *(tables)* order a page by a declared column ([#380](https://github.com/Cratefield/harness/pull/380))
- *(tables)* filter a page, and fix the nullable column it uncovered ([#378](https://github.com/Cratefield/harness/pull/378))
- *(tables-api)* serve the writes the surface already publishes ([#374](https://github.com/Cratefield/harness/pull/374))
- a venture publishes the tables it declares ([#372](https://github.com/Cratefield/harness/pull/372))
- *(tables-api)* writing a declared table, with ownership enforced ([#369](https://github.com/Cratefield/harness/pull/369))

### Fixed

- *(tables-api)* publish cratefield-tables-api so the facade can package ([#787](https://github.com/Cratefield/harness/pull/787))
- *(core)* ERRORS.md covers every crate's problem slugs, and a duplicate slug fails CI ([#419](https://github.com/Cratefield/harness/pull/419)) ([#552](https://github.com/Cratefield/harness/pull/552))
- *(tables-api)* `tenant-members` fails closed where membership cannot be checked ([#385](https://github.com/Cratefield/harness/pull/385)) ([#424](https://github.com/Cratefield/harness/pull/424))
- the manifest's vocabularies are checked against the types they mirror ([#404](https://github.com/Cratefield/harness/pull/404))
- *(tables-api)* a conflict is the engine's phrase, not the word "unique" ([#393](https://github.com/Cratefield/harness/pull/393))
- a subject column must be able to hold a caller's id ([#391](https://github.com/Cratefield/harness/pull/391))
- *(tables)* a json column is not filterable, in either path ([#390](https://github.com/Cratefield/harness/pull/390))
- *(tables)* a filter for a null asks IS NULL, not `= NULL` ([#389](https://github.com/Cratefield/harness/pull/389))
- *(tables-api)* a composite-key table publishes only the routes it has ([#387](https://github.com/Cratefield/harness/pull/387)) ([#388](https://github.com/Cratefield/harness/pull/388))
- *(tables-api)* the cursor the server hands back is one it accepts ([#379](https://github.com/Cratefield/harness/pull/379))

### Other

- Scheduled work runs on a cooperative per-module budget, with a budget-aware Outbox drain ([#537](https://github.com/Cratefield/harness/pull/537)) ([#543](https://github.com/Cratefield/harness/pull/543))
- /__surface publishes an output schema for table reads, so public-read rows can be typed ([#517](https://github.com/Cratefield/harness/pull/517))
- Close four existence oracles: signup timing, owner-table conflicts, passkey issuance, Stripe signature compare ([#487](https://github.com/Cratefield/harness/pull/487))
- *(adr)* a composite key is addressed by query, not by path ([#387](https://github.com/Cratefield/harness/pull/387)) ([#422](https://github.com/Cratefield/harness/pull/422))
- two names that point at nothing ([#410](https://github.com/Cratefield/harness/pull/410))
- *(tables-api)* a declared table's redaction and anonymisation are real ([#397](https://github.com/Cratefield/harness/pull/397))
- `tenant-members` admits any verified caller, and say so ([#385](https://github.com/Cratefield/harness/pull/385)) ([#386](https://github.com/Cratefield/harness/pull/386))
- a writable declared table does not make a venture demand a captcha ([#377](https://github.com/Cratefield/harness/pull/377))
- a declared table's privacy block reaches export and erasure ([#375](https://github.com/Cratefield/harness/pull/375))
- The generated module serves the tables it declares ([#370](https://github.com/Cratefield/harness/pull/370))
- The routes, so a declared table is actually reachable ([#368](https://github.com/Cratefield/harness/pull/368))
- Reading a declared table, with the access level applied ([#366](https://github.com/Cratefield/harness/pull/366))
- The decision about who reaches whose rows ([#364](https://github.com/Cratefield/harness/pull/364))
