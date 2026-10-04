# The Supabase migration report (JSON), version 1

`fz import supabase inspect --json` writes this document; the later importer
steps (#659, #660, #661) and the dashboard read it. The Rust types are
`cratefield_import_supabase::Report` and its fields
(`crates/import-supabase/src/report.rs`), which are the definition; this
page is the reader's guide. [`supabase.md`](supabase.md) explains the
command.

## Stability rules

- `report_version` is `1`. It changes when a field is removed or renamed,
  or changes meaning. **Adding a field does not change it**: a reader
  ignores fields it does not know.
- Every list is sorted — by schema, then name, then whatever makes the key
  unique; findings by `id` — so two inspections of an unchanged project
  produce the same bytes. There is **no timestamp**: when it ran is the
  run directory's business, not the report's.
- Enumerations are lower-case `snake_case` strings.
- Nothing secret is in it: no credential, no password hash, no email, no
  row data. The connection is named by `host`, `port` and `database`
  alone, and every free-text SQL fragment (policy expressions, column
  defaults, check constraints, cron commands) has passed through the
  harness's log scrubber.
- An optional fact is `null` when it was not inspected — never an empty
  list, which would claim "none".

## Top level

| Field | Type | Meaning |
|---|---|---|
| `report_version` | integer | `1` |
| `tool` | object | `name`, `version` of the crate that wrote it |
| `project` | object | `ref`, `host`, `port`, `database`, `server_version` |
| `read_only` | object | what kept the inspection from writing, as observed (below) |
| `coverage` | object | `database`, `management_api`, `policy_classifier`: each `inspected`, `not_inspected` or `failed` |
| `summary` | object | counts and estimates (below) |
| `dispositions` | object | the decisions applied to the needs-work and blocker items (below) |
| `schemas` | array | `name`, `kind` (`user` or `supabase_managed`), `target` (`app` for `public`, the same name for another user schema, `null` for a managed one), `tables` |
| `tables` | array | user tables (below) |
| `views` | array | `schema`, `name`, `materialized`, `references_auth`, `references_storage` |
| `sequences` | array | `schema`, `name`, `owned_by` (`table.column` or `null`), `data_type` |
| `enums` | array | `schema`, `name`, `labels` (in sort order) |
| `extensions` | array | `name`, `version`, `schema`, `support`: `supported`, `supabase_platform`, `unsupported` or `unknown` |
| `functions` | array | `schema`, `name`, `arguments`, `kind`, `language`, `returns`, `security_definer`, `references_auth`, `references_storage`, `references_net` — never the body |
| `triggers` | array | `schema`, `table`, `name`, `function` (`schema.name`), `definition`, `enabled`; user triggers on `auth`/`storage` tables are included |
| `policies` | array | RLS policies (below) |
| `api_role_grants` | array | `role` (`anon`, `authenticated`, `service_role`) and the `tables` it holds a privilege on |
| `auth` | object | Supabase Auth as counts (below) |
| `storage` | object | `present`, `counts_exact`, `buckets` (below) |
| `edge_functions` | object | `status` and `functions` (`slug`, `name`, `status`, `verify_jwt`) |
| `realtime` | object | `publications`: `name`, `all_tables`, `operations`, `tables` |
| `cron_jobs` | array | `name`, `schedule`, `command` (scrubbed), `active` |
| `findings` | array | every item classified (below) |
| `warnings` | array of strings | what the reader should know that is not a finding |

## `read_only`

| Field | Meaning |
|---|---|
| `transaction_read_only` | the reads ran in a `READ ONLY` transaction, read back inside it |
| `session_read_only` | the session default was read-only too |
| `no_transaction_id_assigned` | Postgres never assigned the transaction an id, which a write would have |
| `role` | the role inspect connected as |
| `role_is_superuser` | it is a superuser |
| `role_can_write` | it holds `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` on a user, `auth` or `storage` table, or `CREATE` on one of those schemas |

## `summary`

| Field | Meaning |
|---|---|
| `automatic`, `needs_work`, `blockers` | finding counts |
| `decided`, `undecided` | needs-work and blocker items with, and without, a disposition; cutover refuses while `undecided` is non-zero (#661) |
| `ready` | no blockers |
| `tables`, `estimated_rows` | user tables and the sum of their planner estimates |
| `data_bytes` | heap and TOAST bytes of the user tables: what the data step moves |
| `index_bytes` | their index bytes: rebuilt on the target, not moved |
| `storage_objects`, `storage_bytes` | from `storage.objects` and each object's recorded size |
| `transfer_assumed_mbps` | the throughput the estimate assumes |
| `estimated_transfer_seconds` | `(data_bytes + storage_bytes)` at that throughput, rounded up; index builds and verification are not in it |

## `tables[]`

`schema`, `name`, `kind` (`table` or `partitioned_table`),
`estimated_rows` (`null` when never analyzed), `data_bytes`,
`index_bytes`, `rls_enabled`, `rls_forced`, `primary_key` (column names in
key order; empty when none), `columns` (`name`, `data_type`, `nullable`,
`default`, `identity` — `always`/`by_default`/`null` — and `generated`),
`constraints` (`name`, `kind` — `primary_key`, `foreign_key`, `unique`,
`check`, `exclusion`, `trigger` — `definition`, and `references` as
`schema.table` for a foreign key), `indexes` (`name`, `unique`, `primary`,
`definition`). Tables owned by an extension (PostGIS's spatial reference table)
are not listed.

## `policies[]`

| Field | Meaning |
|---|---|
| `schema`, `table`, `name` | the policy |
| `command` | `ALL`, `SELECT`, `INSERT`, `UPDATE` or `DELETE` |
| `permissive` | permissive or restrictive |
| `roles` | sorted |
| `using`, `with_check` | the expressions as Postgres renders them, scrubbed; `null` when absent |
| `pattern` | `owner_only`, `tenant_scoped`, `public_read`, `public_write`, `role_based`, `service_role_only`, `custom_logic` or `needs_review` |
| `confidence` | 1.0 for a rule match, the classifier's own number for a classifier label, 0.0 when unplaced |
| `source` | `rule` or `classifier` |
| `classifier_label` | the label the classifier gave below the threshold (the policy is then `needs_review`); otherwise `null` |
| `suggested_equivalent` | the check to write in a route — advice, never enforcement code |
| `test_stub` | a failing Rust test (`todo!()`) naming the policy and quoting its SQL, to become the test that proves the replacement |
| `disposition` | `covered`, `waived` or `undecided`: this item's entry in the dispositions file (ADR 0026, Decision 5); `undecided` in an inspect report with no file |

## `dispositions`

`fz import supabase inspect --dispositions <FILE>` applies a TOML file of
per-item decisions (ADR 0026, Decision 5; `docs/import/supabase.md`). Without
one, every needs-work and blocker item is undecided: `decided` and `stale`
are empty and `by_kind` lists them all as `undecided`.

| Field | Meaning |
|---|---|
| `by_kind` | per finding `kind`: `covered`, `waived` and `undecided` counts; only kinds with an item, sorted by `kind` |
| `decided` | one entry per decided item — `id`, `status` (`covered` or `waived`), and `ref` (covered only) or `reason` (waived only) — sorted by `id` |
| `stale` | entry ids from the file that match no needs-work or blocker item, sorted |

## `auth`

`present`, `users`, `users_without_password`, `users_unconfirmed`,
`anonymous_users`, `identities_by_provider` (`provider`, `identities`),
`mfa_factors`, `sso_providers`, and from the Management API
`enabled_providers` and `enabled_mfa` (`null` when not inspected).

## `storage`

`present`; `counts_exact` (false when `storage.objects` has RLS the role
cannot bypass, so counts may be low); `buckets`: `id`, `name`, `public`,
`file_size_limit`, `allowed_mime_types`, `objects`, `bytes`,
`objects_over_blob_cap` (objects over the Blob port's 10 MiB put cap).

## `findings[]`

| Field | Meaning |
|---|---|
| `id` | `<kind>:<object>`, stable across runs; the sort key |
| `kind` | `schema`, `table`, `foreign_key`, `view`, `materialized_view`, `sequence`, `enum`, `extension`, `function`, `trigger`, `policy`, `grant`, `auth`, `auth_provider`, `bucket`, `edge_function`, `publication`, `cron_job` |
| `object` | the qualified name |
| `classification` | `automatic`, `needs_work` or `blocker` |
| `phase` | the step that handles it — `schema`, `data`, `auth`, `storage` — or `code` when the venture's own code has to |
| `reason` | why it is classified so |
| `cratefield_equivalent` | what it becomes on Cratefield |

A later step looks up its own items by `kind` and `phase`; the dashboard
groups by `classification`. Every `needs_work` finding needs a disposition
before cutover (ADR 0026, Decision 5).
