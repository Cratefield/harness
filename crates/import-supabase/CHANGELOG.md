# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1](https://github.com/Cratefield/harness/compare/cratefield-import-supabase-v0.2.0...cratefield-import-supabase-v0.2.1) - 2026-10-09

### Other

- end-to-end Supabase import job on a real `supabase start` with an EarthOS-shaped fixture (issue #733) ([#839](https://github.com/Cratefield/harness/pull/839))

## [0.2.0](https://github.com/Cratefield/harness/compare/cratefield-import-supabase-v0.1.0...cratefield-import-supabase-v0.2.0) - 2026-10-05

### Other

- Supabase import: plan.json, bare `fz import supabase` dry run, `--apply --plan` drift check and target extension preflight ([#754](https://github.com/Cratefield/harness/pull/754))
- Supabase import: record per-item dispositions (covered/waived) in a file and merge them into the report ([#752](https://github.com/Cratefield/harness/pull/752))
- *(import-supabase)* keep the crate version out of the fixture-report snapshot ([#786](https://github.com/Cratefield/harness/pull/786))
- Supabase inspect: drop managed-schema policies, route storage policies to their buckets, flag RLS-on/no-policy tables ([#751](https://github.com/Cratefield/harness/pull/751))

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/cratefield-import-supabase-v0.1.0) - 2026-10-04

### Added

- *(import-supabase)* inspect a Supabase project read-only and write the migration report ([#658](https://github.com/Cratefield/harness/pull/658)) ([#697](https://github.com/Cratefield/harness/pull/697))
