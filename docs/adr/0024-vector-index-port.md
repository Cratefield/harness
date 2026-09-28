# ADR 0024: Nearest-neighbour search is its own port, one namespace per tenant

Status: accepted, 2026-09-28. Issue #561. Extends ADR 0002 (ports and
adapters) with the `VectorIndex` and `Embedder` ports.

## Context

Hybrid retrieval — BM25 for the words, vectors for the meaning — needs
nearest-neighbour search, and the harness has nowhere to put it. The
`Database` port is deliberately a portable SQL subset (ADR 0004): one
query layer for SQLite (D1) and Postgres, no dialect functions. Every
way to store and rank vectors inside SQL is a dialect extension —
pgvector is Postgres, sqlite-vec is SQLite, neither exists on the other
engine — so vectors cannot ride `Database` without breaking the
portability that is its point.

## Decision

**A `VectorIndex` port of its own**: `upsert`, `query` taking a `k` and
an equality `VectorFilter`, and `delete`. An upsert replaces the whole
record (values and metadata, not a merge); a delete of a missing id is
not an error. The score is cosine similarity, higher is closer: one
normalised number a module can threshold without learning the vendor's
metric or scale.

**Every call is scoped by a `VectorNamespace`, one per tenant.**
`VectorNamespace::for_tenant` — the tenant id — is the normal
constructor, the same scoping a table has. A query never crosses
namespaces: tenant A's corpus is not reachable by tenant B's query even
when both live in one index.

**An `Embedder` port of its own, not `TextModel::embed`.** The
`TextModel` module doc keeps embeddings out of its shape — no tools, no
streaming, no embeddings. `Embedder::embed` answers `Embeddings`: one
vector per input text, in input order, plus the answering `model` and
its `input_tokens`. Vectors from different models are not comparable,
so the model name rides with the vectors; the token count is what a
usage report bills.

**Both are `Port` variants.** A module lists `Port::VectorIndex` or
`Port::Embedder` in `requires()` or `optional()`; requiring one fails
composition in `Harness::build` when the runtime does not provide it,
and `GET /__ready` answers 503 naming the port when it is absent at
runtime — a binding name configured in the manifest but missing from
the Worker env. The unwired answer is the error's `NotConfigured`
variant.

**Cloudflare Vectorize adapter.** A hand-written binding on Workers:
worker 0.8.5 has no Vectorize API. Vectorize's ids are index-global and
`deleteByIds` takes an array of ids and no namespace, so the adapter
stores each vector under the hex SHA-256 of namespace + NUL + id —
exactly Vectorize's 64-byte id limit — and keeps the caller's id in a
reserved metadata key, carried back on every match. The index must be
created with the cosine metric, whose scores are already the port's,
and with metadata indexes for every key a `VectorFilter` can select on
(capped at ten). Vectorize caps `topK` at 50 when returning values or
metadata (100 without), so a metadata query answers at most 50 however
large the `k`.

**The native adapter is exact.** `ExactVectorIndex`, in core, is an
in-process brute-force cosine index: wasm-safe, dependency-free,
deterministic (ties break by id ascending). It answers the true
top-`k` — right for tests, development and small single-process
corpora — and is not persistent: a restart starts empty, a second
isolate sees nothing. A Qdrant client or an embedded HNSW is the
upgrade path behind the same port, not built now.

## Alternatives considered

- **pgvector or FTS5 in `Database`.** One engine's extension each, so
  a portable query cannot use either — the portability is the point.
- **`TextModel::embed`.** Changes `TextModel`'s call shape — a
  completion in, a list of vectors out — which the module doc rules out.
- **A namespace per module** (tenant-module pairs). It splits a
  tenant's corpus across every module that embeds it, so no query
  could span it; the module dimension is `VectorFilter`'s job.
- **HNSW now.** Dependency weight in the wasm bundle for a corpus size
  nothing has measured; ADR 0019 puts the measurement first. The exact
  index is the honest baseline an ANN adapter has to beat.

## Consequences

- Two more `Port` variants; the single `Port::ALL` list and the
  exhaustive match behind `Ports::provides` make forgetting one a
  compile error, not a quietly wrong bundle.
- `vector_index_conformance` runs against both adapters from the
  testing crate, pinning isolation, filter and score contracts once.
- ANN results can differ from exact results; the conformance suite
  uses small, well-separated vectors, which both answer identically.
- Hosted adapters are eventually consistent — a write can take seconds
  to become queryable — while the exact index answers immediately.
- No Workers AI `Embedder` adapter yet — a follow-up; a provider
  identifier plus a token count is what its usage report needs.

## References

- Issue #561; `crates/core/src/ports/vector_index.rs`,
  `crates/core/src/ports/embedder.rs`, `crates/core/src/ports/mod.rs`;
  ADR 0002, ADR 0004 (the portable SQL subset this stays out of),
  ADR 0019 (a change is admitted by measurement).
- Cloudflare Vectorize docs: platform limits and the client API
  (`deleteByIds`, the metadata `topK` cap).
