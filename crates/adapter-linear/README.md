<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-linear"><img src="https://img.shields.io/crates/v/cratefield-adapter-linear.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-linear on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-linear"><img src="https://img.shields.io/docsrs/cratefield-adapter-linear?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-linear documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-linear

The [`Tracker`](https://docs.rs/cratefield-core) port over the Linear
GraphQL API for the Cratefield harness (issue #559): `file`, `status`,
`comment` and the inbound status webhook, all over
`https://api.linear.app/graphql` through the runtime's `HttpClient` and
`Clock` ports — no vendor SDK, no `reqwest`, so the same adapter runs
unchanged on Cloudflare Workers and natively.

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_linear::LinearTracker;
use cratefield_core::{Credential, Destination, TicketDraft};

let tracker = LinearTracker::new(Arc::new(FetchClient), Arc::new(WorkersClock));
let filed = tracker
    .file(
        &Destination::Linear { team: "8a7b1c2d-…".into() },  // the team's UUID
        &Credential::new("lin_api_…"),                      // or an OAuth token
        TicketDraft::new("01JFILED…", "Outbox: refund failed", "…", Severity::Error),
    )
    .await?;
// filed.external_id — the issue UUID; filed.url — https://linear.app/acme/issue/ENG-123/…
```

The `Clock` is a constructor argument rather than a builder default so a
deployment that forgets it fails to compile — it is what reads the
HTTP-date form of `Retry-After` on a 429 (issue #278). `with_base` points
the adapter at a fake in tests.

## Three caveats worth knowing

- **A redelivery may file twice.** Unlike the Jira adapter, this one does
  *not* search before it creates: Linear addresses labels by UUID and
  offers no way to search an issue by an arbitrary stamp, so there is
  nothing to look for. The idempotency key is instead folded into the
  description as `cratefield-idem-<first 16 bytes of SHA-256 of the key,
  hex>` (hashed, so a key quoting tenant data never rides Linear as plain
  text), which makes any duplicate findable with one text search. Dedupe at
  the receiver if exact-once filing matters.
- **Tags are not mapped to Linear labels.** Linear addresses a label by
  its UUID and the port's `labels` are free-form text, so guessing one
  would attach a stranger's label or none; the text rides the description
  footnote instead, with the `environment` and `severity/<name>`.
- **Replay protection is the caller's job.** Linear's `webhookTimestamp`
  rides in the signed *body*, not a header, so core's `ProviderScheme`
  cannot bind it into the verifier and a captured delivery verifies
  forever. A caller wanting a freshness window must read
  `webhookTimestamp`/`webhookId` out of the already-verified body itself.
  Terminate on TLS and rotate the per-tenant secret either way.

## Shape of the mapping

The two credential shapes are told apart by Linear's own prefix: a
`lin_api_…` **personal API key** is sent bare (`Authorization: <key>` —
Linear rejects `Bearer` on personal keys), anything else is treated as an
OAuth access token and sent as `Authorization: Bearer <token>`. The
`Credential` is zeroised on drop; the header copy the HTTP layer owns is
not, and nothing else in the crate ever formats the token.

`Filed.external_id` is the issue's **UUID** — the only id
`CommentCreateInput.issueId` is documented to take. `status` maps
`state.type`: `triage`/`backlog`/`unstarted` → `Open`, `started` →
`InProgress`, `completed` → `Resolved`, `canceled` → `Closed`, anything
else → `Unknown`. Bodies are Markdown and ride verbatim.

Linear reports a failed GraphQL operation with **HTTP 200** and a
top-level `errors` array, so this adapter treats a non-empty `errors`, a
`success: false`, and a non-2xx as failures — except that a mutation
already reporting `success: true` wins over a non-fatal `errors` array,
since re-running it would file a duplicate. `401`/`403` (and an
`AUTHENTICATION`/`AUTHORIZATION` code in `errors[].extensions`) →
`Unauthorized`; `429`, `5xx` and a `RATELIMITED` code →
`Transient { retry_after }`; everything else → `Rejected`. Every response
is read through a typed `Deserialize` struct, never by indexing a `Value`:
a `200` whose body is an unexpected shape is an error, not a panic.

`LinearStatusWebhook` (`kind() == "linear"`) verifies `Linear-Signature:
<hex>` — HMAC-SHA256 over the raw body, no prefix — through
`cratefield_core::receive_status`, and reads an Issue `update` carrying a
state and an `updatedFrom.stateId` into a `StatusUpdate` keyed by the same
UUID `file` returns. Every other event is `Ok(None)`: verified silence,
not an error.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.