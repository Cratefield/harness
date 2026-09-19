<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-github-issues"><img src="https://img.shields.io/crates/v/cratefield-adapter-github-issues.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-github-issues on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-github-issues"><img src="https://img.shields.io/docsrs/cratefield-adapter-github-issues?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-github-issues documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-github-issues

The [`Tracker`](https://docs.rs/cratefield-core) port over the GitHub Issues
REST API for the Cratefield harness (issue #432). It speaks
`https://api.github.com` through the runtime's `HttpClient` port — no vendor
SDK, no `reqwest` — so the same adapter runs unchanged on Cloudflare Workers
and natively (ADR 0002: the port is core's, the vendor client is this
crate's).

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_github_issues::GitHubIssues;
use cratefield_core::{Destination, TicketDraft};
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

let tracker = GitHubIssues::new(Arc::new(FetchClient), Arc::new(WorkersClock), token);
let filed = tracker
    .file(
        &TicketDraft::new(
            "Outbox: refund failed",
            "The refund webhook failed twice.",
            Destination::GitHubIssues {
                owner: "acme".into(),
                repo: "widgets".into(),
            },
            "01JFILED000000000000000000",
        )
        .labels(["from-outbox"]),
    )
    .await?;
```

The `Clock` is a constructor argument rather than a builder default so a
deployment that forgets it fails to compile — it is what lets the adapter
read the HTTP-date form of `Retry-After` on a 429 instead of retrying
immediately (issue #278). `GitHubIssues::with_base` points the adapter at
GitHub Enterprise Server, or at a fake in tests.

## Search before create

The outbox is at-least-once: `Tracker::file` **will** be called twice for one
ticket. So the adapter stamps every issue body with an invisible HTML
comment —

```html
<!-- cratefield-idem: <idempotency key> -->
```

— and looks for its own stamp before creating: first
`GET /search/issues?q=...`, then (the search index is eventually consistent,
so a fast retry can predate it) the most recent issues page. A hit only
counts when the marker really appears in the issue body — search
token-matches and must not be trusted blind. On a verified hit the adapter
returns `Filed { deduplicated: true }` and never POSTs.

**Fail closed.** A lookup that itself fails — a non-2xx or a transport error
— fails the whole call instead of falling through to the create. Creating
after an unreliable dedupe check is exactly the double-file the check exists
to prevent.

## Error mapping

To `cratefield_core::TrackerError`: 401/403 → `Unauthorized`, 404 →
`Rejected` (the repository is gone or the token cannot see it — retrying
will not fix it), 422 → `Rejected`, 429/5xx → `Transient { retry_after }`
(`Retry-After`, both the seconds and the HTTP-date form), any other 4xx →
`Rejected`. No error `Display` ever includes the token. A draft whose
destination is not `Destination::GitHubIssues` is `Rejected` before any
network call.

Headers on every request: `Authorization: Bearer <token>`,
`Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`,
and a `User-Agent` — GitHub rejects requests without one.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
