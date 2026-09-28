<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-jira"><img src="https://img.shields.io/crates/v/cratefield-adapter-jira.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-jira on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-jira"><img src="https://img.shields.io/docsrs/cratefield-adapter-jira?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-jira documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-jira

The [`Tracker`](https://docs.rs/cratefield-core) port over the Jira Cloud
REST API v3 for the Cratefield harness (issue #559). It speaks
`https://{site}/rest/api/3/…` through the runtime's `HttpClient` port — no
vendor SDK, no `reqwest` — so the same adapter runs unchanged on Cloudflare
Workers and natively (ADR 0002: the port is core's, the vendor client is
this crate's).

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_jira::JiraCloud;
use cratefield_core::{Credential, Destination, TicketDraft};
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

let tracker = JiraCloud::new(Arc::new(FetchClient), Arc::new(WorkersClock));
let dest = Destination::Jira {
    site: "acme.atlassian.net".into(),   // a bare hostname — never a URL
    project: "PROJ".into(),
};
let cred = Credential::new("devops@acme.test:ATATT3xAedummytoken"); // email:api_token
let filed = tracker
    .file(
        &dest,
        &cred,
        TicketDraft::new(
            "01JFILED000000000000000000",
            "Outbox: refund failed",
            "The refund webhook failed twice.",
            Severity::Error,
        )
        .labels(vec!["from-outbox".into()])
        .environment("production"),
    )
    .await?;
// filed.url — https://acme.atlassian.net/browse/PROJ-7
```

The `Clock` is a constructor argument rather than a builder default so a
deployment that forgets it fails to compile — it is what lets the adapter
read the HTTP-date form of `Retry-After` on a 429 instead of retrying
immediately (issue #278). `JiraCloud::with_issue_type` files as another
issue type than the default `"Bug"` (it must already exist in the project);
`JiraCloud::with_base` points the adapter at a fake in tests.

## The credential

The `Credential` is Atlassian's API-token pair, `email:api_token`, sent as
`Authorization: Basic base64(email:api_token)` on every request — create an
API token at `id.atlassian.com`, in the account that can file into the
destination project. The pair is zeroised on drop and redacted in `Debug`;
the adapter holds none between calls (it arrives per call), and nothing in
the crate ever formats it into an error or a log line.

The destination's `site` must be a **bare hostname** (`acme.atlassian.net`).
A value carrying a scheme, path, port, userinfo or whitespace is `Rejected`
before any request — a malformed site must not be able to move the Basic
credential off the host it names. The project key is validated too
(uppercase letters, digits and underscores, starting with a letter), as is
an `external_id` handed to `status` or `comment` (it must look like
`PROJ-123`).

## Search before create

The outbox is at-least-once: `Tracker::file` **will** be called twice for
one ticket. So the adapter labels every issue —

```text
cratefield-idem-<first 16 bytes of SHA-256 of the idempotency key, hex>
```

— and looks for its own label before creating:
`GET /rest/api/3/search/jql?jql=project = "PROJ" AND labels = "cratefield-idem-…"`.
The label is hashed so a caller's idempotency key (which may quote tenant
data) never rides Jira as plain text. On a hit the adapter returns the
existing issue as `Filed` and never POSTs.

**Fail closed.** A lookup that itself fails — a non-2xx or a transport
error — fails the whole call instead of falling through to the create.
Creating after an unreliable dedupe check is exactly the double-file the
check exists to prevent.

The body becomes an Atlassian Document Format (ADF) document: one plain
paragraph per blank-line-separated block of the Markdown body (the Markdown
syntax itself rides as literal text). Every issue also carries the draft's
own labels, the idempotency label, and a `severity/<name>` label. **The
`environment` field is dropped** — Jira has no single field the port's
shape maps it onto; put it in the body if a tenant needs it. Titles are
truncated to Jira's 255-character `summary` cap on a character boundary.

## Comments

`Tracker::comment` posts to `/rest/api/3/issue/{key}/comment`: the body as
ADF, plus — when the comment carries one — a paragraph whose text node
wears a link `mark` for the URL (only `http(s)` links are accepted; any
other scheme is `Rejected` before any request).

Comments have no search-before-write, so **a redelivery may duplicate the
note.** The caller's idempotency key rides a `cratefield-idem` comment
property, so any duplicate is findable and deletable; dedupe at the
receiver if exact-once notes matter.

## Status

`Tracker::status` reads `GET /rest/api/3/issue/{key}?fields=status` and
maps `fields.status.statusCategory.key` — Jira's own rollup, which
survives every custom workflow a tenant renames: `new` → `Open`,
`indeterminate` → `InProgress`, `done` → `Resolved`, anything else →
`Unknown`. The reported URL is `https://{site}/browse/{key}`.

## Inbound status webhook

`JiraStatusWebhook` implements core's `StatusWebhook` (`kind() == "jira"`),
so `cratefield_core::receive_status` verifies a delivery before parsing it:
the verifier is `X-Hub-Signature: sha256=<hex>` — HMAC-SHA256 over the raw
body, configured as a `ProviderScheme`, compared in constant time by core.

`jira:issue_updated` and `jira:issue_created` payloads carrying a status
map onto a `StatusUpdate`; every other event, and an update without a
status, is `Ok(None)` — verified silence, not an error. Invalid JSON is
`Malformed`.

**Replay is Jira's known gap:** its signature covers the body and nothing
else — there is no timestamp header — so the verifier's replay tolerance
has nothing to run on and a captured delivery verifies forever. Terminate
on TLS and rotate the per-tenant webhook secret; that is a property of
Jira's scheme, not a choice of this adapter.

## Error mapping

To `cratefield_core::TrackerError`: 401/403 → `Unauthorized` (the
`email:api_token` pair is wrong or powerless); any other 4xx → `Rejected`
with Jira's `errorMessages`/`errors` text flattened in, scrubbed by the
error's `Display`; 429/5xx → `Transient { retry_after }` (`Retry-After`,
both the seconds and the HTTP-date form). No error `Display` ever includes
the credential. A call whose destination is not `Destination::Jira` is
`Rejected` before any network call.

Headers on every request: `Authorization: Basic <base64 email:api_token>`
and `Accept: application/json`.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
