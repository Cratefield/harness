<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-colonizer"><img src="https://img.shields.io/crates/v/cratefield-adapter-colonizer.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-colonizer on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-colonizer"><img src="https://img.shields.io/docsrs/cratefield-adapter-colonizer?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-colonizer documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-colonizer

An HTTP client for the **Colonizer mothership** — the service that runs a venture's colonies — for the Cratefield harness (issue #675). It uses the runtime's `HttpClient` port, no vendor SDK and no `reqwest`, so it runs on Workers (`worker::Fetch`) and natively.

## Usage

```rust,ignore
use cratefield_adapter_colonizer::{Colonizer, NewColony};

let mothership = Colonizer::new(
    Arc::new(FetchClient),
    Arc::new(WorkersClock),
    "https://mothership.example",
    Some(col_token),
);
let colony = mothership
    .create_session(&NewColony { repo: repo.into(), issue: Some(675), prompt: None })
    .await?;
if let Some(question) = mothership.question(&colony.id).await? {
    mothership.answer(&colony.id, &question.id, "yes").await?;
}
```

Without a usable token or base URL every call is `ColonizerError::NotConfigured`, with **no request**.

## Reachability

The mothership must be reachable at a **public URL or through the runtime's remote tunnel**: the `HttpClient` port refuses loopback, private and link-local destinations with `HttpError::BlockedDestination` (re-vetting every redirect hop), so `http://127.0.0.1:8080` is refused rather than dialled.

## Routes

Off the base URL (trailing slash trimmed), each with `Authorization: Bearer <token>`.

| Call | Route |
|---|---|
| `whoami()` | `GET {base}/api/v1/whoami` |
| `create_session(&NewColony)` | `POST {base}/api/v1/colonies` |
| `get(id)` | `GET {base}/api/v1/colonies/{id}` |
| `list(limit, cursor)` | `GET {base}/api/v1/colonies?limit=N[&cursor=…]` |
| `question(id)` | `GET {base}/api/v1/colonies/{id}/question` |
| `answer(id, question_id, answer)` | `POST {base}/api/v1/colonies/{id}/answer` |
| `message(id, text)` | `POST {base}/api/v1/colonies/{id}/messages` |
| `stop(id)` / `resume(id)` | `POST {base}/api/v1/colonies/{id}/stop` / `…/resume` |

`question` answers `Ok(None)` when the colony asks nothing (a `204` or a JSON `null`). A colony id is validated to `[A-Za-z0-9_.-]` without `..` **before** any request, so it can never rewrite the path; `list`'s cursor is percent-encoded. An omitted `issue`, `branch`, `scopes`, `options` or `next_cursor` reads as empty.

## Error mapping

Errors arrive as `{"error": "…"}`, with `scope` (or `required_scope`) on a 403.

| Status | Variant |
|---|---|
| *(no token or base URL)* / *(local refusal)* | `NotConfigured`, no request / `Invalid { detail }` |
| 400, 422, other 4xx | `Invalid { detail }` |
| 401 / 403 / 404 / 409 | `Unauthorized` / `Forbidden { scope }` / `NotFound` / `Conflict { detail }` |
| 429 (with `Retry-After`) / 5xx | `Transient { retry_after }` |
| *(transport, incl. `BlockedDestination`)* / *(unreadable body)* | `Transport { detail }` / `Decode { detail }` |

## Tokens

The `col_…` token is held in memory and nothing else: never logged, never printed by `Debug` (which shows only the base URL and `token_configured`), and never allowed into an error — it is cut out of provider and transport text before the error is built, then `cratefield_core::scrub_text` runs over what is left.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.