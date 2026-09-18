# cratefield-module-changelog

A project's release notes, mirrored into the venture's own database and
served over an API. A refresh pulls the releases of a GitHub repository (or
a Keep-a-Changelog file in it) and stores each one — the author's own
markdown, byte-for-byte from the Releases API. The public routes then read
**the database**, never GitHub: an outage, a rate limit or a misconfigured
repository costs a refresh, not the changelog.

There is no LLM here. Rewriting and translation are a later addition behind
a `TextModel` port that does not exist yet; until then every response
reports `rendering.style = "original"` and serves the stored text as-is,
and `?locale=` / `?style=` are accepted and select nothing.

## Routes

Mounted at `/v1/changelog`:

| Route | Audience | What it does |
|---|---|---|
| `GET /` | public | Releases, newest first. `page` (1-based, default 1), `per_page` (default 20, max 100), `locale`, `style` |
| `GET /{version}` | public | One release, 404 when the version is unknown |
| `POST /admin/refresh` | admin | Pull from GitHub now (`Authorization: Bearer <ADMIN_TOKEN>`) |

Before the first refresh the list is simply empty — `200` with
`"releases": []`, never an error.

```json
{
  "releases": [
    {
      "version": "v1.2.0",
      "title": "1.2.0",
      "body": "…original markdown…",
      "url": "https://github.com/owner/name/releases/tag/v1.2.0",
      "published_at": "2026-05-06T10:00:00Z",
      "prerelease": false,
      "rendering": { "style": "original", "locale": "en", "machine_generated": false }
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 37,
  "source": { "kind": "github-releases", "repo": "owner/name" },
  "refreshed_at": "2026-09-18T09:00:00Z"
}
```

## Configuration

Keys are `SCREAMING_SNAKE`, prefixed with the module name. All are optional
except `CHANGELOG_REPO`; set them as Workers vars or secrets.

| Key | Default | Meaning |
|---|---|---|
| `CHANGELOG_REPO` | — (required) | `owner/name` of the repository to mirror |
| `CHANGELOG_SOURCE` | `github-releases` | `github-releases` or `changelog-md` |
| `CHANGELOG_PATH` | `CHANGELOG.md` | File to read, for `changelog-md` |
| `CHANGELOG_REF` | the default branch | Git ref for `changelog-md` |
| `CHANGELOG_TOKEN` | anonymous | GitHub token; raises the rate limit |
| `CHANGELOG_API_BASE` | `https://api.github.com` | Where GitHub's API lives (tests, GitHub Enterprise) |
| `CHANGELOG_INCLUDE_PRERELEASES` | `false` | Mirror prereleases too |
| `CHANGELOG_INCLUDE_DRAFTS` | `false` | Mirror drafts too |
| `CHANGELOG_LOCALE` | `en` | The locale the original notes are written in; reported in `rendering` |
| `CHANGELOG_CACHE_TTL_SECONDS` | `60` | The `KeyValue` read cache's TTL; `0` disables the cache |

A venture that only sets configuration and composes `Changelog::new()` is
complete — everything above can be configuration alone. The same settings
can be composed in code (`.repo("owner/name")`, `.locale("en")`, …);
configuration wins when a key is set.

`refresh` lives at `POST /v1/changelog/admin/refresh` — the admin-audience
action, behind `Authorization: Bearer <ADMIN_TOKEN>`. The `/admin/` path
prefix is a harness rule: core reserves admin-audience surface actions for
`/admin/*` paths.

It answers with what the pull did:

```json
{
  "ok": true,
  "fetched": 37,
  "inserted": 1,
  "updated": 2,
  "unchanged": 33,
  "skipped": 1,
  "removed": 0,
  "not_modified": false,
  "complete": true
}
```

`complete` says whether this fetch saw the **whole** source. It is `false`
when the releases walk hit the module's page cap (five pages of 100):
everything the pages that did arrive held is still inserted and updated,
but **nothing is pruned** — a capped walk cannot tell "upstream deleted
it" from "it is on a page we did not reach", so every stored row is kept,
the refresh logs a warning, and the mirror waits for a walk that sees the
end of the list to repair itself. A `304 Not Modified` refresh is always
`complete: true`: the shortcut is only ever taken on an etag a complete
single-page fetch stored, so "not modified" certifies the whole mirror,
not just page 1.

## What "verbatim" means

- A `github-releases` body comes from the Releases API and is stored
  **byte-for-byte**: what GitHub returned is what is served.
- The `changelog-md` source is parsed as text, not bytes: the file is
  split at `## ` headings, line endings are normalised to `\n` (a CRLF
  `CHANGELOG.md` is stored LF-normalised), and the whitespace at the edges
  of each section's body is trimmed.
- The split is textual all the way down: a `## ` heading inside a fenced
  code block is read as a section boundary, not as markdown. Keep `## `
  out of fenced blocks in `CHANGELOG.md`.

## Storage

Two tables, and neither holds anything about a person:

- `changelog_release` — one row per `(source, version)`. `body` keeps the
  upstream text (byte-for-byte for `github-releases`; line-ending
  normalised and edge-trimmed for `changelog-md`); `first_seen_at`
  survives every update, so a refresh never churns a row it does not have
  to touch. Rows upstream deleted are pruned only after a fetch that saw
  the whole list — never after a walk that hit the page cap.
- `changelog_source` — the etag, the cache generation and how the last
  refresh went. A failed refresh records its status and nothing else. The
  etag is stored only when the whole list fit one page: a page's etag
  describes that page's bytes, and a repository of more than one page
  could take an edit on a later page while page 1 stayed byte-identical,
  which a conditional request would then answer `304` to forever.

`source` is a stable identity string (`github-releases:owner/name`,
`changelog-md:owner/name:CHANGELOG.md@main`), so changing configuration
cannot silently mix two sources' rows.

## Compose it

```rust,ignore
use cratefield_module_changelog::Changelog;

let module = Changelog::new().repo("owner/name");
```

Requires the `Database`, `HttpClient` and `Clock` ports; uses `KeyValue`
when present to cache read responses (correctness never depends on it).

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
