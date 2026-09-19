-- The changelog mirror. `changelog_release` holds releases as upstream
-- published them — the author's own markdown, verbatim — and nothing about a
-- person. All columns are TEXT and 0/1 INTEGER flags (the portable subset,
-- ADR 0004); timestamps are ISO-8601 strings, empty when upstream has none.
CREATE TABLE IF NOT EXISTS changelog_release (
    source        TEXT NOT NULL,              -- stable identity of the configured source
    version       TEXT NOT NULL,              -- the tag or heading, verbatim (`v1.2.0`)
    title         TEXT NOT NULL DEFAULT '',
    body          TEXT NOT NULL DEFAULT '',   -- the author's original markdown, verbatim
    url           TEXT NOT NULL DEFAULT '',
    published_at  TEXT NOT NULL DEFAULT '',   -- RFC 3339; '' when upstream has no date
    prerelease    INTEGER NOT NULL DEFAULT 0, -- 0/1, never a BOOLEAN
    draft         INTEGER NOT NULL DEFAULT 0, -- 0/1
    first_seen_at TEXT NOT NULL,              -- when this row first mirrored upstream
    updated_at    TEXT NOT NULL,              -- when the upstream-derived fields last moved
    PRIMARY KEY (source, version)
);

-- The read path's order, newest first, is exactly this index.
CREATE INDEX IF NOT EXISTS changelog_release_by_published
    ON changelog_release (source, published_at, version);

-- One row per configured source: the etag of the last full fetch, the cache
-- generation current at that fetch, and how the last attempt went.
CREATE TABLE IF NOT EXISTS changelog_source (
    source            TEXT PRIMARY KEY,
    etag              TEXT NOT NULL DEFAULT '',
    generation        TEXT NOT NULL DEFAULT '',
    last_refreshed_at TEXT NOT NULL DEFAULT '',
    last_status       TEXT NOT NULL DEFAULT ''
);
