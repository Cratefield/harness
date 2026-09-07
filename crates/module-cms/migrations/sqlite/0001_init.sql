-- A small content store. `cms_item` is the editable working copy, one row per
-- (collection, slug); `cms_revision` is the immutable, append-only history of
-- published versions. Content lives in the venture's own database, so it never
-- leaves the venture. All columns are TEXT (the portable subset; JSON is kept
-- as text in `data`).
CREATE TABLE cms_item (
    collection TEXT NOT NULL,
    slug       TEXT NOT NULL,
    title      TEXT NOT NULL DEFAULT '',
    body       TEXT NOT NULL DEFAULT '',
    data       TEXT NOT NULL DEFAULT '{}',  -- structured fields, JSON object
    status     TEXT NOT NULL,               -- 'draft' | 'published' | 'unpublished'
    version    INTEGER NOT NULL DEFAULT 0,   -- the currently-published revision, 0 = none
    updated_at TEXT NOT NULL,
    PRIMARY KEY (collection, slug)
);

-- One row per publish. Never updated or deleted while the item lives, so the
-- history of what was public is always recoverable.
CREATE TABLE cms_revision (
    id         TEXT PRIMARY KEY,
    collection TEXT NOT NULL,
    slug       TEXT NOT NULL,
    version    INTEGER NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    data       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX cms_revision_by_item ON cms_revision (collection, slug, version);
