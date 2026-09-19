// Installs `globalThis.__cratefieldSqlite`, the bridge the wasm
// `cratefield-adapter-sqlite-wasm` calls. It is backed by the official
// sqlite-wasm build on an OPFS-backed VFS (opfs-sahpool: synchronous OPFS
// without COOP/COEP), so the database survives reloads.
//
// The three methods mirror the `Database` port: run (writes -> changed count),
// query (reads -> array of row objects), batch (one transaction).
//
// STATUS: written to the documented sqlite-wasm API; NOT yet run in a browser
// (see web/README.md). The exact opfs-sahpool entry points can shift between
// sqlite-wasm releases — pin the version you test with.

import sqlite3InitModule from
  'https://cdn.jsdelivr.net/npm/@sqlite.org/sqlite-wasm@3.50.1-build1/sqlite-wasm/jswasm/sqlite3.mjs';

export async function installSqliteBridge(filename = '/cratefield.sqlite3') {
  const sqlite3 = await sqlite3InitModule();

  let db;
  let persistent = false;
  try {
    // Persistent: OPFS synchronous-access-handle pool VFS. This needs
    // `createSyncAccessHandle`, which some contexts expose only in a Worker;
    // fall back rather than fail the whole boot when it is missing/throws.
    if (!sqlite3.installOpfsSAHPoolVfs) throw new Error('opfs-sahpool VFS not present');
    const poolUtil = await sqlite3.installOpfsSAHPoolVfs({ name: 'cratefield-opfs' });
    db = new poolUtil.OpfsSAHPoolDb(filename);
    persistent = true;
  } catch (err) {
    // Fallback: in-memory (does NOT persist across reloads).
    console.warn(`[cratefield] OPFS SAH pool unavailable (${err}); using in-memory DB (no persistence)`);
    db = new sqlite3.oo1.DB(filename, 'ct');
  }
  globalThis.__cratefieldPersistent = persistent;

  // BLOBs cross the Rust -> JS boundary as the tagged JSON object
  // `{"$bytes": "<base64>"}`, because the wasm bridge's only crossing is a
  // JSON string (see adapter-sqlite-wasm/src/marshal.rs) — raw binary cannot
  // survive it. Only an exact single-key `$bytes` object decodes: a TEXT value
  // that merely looks like the tag stays TEXT.
  const BYTES_TAG = '$bytes';

  function bindParam(param) {
    if (param === null || typeof param !== 'object' || Array.isArray(param)) return param;
    const keys = Object.keys(param);
    if (keys.length !== 1 || keys[0] !== BYTES_TAG || typeof param[BYTES_TAG] !== 'string') return param;
    const bin = atob(param[BYTES_TAG]);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) { bytes[i] = bin.charCodeAt(i); }
    return bytes;
  }

  const decodeParams = (params) => (params ?? []).map(bindParam);

  // sqlite-wasm hands BLOB columns back as Uint8Array (or ArrayBuffer); tag
  // them so they survive the JSON.stringify crossing back into Rust.
  function encodeRow(row) {
    const out = {};
    for (const key of Object.keys(row)) {
      const value = row[key];
      const bytes = value instanceof Uint8Array ? value
        : (value instanceof ArrayBuffer ? new Uint8Array(value) : null);
      if (bytes === null) { out[key] = value; continue; }
      let bin = '';
      // Chunked so a large blob cannot blow the call stack.
      for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      out[key] = { [BYTES_TAG]: btoa(bin) };
    }
    return out;
  }

  globalThis.__cratefieldSqlite = {
    async run(sql, params) {
      db.exec({ sql, bind: decodeParams(params) });
      return db.changes();
    },
    async query(sql, params) {
      const rows = [];
      db.exec({ sql, bind: decodeParams(params), rowMode: 'object', callback: (row) => rows.push(encodeRow(row)) });
      return rows;
    },
    async batch(items) {
      db.exec('BEGIN');
      try {
        for (const item of items) { db.exec({ sql: item.sql, bind: decodeParams(item.params) }); }
        db.exec('COMMIT');
      } catch (err) {
        try { db.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
        throw err;
      }
    },
  };
  return globalThis.__cratefieldSqlite;
}
