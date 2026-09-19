//! `cratefield-adapter-sqlite-wasm`: the [`Database`](cratefield_core::Database)
//! port over **sqlite-wasm** (the official SQLite WebAssembly build) on the
//! **OPFS** origin-private file system — the browser sibling of
//! `cratefield-adapter-sqlite` (rusqlite, native only).
//!
//! # How it is wired
//!
//! The Rust side holds no JS handle. It calls a small JS bridge installed by
//! the host page/worker at `globalThis.__cratefieldSqlite`, which owns the
//! actual sqlite-wasm database (opened on an OPFS-backed VFS, in a dedicated
//! Worker so its OO1 API is synchronous). The bridge exposes three async
//! methods — `run(sql, params)`, `query(sql, params)`, `batch(items)` — and
//! this crate marshals sea-query values to/from JSON: the portable scalar
//! subset behaves identically to D1 and rusqlite (ADR 0004), while BLOBs use a
//! tagged base64 JSON encoding because this bridge's only crossing into JS is
//! a JSON string (see [`marshal`]). Reference bridge: `js/sqlite_bridge_demo.js`.
//!
//! Because the port is a zero-sized unit type that only calls free JS imports
//! (never storing a `JsValue`), it is trivially `Send + Sync`; JS futures are
//! awaited through `send_wrapper::SendWrapper` (sound on the single-threaded
//! isolate, ADR 0002), so this crate needs no `unsafe`.
//!
//! On non-wasm targets this crate is intentionally empty.

#![cfg_attr(docsrs, feature(doc_cfg))]

// Not wasm-gated: the marshalling is pure, so its tests run on the host
// (see the module docs for why it is `pub`).
pub mod marshal;

#[cfg(target_arch = "wasm32")]
mod imp;

#[cfg(target_arch = "wasm32")]
pub use imp::SqliteWasmDatabase;
