//! The `Database` blob round-trip contract (issue #39), asserted against
//! a live adapter rather than trusted from its docs. A database that
//! mangles bound bytes — trimming a NUL, re-encoding through text,
//! padding a base64 hop — cannot hold a ciphertext, a wrapped key or a
//! nonce.

use cratefield_core::{Database, Statement};

/// Proves `db` round-trips bound bytes exactly: a `Vec<u8>` bound as
/// `Value::Bytes` reads back byte-for-byte identical, and a NULL blob
/// reads back as no bytes. Runs its own probe table, so it can be called
/// against any adapter with a writable connection.
///
/// An adapter that stores blobs as text fails loudly here — the port's
/// answer to "bytes where supported" (issue #39).
///
/// # Panics
///
/// Panics when the blob contract is violated: the bound payload does not
/// read back exactly, a NULL blob reads back as bytes, or the probe
/// table cannot be created on the given connection.
pub async fn assert_blob_round_trips(db: &dyn Database) {
    // One DDL for both engines: Postgres spells the byte column BYTEA and
    // has no BLOB (the portability lint bans the token outright), while
    // SQLite accepts any declared type and stores a bound blob faithfully
    // under it — the same reason auth-core's Postgres migration
    // overrides only ever rename the byte columns.
    db.execute(&Statement::new(
        "CREATE TABLE IF NOT EXISTS blob_round_trip_probe \
         (id INTEGER PRIMARY KEY, payload BYTEA)",
    ))
    .await
    .expect("probe table");

    db.execute(&Statement::new("DELETE FROM blob_round_trip_probe"))
        .await
        .expect("clear probe");

    // Bytes that die in any text-encoding hop: a NUL (truncation bait),
    // 0xFF and 0xFE (invalid UTF-8 in any position), a stray continuation
    // byte 0x80, the broken pair 0xC3 0x28, and a newline (trim bait).
    // Eleven bytes — not a multiple of three, so a base64 round trip
    // would leave padding artefacts behind.
    let payload: Vec<u8> = vec![
        0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x80, 0xFE, 0xC3, 0x28, 0x0A,
    ];
    db.execute(&Statement::with_values(
        "INSERT INTO blob_round_trip_probe (id, payload) VALUES (?, ?)",
        vec![1_i32.into(), payload.clone().into()],
    ))
    .await
    .expect("bind the byte payload");

    // A NULL blob: `Value::Bytes(None)` binds as SQL NULL. The adapters
    // do not agree on how NULL is reported back — adapter-sqlite
    // flattens every SQL NULL to `Value::String(None)` (its
    // `sqlite_to_sea`), adapter-postgres uses the type-appropriate
    // `Value::Bytes(None)` — so the raw variant is not portable. What
    // every adapter must agree on is the typed read: no bytes came back.
    db.execute(&Statement::with_values(
        "INSERT INTO blob_round_trip_probe (id, payload) VALUES (?, ?)",
        vec![2_i32.into(), None::<Vec<u8>>.into()],
    ))
    .await
    .expect("bind a NULL blob");

    let stored = db
        .query(&Statement::with_values(
            "SELECT payload FROM blob_round_trip_probe WHERE id = ?",
            vec![1_i32.into()],
        ))
        .await
        .expect("read the payload back");
    let row = stored.first().expect("the payload row is visible");
    assert_eq!(
        row.get::<Vec<u8>>("payload"),
        Some(payload),
        "the bytes read back are exactly the bytes bound"
    );

    let nulled = db
        .query(&Statement::with_values(
            "SELECT payload FROM blob_round_trip_probe WHERE id = ?",
            vec![2_i32.into()],
        ))
        .await
        .expect("read the NULL blob back");
    let row = nulled.first().expect("the NULL row is visible");
    assert!(
        row.get::<Vec<u8>>("payload").is_none(),
        "a NULL blob reads back as no bytes, not as empty or garbage"
    );

    db.execute(&Statement::new("DELETE FROM blob_round_trip_probe"))
        .await
        .expect("clean probe");
}
