//! The per-tenant write ceiling, with the audit chain on (issue #156).
//!
//! One of the four numbers that issue asks for, and the only one that can be
//! measured without somewhere to deploy: it is a database question, not a
//! network one. The other three — cold start to first byte, warm read p99
//! from two regions, provisioning time — need a running venture, and
//! `docs/BENCHMARKS.md` records them as unmeasured rather than guessed.
//!
//! What it measures: single-row secret writes through `SecretStore`, each one
//! appending to the hash-chained audit log in the same database. That chain is
//! the reason the number is worth having — every write reads the previous
//! row's hash, so writes serialise, and "how fast can one tenant write"
//! is really "how fast can the chain extend".
//!
//! Run: `cargo run -p cratefield-bench-write-ceiling --release -- [samples]`

use std::sync::Arc;
use std::time::Instant;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::Database;
use cratefield_kms::{Dek, Kms, LocalFileKms};
use cratefield_secrets::{Actor, ChainAudit, SecretBytes, Secrets, StoreId, migrations};

fn main() {
    let samples: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(500);

    let kek = Dek::generate().expect("rng");
    let kms: Arc<dyn Kms> =
        Arc::new(LocalFileKms::from_key(kek, "bench-kek", "test").expect("not production"));
    let db = SqliteDatabase::in_memory().expect("in-memory db");
    db.apply_migrations("secrets", migrations().sqlite)
        .expect("schema applies");
    let db: Arc<dyn Database> = Arc::new(db);
    let id = StoreId::Tenant("bench".to_owned());
    let store = Secrets::new(kms)
        .with_audit(Arc::new(ChainAudit::new(id, Arc::clone(&db))))
        .tenant("bench", Arc::clone(&db))
        .expect("the bench store opens");
    let actor = Actor::new("bench").expect("named");

    pollster::block_on(async {
        // Warm: the first write provisions the data key, which is a
        // one-off cost and would otherwise land in sample one.
        store
            .put("warmup", &SecretBytes::from("v"), &actor)
            .await
            .expect("warmup write");

        let mut each = Vec::with_capacity(samples);
        let overall = Instant::now();
        for i in 0..samples {
            let name = format!("k{i}");
            let at = Instant::now();
            store
                .put(&name, &SecretBytes::from("value"), &actor)
                .await
                .expect("write");
            each.push(at.elapsed());
        }
        let wall = overall.elapsed();

        each.sort_unstable();
        // Integer percentile index. The float form reads better but needs a
        // cast back to usize that truncates and loses the sign in clippy's
        // eyes; `(len - 1) * pct / 100` is exact and picks the same element.
        let at = |pct: usize| each[(each.len() - 1) * pct / 100];
        let count = u32::try_from(samples).expect("sample count fits in u32");
        let throughput = f64::from(count) / wall.as_secs_f64();
        println!("samples          {samples}");
        println!("wall             {wall:?}");
        println!("throughput       {throughput:.0} writes/s");
        println!("p50              {:?}", at(50));
        println!("p99              {:?}", at(99));
        println!("max              {:?}", each[each.len() - 1]);
    });
}
