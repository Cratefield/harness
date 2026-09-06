//! Q4: argon2 cost measurement in `wrangler dev`.
//!
//! `POST /q4/argon2?m=<kib>&t=<iters>&p=<lanes>&n=<repeats>` hashes and
//! verifies one password with Argon2id at the given parameters and reports
//! the Worker-visible elapsed time. Wall time is measured from the client
//! too (`curl -w '%{time_total}'`), because `Date.now()` inside workerd is
//! frozen during pure CPU work; what the runtime reports as internal
//! elapsed can read as ~0.

use argon2::password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::Serialize;

pub const BENCH_PASSWORD: &str = "spike-bench-password- Presidential#Cargo7";
pub const BENCH_SALT: &[u8] = b"spike-fixed-salt-v1";

#[derive(Serialize, Debug)]
pub struct BenchResult {
    pub algorithm: &'static str,
    pub m_kib: u32,
    pub t_iters: u32,
    pub p_lanes: u32,
    pub repeats: u32,
    pub verify_ok: bool,
    pub internal_ms: f64,
}

pub fn run_bench(
    m_kib: u32,
    t_iters: u32,
    p_lanes: u32,
    repeats: u32,
    elapsed_ms: impl Fn() -> f64,
) -> Result<BenchResult, String> {
    let params = Params::new(m_kib, t_iters, p_lanes, None).map_err(|e| {
        format!("invalid Argon2id parameters m={m_kib} t={t_iters} p={p_lanes}: {e}")
    })?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let verifier = Argon2::default();

    let start = elapsed_ms();
    let mut verify_ok = false;
    for _ in 0..repeats.max(1) {
        let hash = hasher
            .hash_password_with_salt(BENCH_PASSWORD.as_bytes(), BENCH_SALT)
            .map_err(|e| format!("hash: {e}"))?;
        let phc = hash.to_string();
        let parsed = PasswordHash::new(&phc).map_err(|e| format!("reparse: {e}"))?;
        verifier
            .verify_password(BENCH_PASSWORD.as_bytes(), &parsed)
            .map_err(|e| format!("verify: {e}"))?;
        verify_ok = true;
    }
    let internal_ms = elapsed_ms() - start;

    Ok(BenchResult {
        algorithm: "Argon2id v19",
        m_kib,
        t_iters,
        p_lanes,
        repeats: repeats.max(1),
        verify_ok,
        internal_ms,
    })
}

/// The measured matrix. Memory tops out at 128 MiB: the local workerd
/// sandbox gets 128 MB, so anything larger OOMs before it gets slow.
pub const MATRIX: &[(u32, u32, u32)] = &[
    (19456, 2, 1), // OWASP minimal
    (19456, 3, 1),
    (32768, 2, 1),
    (47104, 1, 1), // OWASP tolerable
    (65536, 2, 1),
    (65536, 3, 1),
    (131072, 2, 1),
    (19456, 2, 2), // second lane: no extra cores on a Worker
];

#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> f64 {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64() * 1000.0
}

#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> f64 {
    worker::Date::now().as_millis() as f64
}
