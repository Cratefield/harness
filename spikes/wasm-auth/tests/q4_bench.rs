use wasm_auth_spike::q4_bench;

#[test]
fn argon2_bench_runs_and_verifies_natively() {
    let result = q4_bench::run_bench(8192, 1, 1, 1, q4_bench::now_ms).expect("small bench runs");
    assert!(result.verify_ok);
    assert!(result.internal_ms >= 0.0);
}

#[test]
fn invalid_parameters_are_rejected() {
    let error = q4_bench::run_bench(1, 0, 0, 1, q4_bench::now_ms)
        .expect_err("parameters below the spec minimum must fail");
    assert!(
        error.contains("invalid Argon2id parameters"),
        "got: {error}"
    );
}
