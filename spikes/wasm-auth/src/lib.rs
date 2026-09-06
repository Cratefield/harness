pub mod port;
pub mod q2_webauthn;
pub mod q3_oidc;
pub mod q4_bench;

use worker::{event, Context, Env, Request, Response, Result, Router};

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .post_async("/q2/verify-passkey", |mut req, _ctx| {
            Box::pin(async move {
                let fixture: q2_webauthn::PasskeyFixture = req.json().await?;
                match q2_webauthn::run_fixture(&fixture) {
                    Ok(verified) => Response::from_json(&serde_json::json!({
                        "verified": true,
                        "credential_id": verified.credential_id,
                        "sign_count": verified.sign_count,
                    })),
                    Err(reason) => Response::from_json(&serde_json::json!({
                        "verified": false,
                        "reason": reason,
                    })),
                }
            })
        })
        .get_async("/q3/oidc", |_req, _ctx| {
            Box::pin(async move {
                let client = q3_oidc::WorkerHttpClient {
                    intercept_fixtures: true,
                };
                let report = q3_oidc::run_oidc_flow(client, q3_oidc::worker_now).await;
                Response::from_json(&report)
            })
        })
        .post_async("/q4/argon2", |req, _ctx| {
            Box::pin(async move {
                let query: std::collections::HashMap<String, String> = req
                    .url()?
                    .query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                let m: u32 = query.get("m").and_then(|v| v.parse().ok()).unwrap_or(19456);
                let t: u32 = query.get("t").and_then(|v| v.parse().ok()).unwrap_or(2);
                let p: u32 = query.get("p").and_then(|v| v.parse().ok()).unwrap_or(1);
                let n: u32 = query.get("n").and_then(|v| v.parse().ok()).unwrap_or(1);
                match q4_bench::run_bench(m, t, p, n, q4_bench::now_ms) {
                    Ok(result) => Response::from_json(&result),
                    Err(reason) => Response::error(reason, 400),
                }
            })
        })
        .get_async("/q4/argon2/matrix", |_req, _ctx| {
            Box::pin(async move {
                let mut results = Vec::new();
                for &(m, t, p) in q4_bench::MATRIX {
                    match q4_bench::run_bench(m, t, p, 1, q4_bench::now_ms) {
                        Ok(result) => results.push(result),
                        Err(reason) => {
                            return Response::error(reason, 500);
                        }
                    }
                }
                Response::from_json(&results)
            })
        })
        .run(req, env)
        .await
}
