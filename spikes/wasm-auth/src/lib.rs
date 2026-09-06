pub mod q2_webauthn;

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
        .run(req, env)
        .await
}
