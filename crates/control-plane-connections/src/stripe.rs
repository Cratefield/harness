//! Connecting a venture's Stripe account by OAuth instead of by paste.
//!
//! The paste flow asks a customer to make an API key in the Stripe
//! dashboard, copy it here, then make a webhook endpoint, choose its
//! events, copy `whsec_…` here as well, and get the live/test mode right
//! for both. Every one of those steps is a place to make a mistake that
//! surfaces later as a payment that silently never arrives.
//!
//! This replaces the first half entirely and automates the second.
//!
//! **The connection holds no venture credential.** Stripe deprecated the
//! per-account `access_token`: the documented way to act for a connected
//! account is the platform's own secret key plus a `Stripe-Account`
//! header. So what the OAuth exchange yields and this module keeps is
//! `stripe_user_id` (`acct_…`) — an identifier, not a secret, recorded as
//! the connection's public hint. The paste flow it replaces put a live
//! API key in the tenant store; this one puts nothing there.
//!
//! The webhook signing secret is a real secret and is still stored, but
//! the customer never sees or handles it: it comes back from Stripe once,
//! at endpoint creation, and goes straight to the tenant store.
//!
//! # Two traps, both from Stripe's own reference
//!
//! An authorization code **expires in five minutes and is single-use**,
//! and "consuming an authorization code more than once revokes the
//! account connection". So [`StripeConnect::exchange_code`] must never be
//! retried: a retry does not fail, it disconnects the customer. The
//! bounded HTTP client (#136) refuses rather than retries, which is the
//! behaviour this needs, and the doc says so where someone might add one.
//!
//! `state` is Stripe's only CSRF affordance — "an arbitrary string value
//! we'll pass back to you". An arbitrary string a caller can forge is not
//! protection, so it is a signed, purpose-bound, short-lived token from
//! the harness key ring (#137), carrying the venture it was minted for.

use std::sync::Arc;

use cratefield_core::{HttpClient, Kid, Payload, Signer};

/// Stripe's OAuth authorize endpoint (Standard accounts).
const AUTHORIZE_URL: &str = "https://connect.stripe.com/oauth/authorize";
/// Stripe's OAuth token endpoint.
const TOKEN_URL: &str = "https://connect.stripe.com/oauth/token";
/// Stripe's webhook endpoint collection.
const WEBHOOKS_URL: &str = "https://api.stripe.com/v1/webhook_endpoints";

/// The purpose bound into the CSRF state token, so a token minted for
/// anything else — a confirm link, an admin session — cannot be replayed
/// as one (#137's rule).
pub const STATE_PURPOSE: &str = "connect-stripe-state";

/// How long a connect attempt may sit before its state stops verifying.
/// Stripe's own authorization code lasts five minutes; the window in
/// which a person clicks through an account form is longer, so this is
/// generous without being open-ended.
///
/// Applied by the signer's [`TokenPolicy`], not by this module: the
/// state is minted with no `exp` of its own and the policy ceiling is
/// its lifetime, the same shape the sidecar gateway token uses (#131).
/// A composition root wiring this builds its signer with
/// `TokenPolicy::default().with_max(STATE_PURPOSE, Some(STATE_TTL_SECS))`.
///
/// Taking a timestamp as an argument instead would be a footgun: `verify`
/// reads the signer's clock, so a caller passing a different notion of
/// now mints tokens that are already expired, which is exactly what the
/// first draft of this did.
///
/// [`TokenPolicy`]: cratefield_core::TokenPolicy
pub const STATE_TTL_SECS: u64 = 30 * 60;

/// The events a venture's payments module needs. Listing them rather
/// than subscribing to `*` keeps the endpoint's blast radius to what the
/// module actually handles, and makes a later addition a visible change.
pub const WEBHOOK_EVENTS: &[&str] = &[
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
    "checkout.session.async_payment_failed",
    "payment_intent.succeeded",
    "payment_intent.payment_failed",
    "charge.refunded",
];

/// What a completed connection yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeAccount {
    /// `acct_…`. An identifier, not a credential: it is the connection's
    /// public hint and is safe in the `connection` table and in logs.
    pub account_id: String,
    /// Whether the platform's access to this account is live-mode.
    pub livemode: bool,
}

/// A provisioned webhook endpoint. `signing_secret` is returned by
/// Stripe **only at creation**, so it is stored on the spot or lost.
#[derive(Debug, Clone)]
pub struct StripeWebhook {
    pub endpoint_id: String,
    pub signing_secret: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StripeError {
    /// The state did not verify: forged, expired, or for another venture.
    #[error("the connect state is not one this deployment minted for `{venture}`")]
    State { venture: String },
    /// Stripe refused. Carries Stripe's `error` code, never the body,
    /// which can echo request parameters.
    #[error("stripe refused the request: {code}")]
    Refused { code: String },
    /// The call did not complete.
    #[error("stripe could not be reached: {0}")]
    Transport(String),
    /// Stripe answered with something this code cannot read.
    #[error("stripe's answer was not the shape this expects: {0}")]
    Answer(String),
}

/// The platform's Stripe Connect application. `client_id` (`ca_…`) is
/// public — it appears in the authorize URL a browser follows.
pub struct StripeConnect {
    client_id: String,
    http: Arc<dyn HttpClient>,
    signer: Arc<dyn Signer>,
}

impl StripeConnect {
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        http: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            http,
            signer,
        }
    }

    /// The URL to send the customer's browser to, carrying a signed
    /// `state` bound to `venture`.
    ///
    /// `redirect_uri` must be one of the URIs registered in the platform's
    /// Stripe settings; Stripe refuses anything else, which is the
    /// property that stops an attacker redirecting the code to themselves.
    #[must_use]
    pub fn authorize_url(&self, venture: &str, redirect_uri: &str) -> String {
        let state = self.signer.sign(&Payload {
            purpose: STATE_PURPOSE.to_owned(),
            subject: venture.to_owned(),
            // No `exp`: the signer's policy ceiling is the lifetime
            // (see `STATE_TTL_SECS`).
            exp: None,
            kid: Kid::Cur,
        });
        format!(
            "{AUTHORIZE_URL}?response_type=code&client_id={}&scope=read_write&redirect_uri={}&state={}",
            urlencode(&self.client_id),
            urlencode(redirect_uri),
            urlencode(&state)
        )
    }

    /// The venture a callback's `state` was minted for, or `None`.
    ///
    /// Checked **before** the code is exchanged: the exchange is
    /// single-use and destructive on replay, so an unverified callback
    /// must never reach it.
    #[must_use]
    pub fn venture_for_state(&self, state: &str) -> Option<String> {
        self.signer
            .verify(state, STATE_PURPOSE)
            .map(|payload| payload.subject)
    }

    /// Turns the authorization code into an account id.
    ///
    /// # Never retry this
    ///
    /// Stripe: an authorization code "can only be used once", and
    /// "consuming an authorization code more than once revokes the
    /// account connection". A retry does not fail — it disconnects the
    /// customer. On any error, restart the flow from
    /// [`Self::authorize_url`].
    ///
    /// # Errors
    ///
    /// [`StripeError`].
    pub async fn exchange_code(
        &self,
        code: &str,
        platform_secret_key: &str,
    ) -> Result<StripeAccount, StripeError> {
        let body = format!("grant_type=authorization_code&code={}", urlencode(code));
        let answer = self
            .post(TOKEN_URL, platform_secret_key, None, body)
            .await?;
        Ok(StripeAccount {
            account_id: string_field(&answer, "stripe_user_id")?,
            livemode: answer
                .get("livemode")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// Creates the venture's webhook endpoint on the connected account
    /// and returns its signing secret.
    ///
    /// This is the step the paste flow made a person do by hand, and the
    /// one they most often did wrong — wrong URL, wrong events, or the
    /// secret copied from the other mode.
    ///
    /// # Errors
    ///
    /// [`StripeError`].
    pub async fn create_webhook(
        &self,
        account: &StripeAccount,
        webhook_url: &str,
        platform_secret_key: &str,
    ) -> Result<StripeWebhook, StripeError> {
        let mut body = format!("url={}", urlencode(webhook_url));
        for event in WEBHOOK_EVENTS {
            body.push_str("&enabled_events[]=");
            body.push_str(&urlencode(event));
        }
        let answer = self
            .post(
                WEBHOOKS_URL,
                platform_secret_key,
                Some(&account.account_id),
                body,
            )
            .await?;
        Ok(StripeWebhook {
            endpoint_id: string_field(&answer, "id")?,
            // Returned only at creation. Losing it means deleting the
            // endpoint and making another.
            signing_secret: string_field(&answer, "secret")?,
        })
    }

    /// One form POST to Stripe, authenticated as the platform, optionally
    /// acting for a connected account.
    async fn post(
        &self,
        url: &str,
        platform_secret_key: &str,
        on_behalf_of: Option<&str>,
        body: String,
    ) -> Result<serde_json::Value, StripeError> {
        // Stripe takes the secret key as HTTP basic auth with an empty
        // password (`-u sk_...:`).
        let basic = base64_standard(&format!("{platform_secret_key}:"));
        let mut request = http::Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(http::header::AUTHORIZATION, format!("Basic {basic}"));
        if let Some(account) = on_behalf_of {
            request = request.header("Stripe-Account", account);
        }
        let request = request
            .body(bytes::Bytes::from(body))
            .map_err(|err| StripeError::Transport(err.to_string()))?;

        let response = self
            .http
            .send(request)
            .await
            .map_err(|err| StripeError::Transport(err.to_string()))?;

        let parsed: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|err| StripeError::Answer(err.to_string()))?;

        if !response.status().is_success() {
            // Stripe's own error code, never the body: an error body
            // echoes request parameters, and one of ours is a secret key.
            let code = parsed
                .get("error")
                .and_then(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| string_field(value, "type").ok())
                })
                .unwrap_or_else(|| response.status().as_u16().to_string());
            return Err(StripeError::Refused { code });
        }
        Ok(parsed)
    }
}

fn string_field(value: &serde_json::Value, field: &str) -> Result<String, StripeError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| StripeError::Answer(format!("no `{field}` in the answer")))
}

/// Percent-encodes everything that is not unreserved, which is stricter
/// than necessary and never wrong.
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

fn base64_standard(raw: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
}

#[cfg(test)]
// The recorder below stores what it was asked to send. That is a test
// fixture, not request state (ADR 0007); the scoped allow follows the
// policy in the workspace clippy.toml, as core's sidecar tests do.
#[allow(clippy::disallowed_types)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use cratefield_core::{HmacSigner, HttpError};
    use std::sync::Mutex;

    const SECRET: &str = "a-harness-secret-long-enough-for-the-ring";
    const PLATFORM_KEY: &str = "sk_test_platform_key";

    /// Answers a scripted body and records what it was asked, so a test
    /// can assert on the request as well as the outcome.
    struct FakeHttp {
        status: u16,
        body: &'static str,
        seen: Mutex<Vec<http::Request<bytes::Bytes>>>,
    }

    impl FakeHttp {
        fn ok(body: &'static str) -> Arc<Self> {
            Arc::new(Self {
                status: 200,
                body,
                seen: Mutex::new(Vec::new()),
            })
        }
        fn failing(status: u16, body: &'static str) -> Arc<Self> {
            Arc::new(Self {
                status,
                body,
                seen: Mutex::new(Vec::new()),
            })
        }
        fn calls(&self) -> usize {
            self.seen.lock().expect("lock").len()
        }
    }

    #[async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: http::Request<bytes::Bytes>,
        ) -> Result<http::Response<bytes::Bytes>, HttpError> {
            self.seen.lock().expect("lock").push(request);
            Ok(http::Response::builder()
                .status(self.status)
                .body(bytes::Bytes::from_static(self.body.as_bytes()))
                .expect("builds"))
        }
    }

    /// The inverse of [`urlencode`], for asserting on a round trip.
    fn urldecode(raw: &str) -> String {
        let bytes = raw.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("ascii");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).expect("utf-8")
    }

    fn connect(http: Arc<dyn HttpClient>) -> StripeConnect {
        let signer: Arc<dyn Signer> =
            Arc::new(HmacSigner::new(SECRET, None).expect("secret is long enough"));
        StripeConnect::new("ca_test_client", http, signer)
    }

    #[test]
    fn the_authorize_url_carries_a_state_only_this_deployment_can_mint() {
        let http = FakeHttp::ok("{}");
        let connect = connect(http);
        let url = connect.authorize_url("acme", "https://control.example/cb");

        assert!(url.starts_with(AUTHORIZE_URL), "{url}");
        assert!(url.contains("response_type=code"), "{url}");
        assert!(url.contains("client_id=ca_test_client"), "{url}");
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fcontrol.example%2Fcb"),
            "the redirect is encoded: {url}"
        );

        // The state round-trips to the venture it was minted for — after
        // percent-decoding, which is what a browser and Stripe do before
        // handing the value back on the callback.
        let state = urldecode(url.split("state=").nth(1).expect("state present"));
        assert_eq!(connect.venture_for_state(&state).as_deref(), Some("acme"));
    }

    #[test]
    fn a_forged_or_foreign_state_does_not_verify() {
        let connect = connect(FakeHttp::ok("{}"));
        assert!(connect.venture_for_state("not-a-token").is_none());

        // A token this deployment minted for another purpose is not a
        // connect state, which is the whole point of binding the purpose.
        let other: Arc<dyn Signer> = Arc::new(HmacSigner::new(SECRET, None).expect("long enough"));
        let confirm = other.sign(&Payload {
            purpose: "confirm".to_owned(),
            subject: "acme".to_owned(),
            exp: None,
            kid: Kid::Cur,
        });
        assert!(
            connect.venture_for_state(&confirm).is_none(),
            "a confirm token must not pass as connect state"
        );

        // And one minted under a different secret does not verify either.
        let stranger: Arc<dyn Signer> = Arc::new(
            HmacSigner::new("a-completely-different-secret-of-length", None).expect("long enough"),
        );
        let forged = stranger.sign(&Payload {
            purpose: STATE_PURPOSE.to_owned(),
            subject: "acme".to_owned(),
            exp: None,
            kid: Kid::Cur,
        });
        assert!(connect.venture_for_state(&forged).is_none());
    }

    #[pollster::test]
    async fn the_exchange_keeps_an_account_id_and_no_credential() {
        let http = FakeHttp::ok(
            r#"{"stripe_user_id":"acct_123","livemode":true,
                "access_token":"sk_live_DEPRECATED","token_type":"bearer"}"#,
        );
        let connect = connect(Arc::clone(&http) as Arc<dyn HttpClient>);
        let account = connect
            .exchange_code("ac_code", PLATFORM_KEY)
            .await
            .expect("exchange succeeds");

        assert_eq!(account.account_id, "acct_123");
        assert!(account.livemode);

        // Stripe deprecated `access_token`, and this deliberately does not
        // read it: the account id is an identifier, so the connection
        // holds no venture credential at all.
        let seen = http.seen.lock().expect("lock");
        let sent = String::from_utf8_lossy(seen[0].body()).into_owned();
        assert!(sent.contains("grant_type=authorization_code"), "{sent}");
        assert!(sent.contains("code=ac_code"), "{sent}");
        assert_eq!(seen[0].uri(), TOKEN_URL);
    }

    #[pollster::test]
    async fn one_exchange_is_one_request() {
        // Stripe: consuming an authorization code twice *revokes the
        // account connection*. A retry here does not fail, it disconnects
        // the customer — so the count is the assertion.
        let http = FakeHttp::failing(400, r#"{"error":"invalid_grant"}"#);
        let connect = connect(Arc::clone(&http) as Arc<dyn HttpClient>);
        let err = connect
            .exchange_code("ac_used", PLATFORM_KEY)
            .await
            .expect_err("stripe refused");
        assert!(matches!(err, StripeError::Refused { .. }), "{err:?}");
        assert_eq!(http.calls(), 1, "a failed exchange must never be retried");
    }

    #[pollster::test]
    async fn a_refusal_reports_the_code_and_never_the_body() {
        // An error body echoes request parameters, and one of ours is the
        // platform secret key.
        let http = FakeHttp::failing(
            401,
            r#"{"error":"invalid_client","error_description":"sent with sk_test_platform_key"}"#,
        );
        let connect = connect(Arc::clone(&http) as Arc<dyn HttpClient>);
        let err = connect
            .exchange_code("ac_code", PLATFORM_KEY)
            .await
            .expect_err("refused");
        let shown = err.to_string();
        assert!(shown.contains("invalid_client"), "{shown}");
        assert!(
            !shown.contains(PLATFORM_KEY),
            "the platform key must not reach an error string: {shown}"
        );
    }

    #[pollster::test]
    async fn the_webhook_is_created_on_the_connected_account() {
        let http = FakeHttp::ok(
            r#"{"id":"we_123","secret":"whsec_abc","url":"https://acme.example/v1/payments/webhook"}"#,
        );
        let connect = connect(Arc::clone(&http) as Arc<dyn HttpClient>);
        let account = StripeAccount {
            account_id: "acct_123".to_owned(),
            livemode: true,
        };
        let hook = connect
            .create_webhook(
                &account,
                "https://acme.example/v1/payments/webhook",
                PLATFORM_KEY,
            )
            .await
            .expect("created");

        assert_eq!(hook.endpoint_id, "we_123");
        assert_eq!(hook.signing_secret, "whsec_abc");

        let seen = http.seen.lock().expect("lock");
        // Acting *for* the connected account is the `Stripe-Account`
        // header on the platform's own key — the pattern that replaced
        // the deprecated per-account token.
        assert_eq!(
            seen[0].headers().get("Stripe-Account").expect("header"),
            "acct_123"
        );
        let sent = String::from_utf8_lossy(seen[0].body()).into_owned();
        for event in WEBHOOK_EVENTS {
            assert!(
                sent.contains(&urlencode(event)),
                "the endpoint subscribes to {event}: {sent}"
            );
        }
        assert!(
            !sent.contains("enabled_events[]=*") && !sent.contains("%2A"),
            "never a wildcard subscription: {sent}"
        );
    }

    #[pollster::test]
    async fn an_answer_without_the_signing_secret_is_an_error_not_an_empty_secret() {
        // The secret comes back only at creation. Reading a missing one as
        // empty would store a secret that verifies nothing.
        let http = FakeHttp::ok(r#"{"id":"we_123"}"#);
        let connect = connect(http);
        let account = StripeAccount {
            account_id: "acct_1".to_owned(),
            livemode: false,
        };
        let err = connect
            .create_webhook(&account, "https://x.example/h", PLATFORM_KEY)
            .await
            .expect_err("no secret is an error");
        assert!(matches!(err, StripeError::Answer(_)), "{err:?}");
    }
}
