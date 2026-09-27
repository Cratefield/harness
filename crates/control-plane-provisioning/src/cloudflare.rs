//! The first Cloudflare adapter for the [`Deployer`] port (issue #141):
//! the database step, done for real against the D1 api.
//!
//! This is the one step that is self-contained today — the worker step is
//! not, because nothing in the repository can produce Worker script bytes
//! yet — so it is the only step this wrapper claims. Every other step
//! delegates to the deployer underneath it, which at the bottom of the
//! control plane's composition is [`Unwired`] and refuses as before.
//!
//! # Ownership by name, not by table
//!
//! The venture's tenant id *is* its D1 database's name. That makes
//! Cloudflare's own list-by-name call both the existence check and the
//! ownership record: a database named `ten_x` in the account's list is
//! `ten_x`'s database, and a later run re-derives the same fact from the
//! same name. "Record resource ownership" therefore costs no new table,
//! column or migration, and no database id is kept — nothing downstream
//! asks a question a name cannot answer.
//!
//! # The credential it needs
//!
//! A scoped Cloudflare api token with the **D1:Edit** permission group,
//! granted at the *account* level, is sufficient — D1 is an account-level
//! product with no zone component, so nothing zone-scoped is required and
//! nothing broader than D1 should be granted. The token travels only in
//! the `Authorization` header of the two calls this adapter makes; it is
//! never placed in a [`DeployError`] message, which the engine records
//! against the venture and the screens render.
//!
//! [`Unwired`]: crate::Unwired

use std::sync::Arc;

use bytes::Bytes;
use cratefield_core::{HttpClient, HttpError};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use serde::de::DeserializeOwned;

use crate::{DeployError, Deployer};

/// The D1 api sits under the account, so the account id interpolates into
/// the path and the database name into the query string or the body.
const D1_API: &str = "https://api.cloudflare.com/client/v4/accounts";

/// Cloudflare's error code for "a database with this name already
/// exists": a create that lost a race with another run is told so by this
/// code, and it is the same success the port's "ensure" asks for.
const ALREADY_EXISTS: i64 = 7502;

/// The [`Deployer`] wrapper that makes the database step real:
/// `ensure_database` talks to Cloudflare's D1 api, every other step goes
/// to the deployer underneath.
///
/// With `credentials` of `None` — the unconfigured deployment — even the
/// database step goes to `inner` untouched, so a composition that was
/// never given Cloudflare credentials behaves exactly as it did before
/// this adapter existed. With credentials but no http client, the step
/// fails with the honest reason rather than pretending.
pub struct CloudflareDatabase<D> {
    /// The outbound port, carried from wherever the deployer is wired.
    http: Option<Arc<dyn HttpClient>>,
    /// `(account_id, api_token)`, or `None` when unconfigured.
    credentials: Option<(String, String)>,
    /// The deployer under this one: every step but the database's.
    inner: D,
}

impl<D> CloudflareDatabase<D> {
    /// Wrap `inner` so the database step runs for real against
    /// `credentials` of `Some((account_id, api_token))`, over the given
    /// http port. `credentials` of `None` is the unconfigured mode: every
    /// call, the database step included, delegates to `inner`.
    #[must_use]
    pub fn new(
        http: Option<Arc<dyn HttpClient>>,
        credentials: Option<(String, String)>,
        inner: D,
    ) -> Self {
        Self {
            http,
            credentials,
            inner,
        }
    }

    /// Reads `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` from the
    /// process environment; both present means configured, anything else
    /// means the unconfigured delegation mode. On Workers `std::env` has
    /// no variables at this layer, so a Worker composition that wants the
    /// real call reads its secret and builds the adapter directly with
    /// [`CloudflareDatabase::new`] instead — the same note `Resend`'s
    /// `from_env` carries.
    #[must_use]
    pub fn from_env(http: Option<Arc<dyn HttpClient>>, inner: D) -> Self {
        let credentials = match (
            std::env::var("CLOUDFLARE_ACCOUNT_ID"),
            std::env::var("CLOUDFLARE_API_TOKEN"),
        ) {
            (Ok(account_id), Ok(api_token)) => Some((account_id, api_token)),
            _ => None,
        };
        Self::new(http, credentials, inner)
    }
}

impl<D: Deployer> Deployer for CloudflareDatabase<D> {
    async fn build_artifact(&self, module_set: &str) -> Result<(), DeployError> {
        self.inner.build_artifact(module_set).await
    }

    /// List the account's D1 databases filtered by name, and create the
    /// tenant's only when no database of that exact name answers. Both
    /// halves are the "ensure": an existing database is a no-op, and a
    /// create that raced another run and lost is a success too, so a
    /// resume that re-touches the step cannot break anything.
    async fn ensure_database(&self, tenant: &str) -> Result<(), DeployError> {
        let Some((account_id, api_token)) = &self.credentials else {
            // Unconfigured: exactly the behavior the composition had
            // before this adapter was wired in.
            return self.inner.ensure_database(tenant).await;
        };
        let Some(http) = self.http.as_deref() else {
            return Err(DeployError::new(
                "the Cloudflare D1 credentials are configured, but the composition \
                 wired no http client to make the call with",
            ));
        };
        let base = format!("{D1_API}/{account_id}/d1/database");

        // A database of exactly this name in the account's own list **is**
        // the venture's database — the no-op half of "ensure" and the
        // ownership record in one call. The match is exact, so a name the
        // filter somehow missed can only lead to a create, never to a
        // false "already exists". (Tenant ids are ULID-shaped, so the
        // query value needs no percent-encoding.)
        let uri = format!("{base}?name={tenant}");
        let reply = call(http, api_token, Method::GET, &uri, None).await?;
        let listed: Envelope<Vec<D1Database>> = decode("listing the venture's databases", &reply)?;
        if !reply.status.is_success() || !listed.success {
            return Err(failed("listing the venture's databases", &reply));
        }
        if listed
            .result
            .unwrap_or_default()
            .iter()
            .any(|db| db.name == tenant)
        {
            return Ok(());
        }

        // Nothing by that name: create it. The name is the whole body —
        // Cloudflare assigns the id, and this step keeps nothing: the next
        // run re-derives everything from the name.
        let create = serde_json::to_vec(&CreateDatabase { name: tenant })
            .map_err(|err| DeployError::new(format!("cloudflare d1 create body: {err}")))?;
        let reply = call(
            http,
            api_token,
            Method::POST,
            &base,
            Some(Bytes::from(create)),
        )
        .await?;
        let created: Envelope<D1Database> = decode("creating the venture's database", &reply)?;
        // A create that lost a race comes back as error 7502, "already
        // exists" — the same success, as far as the port is concerned,
        // whatever status Cloudflare gave it.
        if created.errors.iter().any(|err| err.code == ALREADY_EXISTS) {
            return Ok(());
        }
        // Success is a 2xx reply wearing a success envelope — both halves,
        // the same bar the list above clears.
        if reply.status.is_success() && created.success {
            return Ok(());
        }
        Err(failed("creating the venture's database", &reply))
    }

    async fn ensure_worker(&self, tenant: &str, module_set: &str) -> Result<(), DeployError> {
        self.inner.ensure_worker(tenant, module_set).await
    }

    async fn apply_schema(&self, tenant: &str, module_set: &str) -> Result<(), DeployError> {
        self.inner.apply_schema(tenant, module_set).await
    }

    async fn seed_secrets(&self, tenant: &str) -> Result<(), DeployError> {
        self.inner.seed_secrets(tenant).await
    }

    async fn bind_route(&self, tenant: &str, subdomain: &str) -> Result<(), DeployError> {
        self.inner.bind_route(tenant, subdomain).await
    }

    async fn health_ok(&self, subdomain: &str) -> Result<bool, DeployError> {
        self.inner.health_ok(subdomain).await
    }
}

/// One reply from the Cloudflare api: the status and the body text.
struct Reply {
    status: StatusCode,
    body: String,
}

/// Sends one authenticated call and buffers the reply. The token goes
/// only into the `Authorization` header — every failure this returns
/// names the transport, never the credential.
async fn call(
    http: &dyn HttpClient,
    api_token: &str,
    method: Method,
    uri: &str,
    body: Option<Bytes>,
) -> Result<Reply, DeployError> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {api_token}"));
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    let request = builder.body(body.unwrap_or_default()).map_err(|err| {
        DeployError::new(format!("cloudflare d1 request could not be built: {err}"))
    })?;
    let response = http
        .send(request)
        .await
        .map_err(|err: HttpError| DeployError::new(err.to_string()))?;
    Ok(Reply {
        status: response.status(),
        body: String::from_utf8_lossy(response.body()).to_string(),
    })
}

/// The envelope every Cloudflare api reply wears: `success`, the errors
/// that made it false, and the result — `null` on a failed call, which is
/// why the result is an [`Option`] here rather than a bare `R`.
#[derive(serde::Deserialize)]
struct Envelope<R> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<R>,
}

/// One entry of Cloudflare's `errors` list.
#[derive(serde::Deserialize)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// A D1 database as the list reply carries it — only what the step reads:
/// the name. The reply's database id is deliberately not captured; the
/// name is the durable handle (see the module docs).
#[derive(serde::Deserialize)]
struct D1Database {
    #[serde(default)]
    name: String,
}

/// The body of a create call: the name is the whole request.
#[derive(serde::Serialize)]
struct CreateDatabase<'a> {
    name: &'a str,
}

/// The Cloudflare envelope of a reply, when the reply is one. Fails only
/// when the body is not the envelope at all — an edge-blocked HTML page
/// or similar — naming the status so the recorded reason still says what
/// came back.
fn decode<R: DeserializeOwned>(what: &str, reply: &Reply) -> Result<Envelope<R>, DeployError> {
    serde_json::from_str(&reply.body).map_err(|err| {
        DeployError::new(format!(
            "cloudflare d1 {what} returned {} with an unreadable body: {err}",
            reply.status
        ))
    })
}

/// The recorded failure for a reply that said no: the status and
/// Cloudflare's own explanation, never the credential.
fn failed(what: &str, reply: &Reply) -> DeployError {
    DeployError::new(format!(
        "cloudflare d1 {what} failed with {}: {}",
        reply.status,
        detail(&reply.body)
    ))
}

/// The human-readable part of a reply that went wrong: the envelope's
/// error list when there is one, the raw body when there is not. Either
/// way it is what Cloudflare itself sent — safe to record; the credential
/// never is.
fn detail(body: &str) -> String {
    match serde_json::from_str::<Envelope<serde::de::IgnoredAny>>(body) {
        Ok(envelope) if !envelope.errors.is_empty() => envelope
            .errors
            .iter()
            .map(|err| format!("{} (code {})", err.message, err.code))
            .collect::<Vec<_>>()
            .join("; "),
        _ => body.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Unwired;
    use cratefield_testing::FakeHttpClient;

    /// An obvious dummy — a real token must never be committed (and must
    /// never appear in an error message, which several tests assert).
    const TOKEN: &str = "test-token-that-must-never-appear-in-an-error";
    const ACCOUNT: &str = "acct_test";

    /// A reply carrying Cloudflare's envelope with `status`.
    fn replied(status: u16, body: &'static str) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .body(Bytes::from(body))
            .expect("static test response")
    }

    fn configured(http: &FakeHttpClient) -> CloudflareDatabase<Unwired> {
        CloudflareDatabase::new(
            Some(Arc::new(http.clone())),
            Some((ACCOUNT.to_owned(), TOKEN.to_owned())),
            Unwired,
        )
    }

    #[pollster::test]
    async fn an_unconfigured_adapter_delegates_and_never_touches_http() {
        let http = FakeHttpClient::scripted(vec![]);
        let deployer = CloudflareDatabase::new(Some(Arc::new(http.clone())), None, Unwired);

        // `Unwired` underneath refuses; the refusal passing through is the
        // proof of delegation.
        let err = deployer
            .ensure_database("ten_1")
            .await
            .expect_err("the inner deployer's refusal comes through");
        assert!(
            err.message.contains("no deployer is wired"),
            "the inner deployer answered, not this adapter: {err}"
        );
        assert!(
            http.captured().is_empty(),
            "an unconfigured adapter makes no request: {:?}",
            http.captured()
        );
    }

    #[pollster::test]
    async fn a_tenant_without_a_database_gets_one_created() {
        let http = FakeHttpClient::scripted(vec![
            Ok(replied(
                200,
                r#"{"success":true,"result":[],"errors":[],"messages":[]}"#,
            )),
            Ok(replied(
                200,
                r#"{"success":true,"result":{"uuid":"db_01h","name":"ten_1"},"errors":[],"messages":[]}"#,
            )),
        ]);
        let deployer = configured(&http);

        deployer.ensure_database("ten_1").await.expect("creates");

        let captured = http.captured();
        assert_eq!(captured.len(), 2, "one list, one create: {captured:?}");
        assert_eq!(captured[0].0, "GET", "the ask comes before the act");
        assert_eq!(
            captured[0].1,
            "https://api.cloudflare.com/client/v4/accounts/acct_test/d1/database?name=ten_1"
        );
        assert_eq!(captured[1].0, "POST");
        assert_eq!(
            captured[1].1,
            "https://api.cloudflare.com/client/v4/accounts/acct_test/d1/database"
        );
        assert_eq!(captured[1].2, r#"{"name":"ten_1"}"#);
    }

    #[pollster::test]
    async fn an_existing_database_is_a_no_op_and_no_create_is_sent() {
        let http = FakeHttpClient::scripted(vec![Ok(replied(
            200,
            r#"{"success":true,"result":[{"uuid":"db_01h","name":"ten_1"}],"errors":[],"messages":[]}"#,
        ))]);
        let deployer = configured(&http);

        deployer
            .ensure_database("ten_1")
            .await
            .expect("already there");

        let captured = http.captured();
        assert_eq!(
            captured.len(),
            1,
            "the create must not fire for a database the list answered: {captured:?}"
        );
    }

    #[pollster::test]
    async fn a_cloudflare_error_is_recorded_without_the_token() {
        let http = FakeHttpClient::scripted(vec![
            Ok(replied(
                200,
                r#"{"success":true,"result":[],"errors":[],"messages":[]}"#,
            )),
            Ok(replied(
                403,
                r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null,"messages":[]}"#,
            )),
        ]);
        let deployer = configured(&http);

        let err = deployer
            .ensure_database("ten_1")
            .await
            .expect_err("a refused create is a step failure");
        assert!(err.message.contains("Authentication error"), "{err}");
        assert!(err.message.contains("403"), "{err}");
        assert!(
            !err.message.contains(TOKEN),
            "the token must never surface in a recorded message: {err}"
        );
    }

    #[pollster::test]
    async fn a_create_that_lost_a_race_with_another_run_is_the_same_success() {
        let http = FakeHttpClient::scripted(vec![
            Ok(replied(
                200,
                r#"{"success":true,"result":[],"errors":[],"messages":[]}"#,
            )),
            Ok(replied(
                400,
                r#"{"success":false,"errors":[{"code":7502,"message":"database with name already exists"}],"result":null,"messages":[]}"#,
            )),
        ]);
        let deployer = configured(&http);

        deployer
            .ensure_database("ten_1")
            .await
            .expect("the database exists either way");
        assert_eq!(http.captured().len(), 2, "list, then the losing create");
    }

    #[pollster::test]
    async fn a_2xx_reply_without_a_success_envelope_is_still_a_failure() {
        let http = FakeHttpClient::scripted(vec![
            Ok(replied(
                200,
                r#"{"success":true,"result":[],"errors":[],"messages":[]}"#,
            )),
            Ok(replied(
                200,
                r#"{"success":false,"errors":[],"result":null,"messages":[]}"#,
            )),
        ]);
        let deployer = configured(&http);

        let err = deployer
            .ensure_database("ten_1")
            .await
            .expect_err("a reply that says no is no, whatever its status");
        assert!(err.message.contains("200"), "{err}");
        assert!(!err.message.contains(TOKEN), "{err}");
    }

    #[pollster::test]
    async fn a_transport_failure_is_a_recorded_error_not_a_panic() {
        let http = FakeHttpClient::scripted(vec![Err(HttpError::Transport(
            "connection refused".to_owned(),
        ))]);
        let deployer = configured(&http);

        let err = deployer
            .ensure_database("ten_1")
            .await
            .expect_err("fails cleanly");
        assert!(err.message.contains("connection refused"), "{err}");
        assert!(!err.message.contains(TOKEN), "never the credential: {err}");
    }

    #[pollster::test]
    async fn credentials_without_an_http_client_fail_honestly() {
        let deployer =
            CloudflareDatabase::new(None, Some((ACCOUNT.to_owned(), TOKEN.to_owned())), Unwired);

        let err = deployer
            .ensure_database("ten_1")
            .await
            .expect_err("configured but unwirable");
        assert!(err.message.contains("no http client"), "{err}");
        assert!(!err.message.contains(TOKEN), "{err}");
    }
}
