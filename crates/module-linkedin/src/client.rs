//! The LinkedIn client (issue #7): one place that knows the versioning rules,
//! the Rest.li dialect and the error shapes.
//!
//! Three request families, and only the first takes the version headers:
//!
//! | Host | Headers | Auth |
//! |---|---|---|
//! | `api.linkedin.com/rest/*` | `LinkedIn-Version`, `X-Restli-Protocol-Version` | bearer |
//! | `www.linkedin.com/oauth/v2/*` | form encoding, nothing else | client credentials in the body |
//! | the media upload host | none | bearer (images require it; videos forbid it) |
//!
//! There are **no inline retries**. The `Clock` port has `now()` and
//! `timeout_any()` and no sleep, and its default `timeout_any` runs a future
//! to completion, so a backoff built here would block the isolate and hang
//! tests. A 429 or a 5xx returns, the caller writes a `not_before`, and the
//! next cron pass is the timer.

use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, HttpError, retry_after};
use http::{Method, Request, Response, StatusCode, header};
use serde_json::Value;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

pub(crate) const API_HOST: &str = "https://api.linkedin.com";
pub(crate) const OAUTH_TOKEN_URL: &str = "https://www.linkedin.com/oauth/v2/accessToken";
pub(crate) const OAUTH_AUTHORIZE_URL: &str = "https://www.linkedin.com/oauth/v2/authorization";
const RESTLI_PROTOCOL: &str = "2.0.0";

/// What went wrong with a LinkedIn call, in the shape the callers actually
/// branch on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApiError {
    /// The network, or a port failure. Retryable.
    Transport(String),
    /// LinkedIn rejected the access token (HTTP 401). The **token layer**
    /// decides what that means: one refresh and a replay, and only then a
    /// reconnect. The client never flips an account itself; if it did, an
    /// access token that merely needed refreshing would become a forced
    /// re-consent.
    TokenRejected,
    /// A missing scope or a page role we do not hold (HTTP 403).
    Forbidden {
        code: String,
        message: String,
    },
    NotFound,
    /// Rate limited (HTTP 429), with `Retry-After` when LinkedIn (or a CDN
    /// in front of it) sent one — in either form (issue #278).
    RateLimited {
        retry_after: Option<Duration>,
    },
    /// LinkedIn's own failure (HTTP 5xx). Retryable.
    Server {
        status: u16,
        message: String,
    },
    /// Any other 4xx. Terminal, and the caller should record it.
    Client {
        status: u16,
        code: String,
        message: String,
    },
    /// A success whose body was not what the contract says.
    Decode(String),
}

impl ApiError {
    /// Whether waiting and trying again could plausibly work.
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(
            self,
            ApiError::Transport(_) | ApiError::RateLimited { .. } | ApiError::Server { .. }
        )
    }

    /// A short, stable code for the `error_code` column and for logs.
    pub(crate) fn code(&self) -> String {
        match self {
            ApiError::Transport(_) => "transport".to_owned(),
            ApiError::TokenRejected => "token_rejected".to_owned(),
            ApiError::Forbidden { .. } => "forbidden".to_owned(),
            ApiError::NotFound => "not_found".to_owned(),
            ApiError::RateLimited { .. } => "rate_limited".to_owned(),
            ApiError::Server { status, .. } => format!("server_{status}"),
            ApiError::Client { status, code, .. } => {
                if code.is_empty() {
                    format!("client_{status}")
                } else {
                    code.to_ascii_lowercase()
                }
            }
            ApiError::Decode(_) => "decode".to_owned(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Transport(detail) => write!(f, "transport: {detail}"),
            ApiError::TokenRejected => write!(f, "access token rejected"),
            ApiError::Forbidden { code, message } => write!(f, "forbidden ({code}): {message}"),
            ApiError::NotFound => write!(f, "not found"),
            ApiError::RateLimited { retry_after } => {
                write!(f, "rate limited (retry after {retry_after:?})")
            }
            ApiError::Server { status, message } => write!(f, "server {status}: {message}"),
            ApiError::Client {
                status,
                code,
                message,
            } => write!(f, "client {status} ({code}): {message}"),
            ApiError::Decode(detail) => write!(f, "unexpected response: {detail}"),
        }
    }
}

/// The token pair as LinkedIn returns it. `refresh_token_expires_in` is
/// carried through verbatim: the refresh TTL does not extend on use, so it
/// must never be recomputed locally.
#[derive(Debug, Clone)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub refresh_token_expires_in: Option<i64>,
    pub scope: String,
}

/// One `organizationAcls` element.
#[derive(Debug, Clone)]
pub(crate) struct AclEntry {
    pub organization_urn: String,
    pub role: String,
    pub role_assignee: Option<String>,
}

/// The organization fields the module stores.
#[derive(Debug, Clone)]
pub(crate) struct Organization {
    pub id: String,
    pub name: String,
    pub vanity_name: Option<String>,
    pub primary_type: String,
    pub parent_org_id: Option<String>,
    pub logo_urn: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct InitializedUpload {
    pub upload_url: String,
    pub image_urn: String,
}

/// A post as LinkedIn reports it back.
#[derive(Debug, Clone)]
pub(crate) struct PostView {
    pub urn: String,
    pub lifecycle_state: String,
    pub commentary: String,
    pub created_at_ms: i64,
}

pub(crate) struct Client<'a> {
    http: &'a dyn HttpClient,
    /// Read for the HTTP-date form of `Retry-After` (issue #278); the same
    /// clock every other part of the module already holds.
    clock: &'a dyn Clock,
    api_version: &'a str,
    access_token: Option<&'a str>,
    spent: AtomicU32,
}

impl<'a> Client<'a> {
    /// A client for the OAuth endpoints, which take no bearer and no version.
    pub(crate) fn anonymous(http: &'a dyn HttpClient, clock: &'a dyn Clock) -> Self {
        Self {
            http,
            clock,
            api_version: "",
            access_token: None,
            spent: AtomicU32::new(0),
        }
    }

    pub(crate) fn new(
        http: &'a dyn HttpClient,
        clock: &'a dyn Clock,
        api_version: &'a str,
        access_token: &'a str,
    ) -> Self {
        Self {
            http,
            clock,
            api_version,
            access_token: Some(access_token),
            spent: AtomicU32::new(0),
        }
    }

    /// Requests spent against the daily cap. Call sites flush this into
    /// `linkedin_request_budget` when their unit of work ends.
    pub(crate) fn spent(&self) -> u32 {
        self.spent.load(Ordering::Relaxed)
    }

    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, ApiError> {
        self.spent.fetch_add(1, Ordering::Relaxed);
        self.http.send(request).await.map_err(|err| match err {
            HttpError::Transport(detail) => ApiError::Transport(detail),
            // Port bounds (issue #136): the cap, the deadline and a
            // refused destination are all upstream transport failures to
            // a caller that only knows "LinkedIn's API is not answering".
            other => ApiError::Transport(other.to_string()),
        })
    }

    /// Builds a request against the versioned REST gateway. Every call
    /// carries both headers; LinkedIn treats a missing version as an error
    /// rather than defaulting to the newest.
    fn rest_request(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Vec<u8>>,
        restli_method: Option<&str>,
    ) -> Result<Request<Bytes>, ApiError> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{API_HOST}{path_and_query}"))
            .header("LinkedIn-Version", self.api_version)
            .header("X-Restli-Protocol-Version", RESTLI_PROTOCOL);
        if let Some(token) = self.access_token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(restli) = restli_method {
            builder = builder.header("X-RestLi-Method", restli);
        }
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        builder
            .body(Bytes::from(body.unwrap_or_default()))
            .map_err(|err| ApiError::Transport(err.to_string()))
    }

    /// Maps a response onto [`ApiError`]. Everything LinkedIn tells us about
    /// a failure is logged (`x-li-uuid`, its `serviceErrorCode`); the access
    /// token never is.
    fn check(&self, response: Response<Bytes>) -> Result<(Response<Bytes>, Value), ApiError> {
        let status = response.status();
        let trace = response
            .headers()
            .get("x-li-uuid")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let code = body
            .get("serviceErrorCode")
            .map(std::string::ToString::to_string)
            .or_else(|| body.get("code").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_default();

        if status.is_success() {
            return Ok((response, body));
        }

        tracing::warn!(
            status = status.as_u16(),
            service_error_code = %code,
            li_uuid = %trace,
            "linkedin call failed"
        );

        Err(match status {
            StatusCode::UNAUTHORIZED => ApiError::TokenRejected,
            StatusCode::FORBIDDEN => ApiError::Forbidden { code, message },
            StatusCode::NOT_FOUND => ApiError::NotFound,
            StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited {
                // One parser for both header forms (issue #214/#278); the
                // date form needs the clock the client is built with.
                retry_after: retry_after(response.headers(), self.clock),
            },
            other if other.is_server_error() => ApiError::Server {
                status: other.as_u16(),
                message,
            },
            other => ApiError::Client {
                status: other.as_u16(),
                code,
                message,
            },
        })
    }

    async fn rest_json(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Value>,
        restli_method: Option<&str>,
    ) -> Result<(Response<Bytes>, Value), ApiError> {
        let encoded = body.map(|value| serde_json::to_vec(&value).unwrap_or_default());
        let request = self.rest_request(method, path_and_query, encoded, restli_method)?;
        let response = self.send(request).await?;
        self.check(response)
    }

    // -----------------------------------------------------------------------
    // OAuth (issue #8, #9)

    async fn token_call(&self, form: String) -> Result<TokenResponse, ApiError> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(OAUTH_TOKEN_URL)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Bytes::from(form))
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        let response = self.send(request).await?;

        // The token endpoint answers 400 with an `error` / `error_description`
        // pair rather than the REST error shape, and the difference between
        // "your refresh token is dead" and "you forgot a parameter" lives in
        // that description. Callers need both, so it is carried through as a
        // Client error with the code intact.
        let status = response.status();
        let body: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
        if !status.is_success() {
            let code = body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let message = body
                .get("error_description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            return Err(match status {
                StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited {
                    retry_after: retry_after(response.headers(), self.clock),
                },
                other if other.is_server_error() => ApiError::Server {
                    status: other.as_u16(),
                    message,
                },
                other => ApiError::Client {
                    status: other.as_u16(),
                    code,
                    message,
                },
            });
        }

        let access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::Decode("token response has no access_token".to_owned()))?
            .to_owned();
        Ok(TokenResponse {
            access_token,
            expires_in: body.get("expires_in").and_then(Value::as_i64).unwrap_or(0),
            refresh_token: body
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(str::to_owned),
            refresh_token_expires_in: body.get("refresh_token_expires_in").and_then(Value::as_i64),
            scope: body
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        })
    }

    pub(crate) async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, ApiError> {
        let form = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
            form_encode(code),
            form_encode(redirect_uri),
            form_encode(client_id),
            form_encode(client_secret),
        );
        self.token_call(form).await
    }

    pub(crate) async fn refresh(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, ApiError> {
        let form = format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
            form_encode(refresh_token),
            form_encode(client_id),
            form_encode(client_secret),
        );
        self.token_call(form).await
    }

    // -----------------------------------------------------------------------
    // Organizations (issue #10)

    /// One page of the member's ACLs. The organization arrives under
    /// `organizationTarget` in some responses and `organization` in others;
    /// both spellings are documented and both are read.
    pub(crate) async fn member_acls(
        &self,
        start: u32,
        count: u32,
    ) -> Result<(Vec<AclEntry>, bool), ApiError> {
        let path = format!(
            "/rest/organizationAcls?q=roleAssignee&state=APPROVED&start={start}&count={count}"
        );
        let (_, body) = self
            .rest_json(Method::GET, &path, None, Some("FINDER"))
            .await?;
        let elements = body
            .get("elements")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let has_more = body
            .get("paging")
            .and_then(|paging| paging.get("links"))
            .and_then(Value::as_array)
            .is_some_and(|links| {
                links
                    .iter()
                    .any(|link| link.get("rel").and_then(Value::as_str) == Some("next"))
            });
        let entries = elements
            .iter()
            .filter_map(|element| {
                let organization = element
                    .get("organizationTarget")
                    .or_else(|| element.get("organization"))
                    .and_then(Value::as_str)?;
                Some(AclEntry {
                    organization_urn: organization.to_owned(),
                    role: element
                        .get("role")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    role_assignee: element
                        .get("roleAssignee")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })
            })
            .collect();
        Ok((entries, has_more))
    }

    /// Batch organization lookup. Partial failure is normal: the response
    /// carries per-id `statuses` and `errors`, and one 403 must not lose the
    /// rest of the batch.
    pub(crate) async fn organizations(
        &self,
        ids: &[String],
    ) -> Result<Vec<Organization>, ApiError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let path = format!("/rest/organizations?ids=List({})", ids.join(","));
        let (_, body) = self
            .rest_json(Method::GET, &path, None, Some("BATCH_GET"))
            .await?;
        let results = body
            .get("results")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Ok(results.values().filter_map(organization_from).collect())
    }

    /// The showcase pages under a company page. They come back as
    /// organizations with `primaryOrganizationType: BRAND`.
    pub(crate) async fn organizations_by_parent(
        &self,
        parent_urn: &str,
    ) -> Result<Vec<Organization>, ApiError> {
        let path = format!(
            "/rest/organizations?q=parentOrganization&parent={}",
            crate::urn::encode(parent_urn)
        );
        let (_, body) = self
            .rest_json(Method::GET, &path, None, Some("FINDER"))
            .await?;
        let elements = body
            .get("elements")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(elements.iter().filter_map(organization_from).collect())
    }

    // -----------------------------------------------------------------------
    // Images (issue #11)

    pub(crate) async fn initialize_image_upload(
        &self,
        owner_urn: &str,
    ) -> Result<InitializedUpload, ApiError> {
        let body = serde_json::json!({
            "initializeUploadRequest": { "owner": owner_urn }
        });
        let (_, response) = self
            .rest_json(
                Method::POST,
                "/rest/images?action=initializeUpload",
                Some(body),
                None,
            )
            .await?;
        let value = response
            .get("value")
            .ok_or_else(|| ApiError::Decode("initializeUpload has no value".to_owned()))?;
        let upload_url = value
            .get("uploadUrl")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::Decode("initializeUpload has no uploadUrl".to_owned()))?;
        let image_urn = value
            .get("image")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::Decode("initializeUpload has no image urn".to_owned()))?;
        Ok(InitializedUpload {
            upload_url: upload_url.to_owned(),
            image_urn: image_urn.to_owned(),
        })
    }

    /// Uploads the bytes to the URL `initializeUpload` handed back. This is
    /// a `PUT` to a different host, with the bearer token but none of the
    /// Rest.li headers. Image uploads require the token; video uploads
    /// forbid it, which is one more reason video is out of scope.
    pub(crate) async fn upload_image(
        &self,
        upload_url: &str,
        content_type: &str,
        bytes: Bytes,
    ) -> Result<(), ApiError> {
        let mut builder = Request::builder()
            .method(Method::PUT)
            .uri(upload_url)
            .header(header::CONTENT_TYPE, content_type);
        if let Some(token) = self.access_token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = builder
            .body(bytes)
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        let response = self.send(request).await?;
        self.check(response)?;
        Ok(())
    }

    /// `WAITING_UPLOAD`, `PROCESSING`, `AVAILABLE` or `PROCESSING_FAILED`.
    pub(crate) async fn image_status(&self, image_urn: &str) -> Result<String, ApiError> {
        let path = format!("/rest/images/{}", crate::urn::encode(image_urn));
        let (_, body) = self.rest_json(Method::GET, &path, None, None).await?;
        Ok(body
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned())
    }

    // -----------------------------------------------------------------------
    // Posts (issues #12, #13)

    /// Creates a post. The URN comes back in the `x-restli-id` response
    /// header, not in the body.
    pub(crate) async fn create_post(&self, body: Value) -> Result<String, ApiError> {
        let (response, _) = self
            .rest_json(Method::POST, "/rest/posts", Some(body), None)
            .await?;
        let urn = response
            .headers()
            .get("x-restli-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Decode("create returned no x-restli-id".to_owned()))?;
        // The URN goes straight into a request path afterwards, so it is
        // checked here rather than trusted because it arrived in a header.
        if !crate::urn::is_post_urn(&urn) {
            return Err(ApiError::Decode(format!(
                "create returned {urn:?}, which is not a share or ugcPost urn"
            )));
        }
        Ok(urn)
    }

    /// Reads a post as its author, which is the view that reports
    /// `PUBLISH_REQUESTED` and `PUBLISH_FAILED` rather than only what a
    /// reader can see.
    pub(crate) async fn get_post(&self, post_urn: &str) -> Result<PostView, ApiError> {
        let path = format!(
            "/rest/posts/{}?viewContext=AUTHOR",
            crate::urn::encode(post_urn)
        );
        let (_, body) = self.rest_json(Method::GET, &path, None, None).await?;
        post_view_from(&body).ok_or_else(|| ApiError::Decode("post response has no id".to_owned()))
    }

    /// Recent posts by one author. This is the reconciliation read: after a
    /// create whose response was lost, it answers "did that post actually
    /// happen".
    pub(crate) async fn posts_by_author(
        &self,
        author_urn: &str,
        count: u32,
    ) -> Result<Vec<PostView>, ApiError> {
        let path = format!(
            "/rest/posts?author={}&q=author&count={count}&sortBy=CREATED&viewContext=AUTHOR",
            crate::urn::encode(author_urn)
        );
        let (_, body) = self
            .rest_json(Method::GET, &path, None, Some("FINDER"))
            .await?;
        Ok(body
            .get("elements")
            .and_then(Value::as_array)
            .map(|elements| elements.iter().filter_map(post_view_from).collect())
            .unwrap_or_default())
    }

    /// A partial update. On LinkedIn's side this is a `POST` carrying
    /// `X-RestLi-Method: PARTIAL_UPDATE`, never an HTTP `PATCH`.
    pub(crate) async fn partial_update_post(
        &self,
        post_urn: &str,
        set: Value,
    ) -> Result<(), ApiError> {
        let path = format!("/rest/posts/{}", crate::urn::encode(post_urn));
        let body = serde_json::json!({ "patch": { "$set": set } });
        self.rest_json(Method::POST, &path, Some(body), Some("PARTIAL_UPDATE"))
            .await?;
        Ok(())
    }

    /// Deletion is idempotent on LinkedIn's side: an already-deleted post
    /// answers 204 too, so a lost response is not a problem.
    pub(crate) async fn delete_post(&self, post_urn: &str) -> Result<(), ApiError> {
        let path = format!("/rest/posts/{}", crate::urn::encode(post_urn));
        match self
            .rest_json(Method::DELETE, &path, None, Some("DELETE"))
            .await
        {
            Ok(_) | Err(ApiError::NotFound) => Ok(()),
            Err(other) => Err(other),
        }
    }
}

fn organization_from(value: &Value) -> Option<Organization> {
    let id = value
        .get("id")
        .and_then(|id| {
            id.as_i64()
                .map(|n| n.to_string())
                .or_else(|| id.as_str().map(str::to_owned))
        })
        .or_else(|| {
            value
                .get("$URN")
                .and_then(Value::as_str)
                .and_then(crate::urn::page_id)
        })?;
    let name = value
        .get("localizedName")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    Some(Organization {
        id,
        name,
        vanity_name: value
            .get("vanityName")
            .and_then(Value::as_str)
            .map(str::to_owned),
        primary_type: value
            .get("primaryOrganizationType")
            .and_then(Value::as_str)
            .unwrap_or("NONE")
            .to_owned(),
        parent_org_id: value
            .get("parentRelationship")
            .and_then(|parent| parent.get("parent"))
            .and_then(Value::as_str)
            .and_then(crate::urn::page_id),
        logo_urn: value
            .get("logoV2")
            .and_then(|logo| logo.get("original"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn post_view_from(value: &Value) -> Option<PostView> {
    let urn = value.get("id").and_then(Value::as_str)?;
    Some(PostView {
        urn: urn.to_owned(),
        lifecycle_state: value
            .get("lifecycleState")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        commentary: value
            .get("commentary")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        created_at_ms: value
            .get("createdAt")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
    })
}

/// `application/x-www-form-urlencoded` escaping for the OAuth bodies. Small
/// and explicit rather than a dependency: these are the only form bodies the
/// module ever sends.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            other => {
                const HEX: [u8; 16] = *b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[usize::from(other >> 4)] as char);
                out.push(HEX[usize::from(other & 0x0f)] as char);
            }
        }
    }
    out
}

/// The authorization URL a page administrator opens.
pub(crate) fn authorize_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    format!(
        "{OAUTH_AUTHORIZE_URL}?response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
        form_encode(client_id),
        form_encode(redirect_uri),
        form_encode(state),
        form_encode(&crate::SCOPES.join(" ")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding_escapes_what_matters() {
        assert_eq!(form_encode("a b"), "a+b");
        assert_eq!(form_encode("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        assert_eq!(form_encode("plain-value_1.~"), "plain-value_1.~");
    }

    #[test]
    fn authorize_url_carries_the_compiled_in_scopes() {
        let url = authorize_url("client", "https://api.test/v1/linkedin/callback", "st.at.e");
        assert!(url.starts_with(OAUTH_AUTHORIZE_URL));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapi.test%2Fv1%2Flinkedin%2Fcallback"));
        assert!(url.contains("state=st.at.e"));
        assert!(url.contains("rw_organization_admin"));
        assert!(url.contains("w_organization_social"));
        assert!(!url.contains("openid"), "OIDC scopes were cut deliberately");
    }

    #[test]
    fn errors_classify_into_retryable_and_terminal() {
        assert!(ApiError::Transport("dns".into()).is_retryable());
        assert!(
            ApiError::RateLimited {
                retry_after: Some(Duration::from_secs(30))
            }
            .is_retryable()
        );
        assert!(
            ApiError::Server {
                status: 503,
                message: String::new()
            }
            .is_retryable()
        );
        assert!(!ApiError::TokenRejected.is_retryable());
        assert!(
            !ApiError::Client {
                status: 422,
                code: "UNPROCESSABLE_ENTITY".into(),
                message: String::new()
            }
            .is_retryable()
        );
    }

    #[test]
    fn organization_parses_a_showcase_with_its_parent() {
        let value = serde_json::json!({
            "id": 89_758_488_i64,
            "localizedName": "Internal_EI_Demo",
            "vanityName": "internal-ei-demo",
            "primaryOrganizationType": "BRAND",
            "parentRelationship": { "parent": "urn:li:organization:79988552" },
            "logoV2": { "original": "urn:li:digitalmediaAsset:C4D0" }
        });
        let organization = organization_from(&value).expect("parses");
        assert_eq!(organization.id, "89758488");
        assert_eq!(organization.primary_type, "BRAND");
        assert_eq!(organization.parent_org_id.as_deref(), Some("79988552"));
        assert_eq!(
            organization.logo_urn.as_deref(),
            Some("urn:li:digitalmediaAsset:C4D0")
        );
    }

    /// A frozen clock, so the HTTP-date form of `Retry-After` has a
    /// deterministic delta.
    struct FixedClock(time::OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> time::OffsetDateTime {
            self.0
        }
    }

    /// Never called: `check` is exercised on a response built in the test.
    struct NoHttp;

    #[async_trait::async_trait]
    impl HttpClient for NoHttp {
        async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
            unreachable!("no network in this test")
        }
    }

    #[test]
    fn rate_limited_reads_the_http_date_form() {
        // A CDN in front of LinkedIn answers with a date (issue #278): one
        // hour from the client's clock, not `None`.
        let at = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid");
        let format = time::format_description::parse_borrowed::<2>(
            "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
        )
        .expect("valid format");
        let date = (at + time::Duration::seconds(3600))
            .format(&format)
            .expect("formats");
        let response = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(header::RETRY_AFTER, date)
            .body(Bytes::new())
            .expect("builds");
        let clock = FixedClock(at);
        let client = Client::anonymous(&NoHttp, &clock);
        match client.check(response) {
            Err(ApiError::RateLimited { retry_after }) => {
                assert_eq!(retry_after, Some(Duration::from_secs(3600)));
            }
            other => panic!("wrong result: {other:?}"),
        }
    }
}
