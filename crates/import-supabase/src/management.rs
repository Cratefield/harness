//! The two Supabase Management API reads inspect makes, for what Postgres
//! cannot see: the Edge Functions and the auth configuration.
//!
//! Both are `GET`s over the runtime's `HttpClient` port. The auth
//! configuration carries provider client secrets and SMTP passwords; only
//! its `…_enabled` booleans are read, so nothing else in it can reach the
//! report.

use std::sync::Arc;

use bytes::Bytes;
use cratefield_core::HttpClient;
use serde_json::Value;

use crate::report::EdgeFunction;
use crate::secret::Secret;

/// The production Management API.
pub const DEFAULT_API_BASE: &str = "https://api.supabase.com";

/// A Management API client for one project.
pub struct ManagementApi {
    http: Arc<dyn HttpClient>,
    base: String,
    token: Secret,
}

/// What the auth configuration enables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// Sign-in providers, sorted (`email`, `google`, `phone`, `saml`, …).
    pub providers: Vec<String>,
    /// MFA methods, sorted (`totp`, `phone`, `web_authn`).
    pub mfa: Vec<String>,
}

/// A Management API failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementError {
    /// `401` or `403`: the token is wrong or lacks access to the project.
    Unauthorized(u16),
    /// Anything else, as text that never quotes the token.
    Failed(String),
}

impl std::fmt::Display for ManagementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized(status) => write!(
                f,
                "the Management API refused the token ({status}): it must be a personal access \
                 token with access to this project"
            ),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

impl ManagementApi {
    /// A client for `base` (normally [`DEFAULT_API_BASE`]).
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>, base: impl Into<String>, token: Secret) -> Self {
        Self {
            http,
            base: base.into().trim_end_matches('/').to_owned(),
            token,
        }
    }

    async fn get(&self, path: &str) -> Result<Value, ManagementError> {
        let request = http::Request::get(format!("{}{path}", self.base))
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", self.token.expose()),
            )
            .header(http::header::ACCEPT, "application/json")
            .body(Bytes::new())
            .map_err(|_| {
                ManagementError::Failed(format!("could not build the request for {path}"))
            })?;
        let response = self.http.send(request).await.map_err(|error| {
            ManagementError::Failed(format!(
                "GET {path} failed: {}",
                cratefield_core::scrub_text(&error.to_string())
            ))
        })?;
        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(ManagementError::Unauthorized(status));
        }
        if !response.status().is_success() {
            return Err(ManagementError::Failed(format!(
                "GET {path} answered {status}"
            )));
        }
        serde_json::from_slice(response.body())
            .map_err(|_| ManagementError::Failed(format!("GET {path} did not answer JSON")))
    }

    /// The project's Edge Functions, sorted by slug.
    ///
    /// # Errors
    ///
    /// [`ManagementError`] when the call fails or answers something else
    /// than a list.
    pub async fn edge_functions(
        &self,
        project_ref: &str,
    ) -> Result<Vec<EdgeFunction>, ManagementError> {
        let body = self
            .get(&format!("/v1/projects/{project_ref}/functions"))
            .await?;
        let Value::Array(items) = body else {
            return Err(ManagementError::Failed(
                "the functions list was not a JSON array".to_owned(),
            ));
        };
        let text =
            |item: &Value, key: &str| item.get(key).and_then(Value::as_str).map(str::to_owned);
        let mut functions: Vec<EdgeFunction> = items
            .iter()
            .filter_map(|item| {
                let slug = text(item, "slug")?;
                Some(EdgeFunction {
                    name: text(item, "name").unwrap_or_else(|| slug.clone()),
                    status: text(item, "status").unwrap_or_default(),
                    verify_jwt: item.get("verify_jwt").and_then(Value::as_bool),
                    slug,
                })
            })
            .collect();
        functions.sort_by(|a, b| a.slug.cmp(&b.slug));
        Ok(functions)
    }

    /// The providers and MFA methods the auth configuration enables. Only
    /// `external_<provider>_enabled`, `saml_enabled` and
    /// `mfa_<method>_enroll_enabled` booleans are read.
    ///
    /// # Errors
    ///
    /// [`ManagementError`] when the call fails or answers something else
    /// than an object.
    pub async fn auth_config(&self, project_ref: &str) -> Result<AuthConfig, ManagementError> {
        let body = self
            .get(&format!("/v1/projects/{project_ref}/config/auth"))
            .await?;
        let Value::Object(fields) = body else {
            return Err(ManagementError::Failed(
                "the auth configuration was not a JSON object".to_owned(),
            ));
        };
        let mut providers = Vec::new();
        let mut mfa = Vec::new();
        for (key, value) in &fields {
            if value.as_bool() != Some(true) {
                continue;
            }
            if let Some(provider) = key
                .strip_prefix("external_")
                .and_then(|rest| rest.strip_suffix("_enabled"))
            {
                providers.push(provider.to_owned());
            } else if key == "saml_enabled" {
                providers.push("saml".to_owned());
            } else if let Some(method) = key
                .strip_prefix("mfa_")
                .and_then(|rest| rest.strip_suffix("_enroll_enabled"))
            {
                mfa.push(method.to_owned());
            }
        }
        providers.sort();
        mfa.sort();
        Ok(AuthConfig { providers, mfa })
    }
}
