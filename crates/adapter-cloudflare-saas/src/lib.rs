//! `cratefield-adapter-cloudflare-saas`: the [`CustomHostnames`] port over
//! the Cloudflare for [`SaaS`](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/)
//! custom-hostnames API (issue #590). Uses the runtime's [`HttpClient`]
//! port — no `reqwest`, no vendor SDK — so the same adapter runs on Workers
//! (`worker::Fetch`) and natively, and inherits that port's destination
//! vetting, deadline and response-size caps.
//!
//! **Degraded mode.** With no zone or token configured the adapter answers
//! [`CustomHostnameError::NotConfigured`] from every method without any
//! network call, and a hostname the port would never send — an apex, an IP
//! literal, a wildcard, a name inside the deployment's own zone — is
//! [`CustomHostnameError::Refused`] before any request leaves the process.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    CertificateStatus, CustomHostname, CustomHostnameError, CustomHostnames, DnsRecordType,
    HostnameClaim, HttpClient, ProviderStatus, Validation, check_hostname, scrub_text,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use std::sync::Arc;

/// The environment variable [`CloudflareSaas::from_env`] reads the zone id
/// from.
pub const ZONE_ID_VAR: &str = "CF_SAAS_ZONE_ID";
/// The environment variable [`CloudflareSaas::from_env`] reads the zone name
/// from.
pub const ZONE_NAME_VAR: &str = "CF_SAAS_ZONE_NAME";
/// The environment variable [`CloudflareSaas::from_env`] reads the API token
/// from.
pub const API_TOKEN_VAR: &str = "CF_SAAS_API_TOKEN";
/// The environment variable [`CloudflareSaas::from_env`] reads the `CNAME`
/// target from.
pub const CNAME_TARGET_VAR: &str = "CF_SAAS_CNAME_TARGET";

/// The Cloudflare API v4 base every request goes to.
const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// The certificate type Cloudflare for `SaaS` issues for a custom hostname:
/// Domain Validation.
const CERTIFICATE_TYPE: &str = "dv";

/// The minimum TLS version every certificate is asked to allow.
const MIN_TLS_VERSION: &str = "1.2";

/// Where the deployment's Cloudflare for `SaaS` zone lives, and the token
/// used to claim hostnames in it.
#[derive(Clone)]
pub struct CloudflareSaasConfig {
    /// The zone's id, from the Cloudflare dashboard.
    pub zone_id: String,
    /// The zone's own name (e.g. `cratefield.app`). [`check_hostname`]
    /// refuses any claimed hostname inside it.
    pub zone_name: String,
    /// A scoped API token with "SSL and Certificates: Edit" on this one
    /// zone. Never logged or formatted.
    pub api_token: String,
    /// The record a customer points their `CNAME` at, shown while the
    /// hostname is not yet live. `None` omits the `CNAME` hint from
    /// [`CustomHostname::validation`].
    pub cname_target: Option<String>,
}

impl CloudflareSaasConfig {
    /// The config the four values describe, or `None` when a required one
    /// (`zone_id`, `zone_name`, `api_token`) is missing or empty. The pure
    /// core of [`CloudflareSaas::from_env`], split out so it is testable
    /// without mutating the process environment (edition 2024 makes
    /// `std::env::set_var` unsafe).
    #[must_use]
    pub fn from_vars(
        zone_id: Option<String>,
        zone_name: Option<String>,
        api_token: Option<String>,
        cname_target: Option<String>,
    ) -> Option<Self> {
        let zone_id = non_empty(zone_id)?;
        if !is_safe_zone_id(&zone_id) {
            return None;
        }
        Some(Self {
            zone_id,
            zone_name: non_empty(zone_name)?,
            api_token: non_empty(api_token)?,
            cname_target: non_empty(cname_target),
        })
    }
}

/// `Some(value)` only when `value` is present and not blank.
fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

/// The zone id is interpolated into a URL path, so only the characters
/// Cloudflare uses for one (ASCII alphanumerics; in practice 32 hex
/// characters) are accepted. Anything else — a slash, a dot-segment, an
/// empty string — is a misconfiguration, not a path to build.
fn is_safe_zone_id(zone_id: &str) -> bool {
    !zone_id.is_empty()
        && zone_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

/// A provider-returned id, read from the wire and put into a URL path.
/// Only the characters a Cloudflare id uses (`[A-Za-z0-9-]`) are accepted;
/// anything else is a `Provider` error rather than a request to a path the
/// provider did not name.
fn checked_id(id: &str) -> Result<&str, CustomHostnameError> {
    if !id.is_empty()
        && id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        Ok(id)
    } else {
        Err(CustomHostnameError::Provider(format!(
            "the provider returned an id that is not a safe path segment: {id:?}"
        )))
    }
}

/// Redacts the token: this `Debug` never prints `api_token`'s value, so a
/// config logged by accident cannot leak it.
impl std::fmt::Debug for CloudflareSaasConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareSaasConfig")
            .field("zone_id", &self.zone_id)
            .field("zone_name", &self.zone_name)
            .field("api_token", &"[redacted]")
            .field("cname_target", &self.cname_target)
            .finish()
    }
}

/// The [`CustomHostnames`] port over Cloudflare for `SaaS` custom hostnames.
pub struct CloudflareSaas {
    http: Arc<dyn HttpClient>,
    config: Option<CloudflareSaasConfig>,
}

/// Redacts the token through [`CloudflareSaasConfig`]'s own `Debug`.
impl std::fmt::Debug for CloudflareSaas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareSaas")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CloudflareSaas {
    /// Claims hostnames in `config.zone_id` with `config.api_token`. A zone
    /// id that is not safe to interpolate into a URL path degrades the
    /// adapter to [`CustomHostnameError::NotConfigured`] — with a warning
    /// naming the variable, never the token.
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>, config: CloudflareSaasConfig) -> Self {
        if !is_safe_zone_id(&config.zone_id) {
            tracing::warn!(
                provider = "cloudflare-saas",
                variable = ZONE_ID_VAR,
                "the zone id is not alphanumeric; the adapter answers NotConfigured"
            );
            return Self { http, config: None };
        }
        Self {
            http,
            config: Some(config),
        }
    }

    /// An adapter that answers [`CustomHostnameError::NotConfigured`] from
    /// every method without any network call.
    #[must_use]
    pub fn not_configured(http: Arc<dyn HttpClient>) -> Self {
        Self { http, config: None }
    }

    /// Reads [`ZONE_ID_VAR`], [`ZONE_NAME_VAR`] and [`API_TOKEN_VAR`]
    /// (required, non-empty) and [`CNAME_TARGET_VAR`] (optional) from the
    /// process environment; any missing required value yields the
    /// `not_configured` adapter. On Workers, read the secrets from the
    /// venture's `Env` and call [`CloudflareSaas::new`] instead (`std::env`
    /// has no Workers vars).
    #[must_use]
    pub fn from_env(http: Arc<dyn HttpClient>) -> Self {
        let config = CloudflareSaasConfig::from_vars(
            std::env::var(ZONE_ID_VAR).ok(),
            std::env::var(ZONE_NAME_VAR).ok(),
            std::env::var(API_TOKEN_VAR).ok(),
            std::env::var(CNAME_TARGET_VAR).ok(),
        );
        Self { http, config }
    }

    /// Whether a zone and token are configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.config.is_some()
    }

    /// The configured zone and token, or [`CustomHostnameError::NotConfigured`]
    /// (logged, without the token) when the adapter is degraded.
    fn require_config(&self) -> Result<&CloudflareSaasConfig, CustomHostnameError> {
        self.config.as_ref().ok_or_else(|| {
            tracing::info!(
                provider = "cloudflare-saas",
                outcome = "not_configured",
                "custom hostname outcome"
            );
            CustomHostnameError::NotConfigured
        })
    }

    /// Sends one request and returns the status and the body as text. The
    /// token travels in the `Authorization` header and nowhere else.
    async fn send(
        &self,
        config: &CloudflareSaasConfig,
        method: http::Method,
        uri: String,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, String), CustomHostnameError> {
        let token = &config.api_token;
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        let request = builder
            .body(Bytes::from(body.unwrap_or_default()))
            .map_err(|err| CustomHostnameError::Transport(err.to_string()))?;
        let response = self
            .http
            .send(request)
            .await
            .map_err(|err| CustomHostnameError::Transport(err.to_string()))?;
        let status = response.status();
        let text = String::from_utf8_lossy(response.body()).to_string();
        Ok((status, text))
    }

    /// The provider's error as a port error. The documented provider codes
    /// name the condition more precisely than the bare status, so they are
    /// read first; a 403 that carries a quota code (1404/1405) is a
    /// `Rejected` — the request is understood and refused, not unauthorised.
    fn map_error(status: StatusCode, errors: &[ApiError], body: &str) -> CustomHostnameError {
        let code = errors.first().map(|error| error.code);
        if status == StatusCode::FORBIDDEN && matches!(code, Some(1404 | 1405)) {
            return CustomHostnameError::Rejected(Self::detail(errors, body));
        }
        match code {
            Some(1406) => return CustomHostnameError::AlreadyExists,
            Some(1436) => return CustomHostnameError::NotFound,
            Some(1403 | 1000..=1005 | 10000 | 9109) => return CustomHostnameError::Unauthorized,
            _ => {}
        }
        match status {
            StatusCode::CONFLICT => CustomHostnameError::AlreadyExists,
            StatusCode::NOT_FOUND => CustomHostnameError::NotFound,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => CustomHostnameError::Unauthorized,
            StatusCode::TOO_MANY_REQUESTS => CustomHostnameError::RateLimited,
            status if status.is_client_error() => {
                CustomHostnameError::Rejected(Self::detail(errors, body))
            }
            _ => CustomHostnameError::Provider(Self::detail(errors, body)),
        }
    }

    /// The provider's words: the first error as `<code>: <message>`, the raw
    /// body when the envelope carried no error, or a placeholder when both
    /// are empty. `Display` scrubs a bearer token out of whatever this
    /// returns.
    fn detail(errors: &[ApiError], body: &str) -> String {
        match errors.first() {
            Some(error) if !error.message.is_empty() => {
                let code = error.code;
                let message = &error.message;
                format!("{code}: {message}")
            }
            Some(error) => error.code.to_string(),
            None => {
                let trimmed = body.trim();
                if trimmed.is_empty() {
                    "the provider sent no error detail".to_owned()
                } else {
                    trimmed.to_owned()
                }
            }
        }
    }

    /// The errors array of an error envelope, best-effort: a body that does
    /// not parse is reported by its raw text instead.
    fn parse_errors(body: &str) -> Vec<ApiError> {
        match serde_json::from_str::<Envelope<serde_json::Value>>(body) {
            Ok(envelope) => envelope.errors,
            Err(_) => Vec::new(),
        }
    }

    /// A non-success response as a port error.
    fn error_from(status: StatusCode, body: &str) -> CustomHostnameError {
        Self::map_error(status, &Self::parse_errors(body), body)
    }

    /// Looks a hostname up through the list endpoint, one page of 50. Only
    /// a wire entry whose `hostname` equals `hostname` exactly is a match;
    /// when the page holds no such entry but the filter matched further
    /// pages, the lookup fails closed rather than guessing.
    async fn find(
        &self,
        config: &CloudflareSaasConfig,
        hostname: &str,
    ) -> Result<Option<WireHostname>, CustomHostnameError> {
        let collection = collection_uri(&config.zone_id);
        let uri = format!("{collection}?hostname={hostname}&per_page=50");
        let (status, text) = self.send(config, http::Method::GET, uri, None).await?;
        if !status.is_success() {
            return Err(Self::error_from(status, &text));
        }
        let envelope: Envelope<Vec<WireHostname>> =
            serde_json::from_str(&text).map_err(|err| parse_error(&err))?;
        if !envelope.success {
            return Err(CustomHostnameError::Provider(Self::detail(
                &envelope.errors,
                &text,
            )));
        }
        if let Some(wire) = envelope
            .result
            .unwrap_or_default()
            .into_iter()
            .find(|wire| wire.hostname == hostname)
        {
            return Ok(Some(wire));
        }
        // The exact name was not on the one page we read. If the filter
        // matched more than one page there is no way to be sure it is
        // absent, and `delete` must never report success for a claim it
        // did not find.
        if envelope
            .result_info
            .is_some_and(|info| info.total_pages > 1)
        {
            return Err(CustomHostnameError::Provider(
                "the hostname filter matched more than one page; refusing to guess".to_owned(),
            ));
        }
        Ok(None)
    }

    /// One parsed success envelope: `success: true` and a result, or the
    /// matching port error.
    fn success_body<T: serde::de::DeserializeOwned>(
        status: StatusCode,
        text: &str,
    ) -> Result<T, CustomHostnameError> {
        if !status.is_success() {
            return Err(Self::error_from(status, text));
        }
        let envelope: Envelope<T> = serde_json::from_str(text).map_err(|err| parse_error(&err))?;
        if !envelope.success {
            return Err(CustomHostnameError::Provider(Self::detail(
                &envelope.errors,
                text,
            )));
        }
        envelope.result.ok_or_else(|| {
            CustomHostnameError::Provider("the provider's response carried no result".to_owned())
        })
    }
}

#[async_trait]
impl CustomHostnames for CloudflareSaas {
    async fn create(&self, claim: &HostnameClaim) -> Result<CustomHostname, CustomHostnameError> {
        let config = self.require_config()?;
        let hostname = check_hostname(&claim.hostname, &config.zone_name)
            .map_err(CustomHostnameError::Refused)?;
        let method = claim.method.as_str();
        let body = serde_json::to_vec(&serde_json::json!({
            "hostname": hostname,
            "ssl": {
                "method": method,
                "type": CERTIFICATE_TYPE,
                "settings": { "min_tls_version": MIN_TLS_VERSION },
            },
        }))
        .map_err(|err| CustomHostnameError::Transport(err.to_string()))?;
        let uri = collection_uri(&config.zone_id);
        let (status, text) = self
            .send(config, http::Method::POST, uri, Some(body))
            .await?;
        if !status.is_success() {
            let error = Self::error_from(status, &text);
            tracing::warn!(
                provider = "cloudflare-saas",
                zone = %config.zone_name,
                hostname = %hostname,
                code = status.as_u16(),
                error = %error,
                "custom hostname outcome"
            );
            return Err(error);
        }
        let wire = Self::success_body::<WireHostname>(status, &text)?;
        tracing::info!(
            provider = "cloudflare-saas",
            zone = %config.zone_name,
            hostname = %wire.hostname,
            status = %wire.status,
            "custom hostname outcome"
        );
        Ok(wire.into_custom_hostname(config.cname_target.as_deref()))
    }

    async fn get(&self, hostname: &str) -> Result<Option<CustomHostname>, CustomHostnameError> {
        let config = self.require_config()?;
        let hostname =
            check_hostname(hostname, &config.zone_name).map_err(CustomHostnameError::Refused)?;
        let found = self.find(config, &hostname).await?;
        Ok(found.map(|wire| wire.into_custom_hostname(config.cname_target.as_deref())))
    }

    async fn delete(&self, hostname: &str) -> Result<(), CustomHostnameError> {
        let config = self.require_config()?;
        let hostname =
            check_hostname(hostname, &config.zone_name).map_err(CustomHostnameError::Refused)?;
        let Some(found) = self.find(config, &hostname).await? else {
            // Not there is already the wanted end state (idempotent).
            return Ok(());
        };
        let collection = collection_uri(&config.zone_id);
        let id = checked_id(&found.id)?;
        let uri = format!("{collection}/{id}");
        let (status, text) = self.send(config, http::Method::DELETE, uri, None).await?;
        if status.is_success() {
            tracing::info!(
                provider = "cloudflare-saas",
                zone = %config.zone_name,
                hostname = %hostname,
                "custom hostname outcome"
            );
            return Ok(());
        }
        // Gone between the lookup and the delete: the same end state.
        if status == StatusCode::NOT_FOUND
            || Self::parse_errors(&text)
                .first()
                .is_some_and(|error| error.code == 1436)
        {
            return Ok(());
        }
        Err(Self::error_from(status, &text))
    }

    async fn refresh(&self, hostname: &str) -> Result<CustomHostname, CustomHostnameError> {
        let config = self.require_config()?;
        let hostname =
            check_hostname(hostname, &config.zone_name).map_err(CustomHostnameError::Refused)?;
        let Some(found) = self.find(config, &hostname).await? else {
            return Err(CustomHostnameError::NotFound);
        };
        // Re-run domain control validation with the same method and
        // certificate type the hostname was created with.
        let method = found
            .ssl
            .as_ref()
            .map(|ssl| ssl.method.as_str())
            .filter(|method| !method.is_empty())
            .unwrap_or("http");
        let body = serde_json::to_vec(&serde_json::json!({
            "ssl": { "method": method, "type": CERTIFICATE_TYPE },
        }))
        .map_err(|err| CustomHostnameError::Transport(err.to_string()))?;
        let collection = collection_uri(&config.zone_id);
        let id = checked_id(&found.id)?;
        let uri = format!("{collection}/{id}");
        let (status, text) = self
            .send(config, http::Method::PATCH, uri, Some(body))
            .await?;
        if !status.is_success() {
            let error = Self::error_from(status, &text);
            tracing::warn!(
                provider = "cloudflare-saas",
                zone = %config.zone_name,
                hostname = %hostname,
                code = status.as_u16(),
                error = %error,
                "custom hostname outcome"
            );
            return Err(error);
        }
        let wire = Self::success_body::<WireHostname>(status, &text)?;
        tracing::info!(
            provider = "cloudflare-saas",
            zone = %config.zone_name,
            hostname = %wire.hostname,
            status = %wire.status,
            "custom hostname outcome"
        );
        Ok(wire.into_custom_hostname(config.cname_target.as_deref()))
    }
}

/// The custom-hostnames collection URL for a zone.
fn collection_uri(zone_id: &str) -> String {
    format!("{API_BASE}/zones/{zone_id}/custom_hostnames")
}

/// A success body that does not parse is the JSON path breaking between the
/// provider and here, not a refusal.
fn parse_error(err: &serde_json::Error) -> CustomHostnameError {
    CustomHostnameError::Provider(format!("the provider's response did not parse: {err}"))
}

/// The provider's envelope: `success` gates everything, `errors` carries the
/// taxonomy, `result` the object (or array) on success.
#[derive(serde::Deserialize)]
// Serde would otherwise demand `T: Default` for the defaulted `result`
// field, which says nothing about the wire and only narrows the bound.
#[serde(bound(deserialize = "T: serde::de::Deserialize<'de>"))]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    #[serde(default)]
    result: Option<T>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

/// The pagination block the list endpoint carries alongside `result`.
#[derive(serde::Deserialize, Default)]
struct ResultInfo {
    #[serde(default)]
    total_pages: u64,
}

#[derive(serde::Deserialize, Default)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// One custom hostname as the provider sends it. Every field defaults, so an
/// unknown or absent one never fails the whole response.
#[derive(serde::Deserialize, Default)]
struct WireHostname {
    #[serde(default)]
    id: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    verification_errors: Vec<String>,
    #[serde(default)]
    ownership_verification: Option<OwnershipVerification>,
    #[serde(default)]
    ssl: Option<WireSsl>,
}

#[derive(serde::Deserialize, Default)]
struct OwnershipVerification {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}

#[derive(serde::Deserialize, Default)]
struct WireSsl {
    #[serde(default)]
    method: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    validation_errors: Vec<ValidationError>,
    #[serde(default)]
    validation_records: Vec<ValidationRecord>,
}

#[derive(serde::Deserialize, Default)]
struct ValidationError {
    #[serde(default)]
    message: String,
}

#[derive(serde::Deserialize, Default)]
struct ValidationRecord {
    #[serde(default)]
    txt_name: Option<String>,
    #[serde(default)]
    txt_value: Option<String>,
}

impl WireHostname {
    /// The port's shape of this hostname. `cname_target` is the record the
    /// customer points at, shown while the hostname is not live.
    fn into_custom_hostname(self, cname_target: Option<&str>) -> CustomHostname {
        let status = self.provider_status();
        let certificate = self.certificate_status();
        let validation = self.validation(cname_target);
        CustomHostname {
            id: self.id,
            hostname: self.hostname,
            status,
            certificate,
            validation,
        }
    }

    /// `active` is serving; the provider's terminal failures say why they
    /// stopped; anything else is still pending. `verification_errors` on a
    /// pending hostname is informational, not a failure.
    fn provider_status(&self) -> ProviderStatus {
        match self.status.as_str() {
            "active" => ProviderStatus::Active,
            "blocked" | "moved" | "deleted" | "test_failed" | "pending_deletion" => {
                ProviderStatus::Failed {
                    reason: scrub_text(&self.failure_reason()),
                }
            }
            _ => ProviderStatus::Pending,
        }
    }

    /// The first verification error, or `hostname <status>` when the
    /// provider sent none.
    fn failure_reason(&self) -> String {
        self.verification_errors
            .first()
            .cloned()
            .unwrap_or_else(|| format!("hostname {}", self.status))
    }

    /// The certificate's own state, read from `ssl.status`. A missing `ssl`
    /// block is still pending, not failed.
    fn certificate_status(&self) -> CertificateStatus {
        let Some(ssl) = self.ssl.as_ref() else {
            return CertificateStatus::Pending;
        };
        match ssl.status.as_str() {
            "active" => CertificateStatus::Active,
            "validation_timed_out"
            | "issuance_timed_out"
            | "deployment_timed_out"
            | "deletion_timed_out"
            | "initializing_timed_out"
            | "expired"
            | "deleted" => CertificateStatus::Failed {
                reason: scrub_text(&ssl.failure_reason()),
            },
            _ => CertificateStatus::Pending,
        }
    }

    /// The DNS records to show the customer, only while the claim is not
    /// live: the `CNAME` at this deployment's target, the ownership
    /// verification `TXT`, and any `TXT` validation records the certificate
    /// challenge wants.
    fn validation(&self, cname_target: Option<&str>) -> Vec<Validation> {
        let status = self.provider_status();
        let certificate = self.certificate_status();
        let mut records = Vec::new();
        if !matches!(status, ProviderStatus::Active) {
            if let Some(target) = cname_target {
                records.push(Validation {
                    record_type: DnsRecordType::Cname,
                    name: self.hostname.clone(),
                    value: target.to_owned(),
                });
            }
            if let Some(ownership) = &self.ownership_verification {
                records.push(Validation {
                    record_type: DnsRecordType::Txt,
                    name: ownership.name.clone(),
                    value: ownership.value.clone(),
                });
            }
        }
        if !matches!(certificate, CertificateStatus::Active)
            && let Some(ssl) = &self.ssl
        {
            for record in &ssl.validation_records {
                if let (Some(name), Some(value)) = (&record.txt_name, &record.txt_value) {
                    records.push(Validation {
                        record_type: DnsRecordType::Txt,
                        name: name.clone(),
                        value: value.clone(),
                    });
                }
            }
        }
        records
    }
}

impl WireSsl {
    /// The first non-empty validation error message, or
    /// `certificate <status>` when the provider sent none.
    fn failure_reason(&self) -> String {
        self.validation_errors
            .iter()
            .map(|error| error.message.as_str())
            .find(|message| !message.is_empty())
            .map_or_else(|| format!("certificate {}", self.status), str::to_owned)
    }
}
