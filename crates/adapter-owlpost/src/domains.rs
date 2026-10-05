//! Sending domains over `/v1/domains` (issue #681). Owlpost publishes no
//! domains spec of its own and inherits Resend's — see the routes on
//! [`Owlpost`]. A field the provider adds later is ignored or absorbed by an
//! `Unknown` variant. The error is [`DomainError`], not [`OwlpostError`]:
//! onboarding needs 404, 409 and 422 apart, which [`MailError`] folds
//! together.

use crate::{Owlpost, OwlpostClient, OwlpostError};
use cratefield_core::MailError;
use http::StatusCode;
use std::fmt;
use std::time::Duration;

/// A sending domain, with the DNS records a venture must publish.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct Domain {
    /// The provider id, used by every other route here.
    pub id: String,
    /// The domain itself, e.g. `send.example.com`.
    pub name: String,
    /// Verification state.
    #[serde(default)]
    pub status: DomainStatus,
    /// The records to set in DNS; a list response may omit them.
    #[serde(default)]
    pub records: Vec<DnsRecord>,
    /// When the domain was added, as the provider's timestamp string.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Verification state of a [`Domain`]. `#[non_exhaustive]`: match with a
/// wildcard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DomainStatus {
    /// Nothing published yet, or the provider's default when it says nothing.
    #[default]
    NotStarted,
    /// Set up, awaiting DNS or a re-check.
    Pending,
    /// Every required record is published; the domain may send.
    Verified,
    /// Verification ran and failed.
    Failed,
    /// Verification could not run right now; retryable.
    TemporaryFailure,
    /// A state added after this adapter was written.
    #[serde(other)]
    Unknown,
}

/// What a record is for, from the `record` key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub enum RecordPurpose {
    /// The DKIM signing key.
    #[default]
    #[serde(rename = "DKIM")]
    Dkim,
    /// The MAIL FROM return path.
    #[serde(rename = "MAIL FROM")]
    MailFrom,
    /// The SPF allowlist.
    #[serde(rename = "SPF")]
    Spf,
    /// A purpose this adapter predates.
    #[serde(other)]
    Unknown,
}

/// The DNS record type, from the `type` key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub enum RecordType {
    /// A `TXT` record — the DKIM key.
    #[default]
    #[serde(rename = "TXT")]
    Txt,
    /// An `MX` record.
    #[serde(rename = "MX")]
    Mx,
    /// A `CNAME` record.
    #[serde(rename = "CNAME")]
    Cname,
    /// A type this adapter predates.
    #[serde(other)]
    Unknown,
}

/// One DNS record a venture must publish for a [`Domain`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct DnsRecord {
    /// What the record is for, from the `record` key.
    #[serde(rename = "record", default)]
    pub purpose: RecordPurpose,
    /// The record type, from the `type` key.
    #[serde(rename = "type", default)]
    pub kind: RecordType,
    /// The name to publish it under.
    pub name: String,
    /// The record's value: the DKIM key, the mail exchanger, and so on.
    pub value: String,
    /// The TTL as the provider words it — `"Auto"` is what it sends.
    #[serde(default)]
    pub ttl: Option<String>,
    /// The MX priority, for an `MX` record.
    #[serde(default)]
    pub priority: Option<u16>,
    /// Whether this record alone is satisfied.
    #[serde(default)]
    pub status: Option<DomainStatus>,
}

/// What a sending-domain call can fail with. `#[non_exhaustive]`: match
/// with a wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainError {
    /// No API key, so no call was made.
    NotConfigured,
    /// 404: no such domain.
    NotFound {
        /// The provider's problem detail, key-redacted.
        detail: String,
    },
    /// 409: the domain is already registered.
    AlreadyExists {
        /// The provider's problem detail, key-redacted.
        detail: String,
    },
    /// 400, 422, or a local refusal: a name or id this adapter will not
    /// put on the wire, or content the provider refused.
    Invalid {
        /// What was refused, key-redacted.
        detail: String,
    },
    /// Every other status, mapped as the mail routes map it: 401, 429, 5xx
    /// and transport failures, plus 403 — a key without the `domains:manage`
    /// scope — as [`MailError::Unauthorized`].
    Mail(MailError),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("owlpost domains are not configured (no API key)"),
            Self::NotFound { detail } => write!(f, "owlpost domain not found: {detail}"),
            Self::AlreadyExists { detail } => write!(f, "owlpost domain already exists: {detail}"),
            Self::Invalid { detail } => write!(f, "invalid owlpost domain: {detail}"),
            Self::Mail(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DomainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mail(error) => Some(error),
            _ => None,
        }
    }
}

impl From<OwlpostError> for DomainError {
    fn from(error: OwlpostError) -> Self {
        match error {
            OwlpostError::NotConfigured => Self::NotConfigured,
            OwlpostError::Mail(error) => Self::Mail(error),
        }
    }
}

impl Owlpost {
    /// Registers a sending domain (`POST {base}/v1/domains`) and returns it
    /// with the DKIM and MAIL FROM records to publish. It sends nothing
    /// until they are set: publish them, then poll [`Owlpost::get_domain`]
    /// until [`DomainStatus::Verified`].
    ///
    /// # Errors
    ///
    /// [`DomainError`]: a refused name, or 409 for one already registered.
    pub async fn create_domain(&self, name: &str) -> Result<Domain, DomainError> {
        if !valid_domain_name(name) {
            return Err(DomainError::Invalid {
                detail: format!("invalid domain name {name:?}"),
            });
        }
        let body = serde_json::to_vec(&CreateDomain { name })
            .map_err(|err| DomainError::from(self.client.transport(err)))?;
        let text = self
            .route(http::Method::POST, "/v1/domains", Some(body))
            .await?;
        serde_json::from_str(&text).map_err(|err| DomainError::from(self.client.transport(err)))
    }

    /// Every domain (`GET {base}/v1/domains`); entries may carry no records.
    ///
    /// # Errors
    ///
    /// [`DomainError`], including [`DomainError::NotConfigured`].
    pub async fn list_domains(&self) -> Result<Vec<Domain>, DomainError> {
        let text = self.route(http::Method::GET, "/v1/domains", None).await?;
        let parsed: DomainList = serde_json::from_str(&text)
            .map_err(|err| DomainError::from(self.client.transport(err)))?;
        Ok(parsed.data)
    }

    /// One domain by id (`GET {base}/v1/domains/{id}`), with its records.
    ///
    /// # Errors
    ///
    /// [`DomainError`]: a refused id, or [`DomainError::NotFound`].
    pub async fn get_domain(&self, id: &str) -> Result<Domain, DomainError> {
        require_valid_id(id)?;
        let text = self
            .route(http::Method::GET, &format!("/v1/domains/{id}"), None)
            .await?;
        serde_json::from_str(&text).map_err(|err| DomainError::from(self.client.transport(err)))
    }

    /// Re-checks a domain's DNS records (`POST .../{id}/verify`). It returns
    /// once the check is *scheduled*: poll [`Owlpost::get_domain`].
    ///
    /// # Errors
    ///
    /// [`DomainError`]: a refused id, or [`DomainError::NotFound`].
    pub async fn verify_domain(&self, id: &str) -> Result<(), DomainError> {
        require_valid_id(id)?;
        self.route(
            http::Method::POST,
            &format!("/v1/domains/{id}/verify"),
            None,
        )
        .await
        .map(|_| ())
    }

    /// Removes a sending domain (`DELETE {base}/v1/domains/{id}`).
    ///
    /// # Errors
    ///
    /// [`DomainError`]: a refused id, or [`DomainError::NotFound`].
    pub async fn delete_domain(&self, id: &str) -> Result<(), DomainError> {
        require_valid_id(id)?;
        self.route(http::Method::DELETE, &format!("/v1/domains/{id}"), None)
            .await
            .map(|_| ())
    }

    /// One `/v1/domains` request, with the sending-domain status mapping.
    async fn route(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<String, DomainError> {
        self.client
            .call_mapped(method, path, body, None, map_domain_status)
            .await
    }
}

/// The `POST /v1/domains` body.
#[derive(serde::Serialize)]
struct CreateDomain<'a> {
    name: &'a str,
}

/// The `{"data": [...]}` list envelope; `object` and any other key
/// alongside it are ignored.
#[derive(serde::Deserialize)]
struct DomainList {
    #[serde(default)]
    data: Vec<Domain>,
}

/// A cheap local check on a domain name — length, charset, and at least two
/// non-empty labels, which is what rules out a leading, trailing or doubled
/// dot. The provider has the final say.
fn valid_domain_name(name: &str) -> bool {
    name.len() <= 253
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        && name.split('.').count() >= 2
        && name.split('.').all(|label| !label.is_empty())
}

/// An id is spliced into a path, so it must hold only what a provider id
/// does — never a `/` or `..`. Refused locally, before the key check.
fn require_valid_id(id: &str) -> Result<(), DomainError> {
    if !crate::valid_email_id(id) {
        return Err(DomainError::Invalid {
            detail: format!("invalid domain id {id:?}"),
        });
    }
    Ok(())
}

/// 404, 409 and 400/422 stay distinct; everything else falls through to the
/// mail routes' [`OwlpostClient::map_status`], which is why this is not that
/// function alone. 403 is the exception: on a domain route a refusal means a
/// key without the `domains:manage` scope, not an unverified sending domain,
/// so it is `Unauthorized` and never `DomainNotVerified`.
fn map_domain_status(
    client: &OwlpostClient,
    status: StatusCode,
    body: &str,
    retry_after: Option<Duration>,
) -> DomainError {
    let detail = client.redact(crate::problem_detail(body));
    match status {
        StatusCode::NOT_FOUND => DomainError::NotFound { detail },
        StatusCode::CONFLICT => DomainError::AlreadyExists { detail },
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            DomainError::Invalid { detail }
        }
        StatusCode::FORBIDDEN => DomainError::Mail(MailError::Unauthorized),
        _ => DomainError::Mail(client.map_status(status, body, retry_after)),
    }
}
