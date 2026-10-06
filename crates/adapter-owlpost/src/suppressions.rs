//! Suppressions and topics (issue #669), shaped by the published Owlpost
//! docs at <https://owlpost.to/docs/suppression/>. Each method is one
//! `OwlpostClient::call`, so `map_status` maps 404 and 422 to
//! [`MailError::Invalid`] with the provider's detail, key redacted.

use super::{Owlpost, OwlpostError};
use cratefield_core::MailError;
use serde_json::from_str;

/// One suppression, as `GET {base}/v1/emails/suppressions` returns it. A
/// `topic` of `None` is account-wide; `reason` is `bounce`, `complaint` or
/// `manual`. `#[non_exhaustive]`: read the fields, do not build a literal.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Suppression {
    /// The suppressed address.
    pub address: String,
    /// The topic this is scoped to, `None` when account-wide.
    #[serde(default)]
    pub topic: Option<String>,
    /// Why the address is suppressed.
    #[serde(default)]
    pub reason: Option<String>,
    /// The email behind an automatic suppression.
    #[serde(default)]
    pub email_id: Option<String>,
    /// When the entry was added, as an RFC 3339 timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// The `{"object": "list", "data": [...]}` body a list answers with; `data`
/// defaults so a proxy's partial body reads as an empty list.
#[derive(serde::Deserialize)]
struct SuppressionList {
    #[serde(default)]
    data: Vec<Suppression>,
}

/// The `{"address", "topic"?}` body an add sends. An account-wide entry
/// carries no `topic` key at all.
#[derive(serde::Serialize)]
struct NewSuppression<'a> {
    address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    topic: Option<&'a str>,
}

/// The `{"name"}` body a topic rename sends.
#[derive(serde::Serialize)]
struct TopicName<'a> {
    name: &'a str,
}

/// Refuses any present-but-empty field: each would go on the wire as `""`,
/// which the provider answers 422 for.
fn check_fields(fields: [(&str, Option<&str>); 3]) -> Result<(), OwlpostError> {
    for (name, value) in fields {
        if value.is_some_and(str::is_empty) {
            return Err(MailError::Invalid {
                detail: format!("a suppression {name} must not be empty"),
            }
            .into());
        }
    }
    // Owlpost defines the topic charset account-wide, so a topic is held to
    // it on every route that takes one, not just the naming one.
    if let Some(topic) = fields
        .iter()
        .find(|(name, _)| *name == "topic")
        .and_then(|(_, v)| *v)
        && !valid_topic(topic)
    {
        return Err(bad_topic(topic).into());
    }
    Ok(())
}

/// The refusal [`check_fields`] makes for a topic outside the allowlist.
fn bad_topic(topic: &str) -> MailError {
    MailError::Invalid {
        detail: format!(
            "invalid topic {topic:?}: a topic is 1-64 characters of a-z, 0-9, ':', '_' or '-'"
        ),
    }
}

/// Owlpost's topic identifier: 1–64 characters of `a-z`, `0-9`, `:`, `_`,
/// `-`. Checked against the provider's allowlist before the segment is
/// percent-encoded, so a caller learns about a bad topic without a request.
fn valid_topic(topic: &str) -> bool {
    !topic.is_empty()
        && topic.len() <= 64
        && topic.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b':'
                || byte == b'_'
                || byte == b'-'
        })
}

/// Percent-encodes a path segment or query parameter. The allowlist is RFC
/// 3986's unreserved set, so a topic's `&` or an address's `@` and `/` come
/// out encoded instead of terminating the path or parameter early. (No `url`
/// crate: one value is not worth a dependency.)
fn percent_encode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            other => {
                // Writing to a String cannot fail.
                let _ = write!(encoded, "%{other:02X}");
            }
        }
    }
    encoded
}

impl Owlpost {
    /// `GET {base}/v1/emails/suppressions`, optionally `?topic=`-filtered.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] for an empty topic, or the mapped provider failure.
    pub async fn list_suppressions(
        &self,
        topic: Option<&str>,
    ) -> Result<Vec<Suppression>, OwlpostError> {
        let path = match topic {
            Some(topic) => {
                check_fields([("address", None), ("topic", Some(topic)), ("reason", None)])?;
                format!("/v1/emails/suppressions?topic={}", percent_encode(topic))
            }
            None => "/v1/emails/suppressions".to_owned(),
        };
        let text = self
            .client
            .call(http::Method::GET, &path, None, None)
            .await?;
        Ok(from_str::<SuppressionList>(&text)
            .map_err(|err| self.client.transport(err))?
            .data)
    }

    /// `POST {base}/v1/emails/suppressions` with `{"address", "topic"?}`;
    /// Owlpost assigns the reason, so none is sent.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] for an empty address or topic.
    pub async fn add_suppression(
        &self,
        address: &str,
        topic: Option<&str>,
    ) -> Result<(), OwlpostError> {
        check_fields([
            ("address", Some(address)),
            ("topic", topic),
            ("reason", None),
        ])?;
        let body = serde_json::to_vec(&NewSuppression { address, topic })
            .map_err(|e| self.client.transport(e))?;
        self.client
            .call(
                http::Method::POST,
                "/v1/emails/suppressions",
                Some(body),
                None,
            )
            .await
            .map(|_| ())
    }

    /// `DELETE {base}/v1/emails/suppressions/{address}?topic=&reason=`. The
    /// address is a path segment and the rest are query parameters, the
    /// documented shape; a DELETE carries no body.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] for an empty field, or [`MailError::Invalid`] when
    /// there was no such entry (404).
    pub async fn remove_suppression(
        &self,
        address: &str,
        topic: Option<&str>,
        reason: Option<&str>,
    ) -> Result<(), OwlpostError> {
        check_fields([
            ("address", Some(address)),
            ("topic", topic),
            ("reason", reason),
        ])?;
        let mut query: Vec<String> = Vec::new();
        for (name, value) in [("topic", topic), ("reason", reason)] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                query.push(format!("{name}={}", percent_encode(value)));
            }
        }
        let mut path = format!("/v1/emails/suppressions/{}", percent_encode(address));
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query.join("&"));
        }
        self.client
            .call(http::Method::DELETE, &path, None, None)
            .await
            .map(|_| ())
    }

    /// `PUT {base}/v1/emails/topics/{topic}` with `{"name"}`. The topic
    /// allowlist and the name's length are checked before any request.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] for a topic or name the provider would refuse.
    pub async fn set_topic_name(&self, topic: &str, name: &str) -> Result<(), OwlpostError> {
        if !valid_topic(topic) {
            return Err(bad_topic(topic).into());
        }
        if name.is_empty() || name.chars().count() > 200 {
            return Err(MailError::Invalid {
                detail: format!(
                    "invalid topic name of {} characters: a name is 1-200 characters",
                    name.chars().count()
                ),
            }
            .into());
        }
        let body = serde_json::to_vec(&TopicName { name }).map_err(|e| self.client.transport(e))?;
        let path = format!("/v1/emails/topics/{}", percent_encode(topic));
        self.client
            .call(http::Method::PUT, &path, Some(body), None)
            .await
            .map(|_| ())
    }
}
