//! Owlpost's inbound mail: the `/v1/inbound/messages` API (issue #682).
//!
//! **A held body is only ever an explicit fetch.** A held message is listed as
//! a [`MessageSummary`], which has no body field at all: the HTML and text
//! come from [`Owlpost::get_message`] or [`Owlpost::raw_message`], never from a
//! listing. Inboxes, threads and routes follow.

use cratefield_core::{MailError, Message};
use http::Method;
use std::fmt::Write as _;

use crate::{Owlpost, OwlpostError, valid_email_id};

/// The `/v1/inbound` root every path hangs off.
const INBOUND: &str = "/v1/inbound/messages";

impl Owlpost {
    /// One page of `GET {base}/v1/inbound/messages`, filtered and cursor-paged
    /// by [`MessageQuery`]. Scope `inbound:read`.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] from the provider, or `NotConfigured` with no request.
    pub async fn list_messages(&self, query: &MessageQuery) -> Result<MessagePage, OwlpostError> {
        let mut params: Vec<(&str, String)> = Vec::new();
        for (key, value) in [
            ("inbox", query.inbox.as_deref()),
            ("thread", query.thread.as_deref()),
            ("q", query.q.as_deref()),
            ("before", query.before.as_deref()),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                params.push((key, value.to_owned()));
            }
        }
        if let Some(limit) = query.limit {
            params.push(("limit", limit.to_string()));
        }
        if query.held {
            params.push(("status", "held".to_owned()));
        }
        self.get(&query_path(INBOUND, &params)).await
    }

    /// `GET {base}/v1/inbound/messages?status=held` for one inbox. Scope `inbound:read`.
    ///
    /// # Errors
    ///
    /// As [`Owlpost::list_messages`].
    pub async fn list_held(
        &self,
        inbox: &str,
        before: Option<&str>,
    ) -> Result<MessagePage, OwlpostError> {
        self.list_messages(&MessageQuery {
            inbox: Some(inbox.to_owned()),
            before: before.map(str::to_owned),
            held: true,
            ..MessageQuery::default()
        })
        .await
    }

    /// `GET {base}/v1/inbound/messages/{id}`, the listing-free way to read a
    /// body. Scope `inbound:read`.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] for an empty or path-like id, or a provider failure.
    pub async fn get_message(&self, id: &str) -> Result<MessageDetail, OwlpostError> {
        refuse_id(id)?;
        self.get(&format!("{INBOUND}/{id}")).await
    }

    /// `GET {base}/v1/inbound/messages/{id}/raw`, the RFC 822 source.
    /// Scope `inbound:read`.
    ///
    /// # Errors
    ///
    /// As [`Owlpost::get_message`].
    pub async fn raw_message(&self, id: &str) -> Result<String, OwlpostError> {
        refuse_id(id)?;
        // The source verbatim: a body that happens to parse as `{"id": …}` is
        // still the message, so nothing here inspects it.
        self.client
            .call(Method::GET, &format!("{INBOUND}/{id}/raw"), None, None)
            .await
    }

    /// `POST {base}/v1/inbound/messages/{id}/reply`, answering the reply's id.
    /// Only the message's `to`, `subject`, `text` and `html` travel — Owlpost
    /// takes the sender from the inbox the reply is on. Scope `inbound:manage`.
    ///
    /// # Errors
    ///
    /// [`OwlpostError`] for an empty or path-like id, or an answer that is not
    /// a `{"id": …}` body.
    pub async fn reply(&self, id: &str, message: Message) -> Result<String, OwlpostError> {
        refuse_id(id)?;
        let body = serde_json::json!({
            "to": message.to,
            "subject": message.subject,
            "text": message.text,
            "html": message.html,
        });
        let bytes = serde_json::to_vec(&body).map_err(|err| self.client.transport(err))?;
        let text = self
            .client
            .call(
                Method::POST,
                &format!("{INBOUND}/{id}/reply"),
                Some(bytes),
                message.idempotency_key.as_deref(),
            )
            .await?;
        Ok(self.parse::<crate::SendResponse>(&text)?.id)
    }

    /// `POST {base}/v1/inbound/messages/{id}/release`, stopping the hold.
    /// Scope `inbound:manage`.
    ///
    /// # Errors
    ///
    /// As [`Owlpost::get_message`].
    pub async fn release(&self, id: &str) -> Result<(), OwlpostError> {
        refuse_id(id)?;
        // Any 2xx answers; the body is not worth reading.
        self.client
            .call(Method::POST, &format!("{INBOUND}/{id}/release"), None, None)
            .await
            .map(|_| ())
    }

    /// One `GET`, parsed.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, OwlpostError> {
        self.parse(&self.client.call(Method::GET, path, None, None).await?)
    }

    fn parse<T: serde::de::DeserializeOwned>(&self, text: &str) -> Result<T, OwlpostError> {
        serde_json::from_str(text).map_err(|err| self.client.transport(err))
    }
}

/// The filters and cursor for [`Owlpost::list_messages`]: an inbox or thread
/// id, a full-text `q`, a page `limit`, `before` — the previous page's
/// [`MessagePage::next`] — and `held`, the only lifecycle state
/// (`status=held`) a listing can be filtered to. Every field is optional, and
/// an empty one is left off the query string. `#[non_exhaustive]`: build with
/// [`MessageQuery::default`] and set fields.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct MessageQuery {
    pub inbox: Option<String>,
    pub thread: Option<String>,
    pub q: Option<String>,
    pub limit: Option<u32>,
    pub before: Option<String>,
    pub held: bool,
}

/// One page of messages, and the cursor for the page before them (`None` on
/// the last page). `#[non_exhaustive]`.
#[derive(Debug, Clone, Default, serde::Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessagePage {
    #[serde(default)]
    pub data: Vec<MessageSummary>,
    /// The cursor for the page of older messages: pass it back as
    /// [`MessageQuery::before`]. `None` on the last page.
    #[serde(default)]
    pub next: Option<String>,
}

/// What a listing says about a message — and all it may say: there is no body
/// field, so a held message's HTML and text cannot leak into a list; fetch
/// them with [`Owlpost::get_message`]. Fields are defaulted one by one, not by
/// a container `#[serde(default)]`, which a flattened [`MessageDetail`] cannot
/// see through. `#[non_exhaustive]`.
#[derive(Debug, Clone, Default, serde::Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessageSummary {
    pub id: String,
    pub inbox: String,
    pub status: String,
    #[serde(default)]
    pub thread: Option<String>,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub received_at: String,
}

/// One message with its body — the only inbound type that carries one.
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Default, serde::Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessageDetail {
    /// The summary fields a listing returns …
    #[serde(flatten)]
    pub summary: MessageSummary,
    /// … plus the parsed body, which a held message exposes only here.
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
}

/// Refuses an id that is empty or path-like before any request, exactly as
/// [`Owlpost::get_email`] does for a sent email id.
fn refuse_id(id: &str) -> Result<(), OwlpostError> {
    if !valid_email_id(id) {
        return Err(MailError::Invalid {
            detail: format!("invalid inbound id {id:?}"),
        }
        .into());
    }
    Ok(())
}

/// Appends `?k=v&k=v` to `path`; [`crate::OwlpostClient::call`] splices the
/// path into the URI raw, so every key and value is percent-encoded here.
fn query_path(path: &str, params: &[(&str, String)]) -> String {
    let mut path = path.to_owned();
    for (index, (key, value)) in params.iter().enumerate() {
        path.push(if index == 0 { '?' } else { '&' });
        path.push_str(&percent_encode(key));
        path.push('=');
        path.push_str(&percent_encode(value));
    }
    path
}

/// Percent-encodes everything outside the unreserved set, so a space or an
/// `&` in a search term cannot end the query early.
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}
