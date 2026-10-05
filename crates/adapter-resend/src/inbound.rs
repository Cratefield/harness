//! Resend's inbound mail: the `email.received` webhook, verified with the
//! Svix scheme Resend signs with (issue #563). The inbound sibling of
//! [`Resend`](crate::Resend), which sends.

use cratefield_core::{
    InboundMailError, InboundMailSource, InboundMessage, Svix, WebhookVerifier, receive_mail,
};
use http::HeaderMap;

/// Resend's `email.received` webhook, over core's [`Svix`] scheme.
///
/// **The webhook is metadata only.** Resend's delivery carries the message
/// id, envelopes, subject and attachment *metadata*, never the body: the
/// HTML, text and headers are a separate call to the Received-emails API
/// (`GET /emails/receiving/{email_id}`). [`parse`](InboundMailSource::parse)
/// therefore fills [`InboundMessage::text`] and [`InboundMessage::html`]
/// with `None` and leaves the fetch to the caller — a body fetch is a
/// policy decision, not a parse.
///
/// **The secret is the endpoint's.** A Resend webhook signing secret
/// (`whsec_…`) belongs to the endpoint rather than to a tenant, so this
/// source holds the one it verifies with — hence [`receive`](Self::receive).
pub struct ResendInbound {
    secret: String,
}

impl ResendInbound {
    /// `secret` is the webhook signing secret (`whsec_…`); an empty one
    /// refuses every delivery rather than guessing.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    /// Reads `RESEND_WEBHOOK_SECRET` from the process environment. On
    /// Workers the venture should read the secret from its `Env` and use
    /// [`ResendInbound::new`] instead (`std::env` has no Workers vars).
    pub fn from_env() -> Self {
        Self::new(std::env::var("RESEND_WEBHOOK_SECRET").unwrap_or_default())
    }

    /// Verify-then-parse with the secret this source was built with — the
    /// one call a webhook route needs.
    ///
    /// # Errors
    ///
    /// As [`receive_mail`].
    pub fn receive(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now_unix: i64,
    ) -> Result<Option<InboundMessage>, InboundMailError> {
        receive_mail(self, &self.secret, headers, body, now_unix)
    }
}

/// The `data` object of an `email.received` event, exactly the fields
/// Resend's webhook documents. `to` is an array even for one recipient.
#[derive(serde::Deserialize)]
struct ReceivedData {
    email_id: String,
    from: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    subject: String,
    /// The RFC 5322 `Message-ID`, when the payload carries it. It is the
    /// only header the webhook gives, so it is the only one handed on.
    #[serde(default)]
    message_id: Option<String>,
    /// RFC 3339 (`2026-02-22T23:41:11.894Z`), when the payload carries it.
    #[serde(default)]
    created_at: Option<String>,
}

/// Converts Resend's RFC 3339 timestamp to Unix seconds; `None` when it is
/// absent or unparseable, which is not an error — the delivery is still
/// the message.
fn received_at(created_at: Option<&str>) -> Option<i64> {
    time::OffsetDateTime::parse(created_at?, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(time::OffsetDateTime::unix_timestamp)
}

impl InboundMailSource for ResendInbound {
    fn kind(&self) -> &'static str {
        "resend"
    }

    /// Constant-time compare, fail-closed on unreadable input: inherited
    /// from core's [`WebhookVerifier`], never re-derived here.
    fn verifier(&self) -> WebhookVerifier {
        WebhookVerifier::new(Svix)
    }

    /// Reads one **verified** delivery. An `email.received` maps onto an
    /// [`InboundMessage`]; every other event Resend sends — `email.sent`,
    /// `email.delivered` — is `Ok(None)`, verified silence, not an error.
    ///
    /// # Errors
    ///
    /// [`InboundMailError::Malformed`] when the verified body is not a JSON
    /// object, or an `email.received` arrives without its `data`. Never
    /// [`InboundMailError::Signature`] — that answer belongs to
    /// [`receive_mail`], before bytes are parsed.
    fn parse(&self, body: &[u8]) -> Result<Option<InboundMessage>, InboundMailError> {
        let event: serde_json::Value = serde_json::from_slice(body)
            .map_err(|error| InboundMailError::Malformed(error.to_string()))?;
        // An array or scalar is not an event envelope: it is not another
        // event type, so it cannot be dismissed as one.
        if event.as_object().is_none() {
            return Err(InboundMailError::Malformed("not an object".to_owned()));
        }
        if event["type"].as_str() != Some("email.received") {
            return Ok(None);
        }
        let data: ReceivedData = serde_json::from_value(event["data"].clone())
            .map_err(|error| InboundMailError::Malformed(error.to_string()))?;
        let headers = data
            .message_id
            .map(|id| ("Message-ID".to_owned(), id))
            .into_iter()
            .collect();
        Ok(Some(InboundMessage {
            id: data.email_id,
            from: data.from,
            to: data.to,
            cc: data.cc,
            subject: data.subject,
            // Metadata only: the body is a separate API call (see the type
            // doc). Do not fetch it here.
            text: None,
            html: None,
            headers,
            received_at: received_at(data.created_at.as_deref()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use cratefield_core::svix_secret_key;
    use hmac::{Hmac, KeyInit, Mac};
    use http::HeaderValue;
    use sha2::Sha256;

    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const NOW: i64 = 1_800_000_000;
    const ID: &str = "56761188-7520-42d8-8898-ff6fc54ce618";
    const RECEIVED: &[u8] = br#"{"type":"email.received","created_at":"2026-02-22T23:41:12.126Z","data":{"email_id":"56761188-7520-42d8-8898-ff6fc54ce618","created_at":"2026-02-22T23:41:11.894Z","from":"onboarding@resend.dev","to":["delivered@resend.dev"],"bcc":[],"cc":["cc@example.test"],"received_for":["forwarded@example.com"],"message_id":"<111-222-333@email.example.com>","subject":"Sending this example"}}"#;

    /// The three Svix headers Resend sends for this body, signed a second
    /// time here, never through core's own extraction.
    fn signed(secret: &str, id: &str, at: i64, body: &[u8]) -> HeaderMap {
        let key = svix_secret_key(secret).expect("the fixture secret decodes");
        let timestamp = at.to_string();
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(&[id.as_bytes(), b".", timestamp.as_bytes(), b".", body].concat());
        let signature = format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()));
        let id = HeaderValue::from_str(id).expect("id");
        let ts = HeaderValue::from_str(&timestamp).expect("timestamp");
        let sig = HeaderValue::from_str(&signature).expect("signature");
        let mut headers = HeaderMap::new();
        headers.insert("svix-id", id);
        headers.insert("svix-timestamp", ts);
        headers.insert("svix-signature", sig);
        headers
    }

    fn inbound() -> ResendInbound {
        ResendInbound::new(SECRET)
    }

    /// The fixture signs exactly as Svix documents: this is Svix's own
    /// worked example (`whsec_…` secret, id, timestamp, body → signature),
    /// so a drift in the key derivation or the signed payload stops
    /// matching it.
    #[test]
    fn the_fixture_matches_svixs_documented_signature() {
        let body = br#"{"test": 2432232314}"#;
        let headers = signed(SECRET, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_330, body);
        assert_eq!(
            headers["svix-signature"],
            "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
        );
    }

    #[test]
    fn a_signed_email_received_parses_its_metadata() {
        let headers = signed(SECRET, ID, NOW, RECEIVED);
        let message = inbound()
            .receive(&headers, RECEIVED, NOW)
            .expect("the signature verifies")
            .expect("an inbound message");
        assert_eq!(message.id, ID);
        assert_eq!(message.from, "onboarding@resend.dev");
        assert_eq!(message.to, vec!["delivered@resend.dev".to_owned()]);
        assert_eq!(message.cc, vec!["cc@example.test".to_owned()]);
        assert_eq!(message.subject, "Sending this example");
        // Metadata only: the body is not in the webhook.
        assert_eq!(message.text, None);
        assert_eq!(message.html, None);
        // The one header the webhook carries is handed on.
        assert_eq!(
            message.headers,
            vec![(
                "Message-ID".to_owned(),
                "<111-222-333@email.example.com>".to_owned()
            )]
        );
        assert_eq!(message.received_at, Some(1_771_803_671));
        assert_eq!(message.event_key(), format!("inbound-mail:{ID}"));
    }

    #[test]
    fn a_bad_signature_is_refused_before_parsing() {
        let headers = signed(SECRET, ID, NOW, RECEIVED);
        // Wrong secret, a body that no longer matches the signature, and no
        // headers at all.
        for (source, headers, body) in [
            (ResendInbound::new("whsec_other"), &headers, RECEIVED),
            (inbound(), &headers, b"{}" as &[u8]),
            (inbound(), &HeaderMap::new(), RECEIVED),
        ] {
            assert_eq!(
                source.receive(headers, body, NOW).unwrap_err(),
                InboundMailError::Signature
            );
        }
    }

    #[test]
    fn another_event_type_is_not_an_inbound_message() {
        let body = br#"{"type":"email.delivered","data":{"email_id":"msg_2"}}"#;
        let headers = signed(SECRET, "msg_2", NOW, body);
        assert_eq!(
            inbound().receive(&headers, body, NOW).expect("verifies"),
            None
        );
    }

    #[test]
    fn a_verified_body_that_does_not_parse_is_malformed() {
        // Not JSON, a top-level array, and JSON of the right type with no
        // `data`.
        for body in [b"not json" as &[u8], b"[]", br#"{"type":"email.received"}"#] {
            let headers = signed(SECRET, "msg_3", NOW, body);
            assert!(matches!(
                inbound().receive(&headers, body, NOW),
                Err(InboundMailError::Malformed(_))
            ));
        }
        // An absent or unparseable `created_at` is not an error: the
        // delivery is still the message (the round trip is in the test
        // above).
        assert_eq!(received_at(None), None);
        assert_eq!(received_at(Some("not a date")), None);
    }
}
