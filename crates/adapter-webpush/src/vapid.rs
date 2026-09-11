//! VAPID: Voluntary Application Server Identification ([RFC 8292]).
//!
//! The application server signs an ES256 JWT whose `aud` is the push
//! service's **origin** and presents it, next to its public key, in one
//! header:
//!
//! ```text
//! Authorization: vapid t=<jwt>, k=<base64url(uncompressed public key)>
//! ```
//!
//! Signing and the mint-once cache are [`cratefield_push_auth`]'s — the same
//! `Es256Signer` the APNs adapter uses, with different claims (issue #178).
//! The cache is keyed **per origin**, because `aud` is part of the signed
//! claims: Mozilla's token is not Google's, and a venture whose subscribers
//! are spread across four browsers and a self-hosted UnifiedPush server
//! needs five.
//!
//! The legacy `Crypto-Key: p256ecdsa=` header is deliberately not sent. It
//! belongs to the pre-RFC draft Chrome shipped in 2016; every current push
//! service accepts RFC 8292 §3, and sending both forms is how a mismatched
//! pair of keys goes unnoticed.
//!
//! [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use cratefield_core::Clock;
use cratefield_push_auth::{CachedToken, Es256Signer};
use serde_json::json;

/// How far ahead a minted token's `exp` is set.
///
/// RFC 8292 §2 caps it at 24 hours and recommends a shorter one; 12 hours
/// leaves an unmistakable margin on both sides of a device clock that is a
/// few minutes out.
#[allow(clippy::duration_suboptimal_units)] // `from_hours` is not const-stable on 1.98
pub const TOKEN_EXPIRY: Duration = Duration::from_secs(12 * 3_600);

/// How long a minted token is reused before it is re-signed.
///
/// Strictly shorter than [`TOKEN_EXPIRY`], and by more than any plausible
/// request: the cache must never hand out a token that expires mid-flight.
#[allow(clippy::duration_suboptimal_units)] // as above
pub const TOKEN_TTL: Duration = Duration::from_secs(11 * 3_600);

/// A VAPID key pair and the contact `sub` that goes with it.
#[derive(Debug, thiserror::Error)]
pub enum VapidError {
    /// The private key did not parse as either accepted form.
    #[error("invalid VAPID private key: {0}")]
    Key(String),
    /// RFC 8292 §2.1: `sub` is a contact URI, `mailto:` or `https:`.
    #[error("VAPID subject must be a mailto: or https: URI, got {0:?}")]
    Subject(String),
    /// The push endpoint is not an absolute `http`/`https` URL, so it has no
    /// origin to put in `aud`.
    #[error("push endpoint has no usable origin: {0}")]
    Endpoint(String),
}

/// The two secrets a venture configures: `VAPID_PRIVATE_KEY` and
/// `VAPID_SUBJECT`.
///
/// A struct and not two adjacent string arguments on purpose — both are
/// strings, so a constructor taking them positionally accepts them the wrong
/// way round without a word from the compiler, and the failure would only
/// show up as a push service rejecting every token.
///
/// The **public** key is absent because it is derived from the private one
/// and never configured: a separately-configured public key that drifts from
/// its private half is the classic silent VAPID failure.
pub struct VapidKeys {
    /// The private key, in either form that circulates: a PKCS#8 PEM
    /// (`-----BEGIN PRIVATE KEY-----`, what `openssl` emits) or the bare
    /// 32-byte P-256 scalar base64url-encoded (what the JavaScript tooling
    /// calls a VAPID private key).
    pub private_key: String,
    /// RFC 8292 §2.1's `sub`: a `mailto:` or `https:` contact URI a push
    /// service can reach the operator at.
    pub subject: String,
}

impl VapidKeys {
    /// The same, without writing the field names.
    pub fn new(private_key: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            private_key: private_key.into(),
            subject: subject.into(),
        }
    }
}

impl std::fmt::Debug for VapidKeys {
    /// Never prints the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VapidKeys")
            .field("private_key", &"[redacted]")
            .field("subject", &self.subject)
            .finish()
    }
}

/// A PKCS#8 PEM, or the bare scalar base64url (padded or not).
fn parse_private_key(private_key: &str) -> Result<Es256Signer, VapidError> {
    let trimmed = private_key.trim();
    if trimmed.contains("-----BEGIN") {
        return Es256Signer::from_pkcs8_pem(trimmed)
            .map_err(|err| VapidError::Key(err.to_string()));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE.decode(trimmed))
        .map_err(|_| VapidError::Key("not a PKCS#8 PEM and not base64url".to_owned()))?;
    let scalar: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        VapidError::Key(format!(
            "a raw P-256 private key is 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    Es256Signer::from_scalar(&scalar).map_err(|err| VapidError::Key(err.to_string()))
}

/// The `aud` of a token for `endpoint`: the push service's origin
/// (RFC 6454) — scheme, host, and the port only when it is not the
/// scheme's default.
///
/// **Never the path.** The path of a push endpoint is the subscription's
/// bearer capability and differs per subscriber; putting it in `aud` mints
/// one token per subscriber and, on the services that check `aud` strictly
/// (Mozilla autopush does), earns a `401 UnauthorizedRegistration` on every
/// send. It is the classic VAPID bug, so it has a test of its own.
///
/// There is one implementation, in `cratefield-core`, and this is a thin
/// wrapper over it (issue #215). It used to be the strict of two: the
/// other split strings and fed a Content-Security-Policy, where its
/// looseness mattered more than it does here.
///
/// # Errors
///
/// [`VapidError::Endpoint`] if the endpoint is not an absolute `http`/`https`
/// URL with a host.
pub fn origin_of(endpoint: &str) -> Result<String, VapidError> {
    // One implementation, in core (issue #215). It was the strict one and
    // this is where it came from; the argument for allowing `http` is
    // above and is unchanged.
    //
    // The error text is rebuilt here rather than delegated, because
    // `VapidError::Endpoint` is what a venture reads when a push fails to
    // authorise, and "scheme \"ftp\" is not http or https" is the sentence
    // that tells them which end is wrong.
    cratefield_core::origin_of(endpoint).map_err(|err| VapidError::Endpoint(err.to_string()))
}

/// Mints and reuses the `Authorization` header, one token per push-service
/// origin.
pub struct Vapid {
    signer: Es256Signer,
    subject: String,
    /// `base64url(uncompressed public key)`, precomputed because it is a
    /// constant of the key and goes on every request.
    public_key: String,
    tokens: CachedToken<String>,
}

impl Vapid {
    /// Parses the configured secrets into a signer whose tokens are cached
    /// for [`TOKEN_TTL`].
    ///
    /// # Errors
    ///
    /// [`VapidError::Key`] if the private key is neither accepted form, or
    /// is not a usable P-256 scalar; [`VapidError::Subject`] if the subject
    /// is not a `mailto:` or `https:` URI.
    pub fn new(keys: VapidKeys) -> Result<Self, VapidError> {
        let lower = keys.subject.to_ascii_lowercase();
        if !(lower.starts_with("mailto:") || lower.starts_with("https://")) {
            return Err(VapidError::Subject(keys.subject));
        }
        let signer = parse_private_key(&keys.private_key)?;
        let public_key = URL_SAFE_NO_PAD.encode(signer.public_key_uncompressed());
        Ok(Self {
            signer,
            subject: keys.subject,
            public_key,
            tokens: CachedToken::new(TOKEN_TTL),
        })
    }

    /// The `k=` parameter, and the `applicationServerKey` a browser passes
    /// to `pushManager.subscribe()`. Public by construction — it is on every
    /// request.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// The `Authorization` header value for a request to `origin`.
    ///
    /// `origin` must already be the output of [`origin_of`]: it is both the
    /// signed `aud` and the cache key, and the two must be the same string
    /// or the cache would key on something the token does not claim.
    // `&String` and not `&str`: [`origin_of`] hands the caller an owned
    // `String` and `CachedToken`'s key type *is* `String`, so taking `&str`
    // here meant allocating a second copy of the origin on every send purely
    // to look one up. Borrowing what the caller already owns is the whole
    // point of this signature.
    #[allow(clippy::ptr_arg)]
    pub fn authorization(&self, clock: &dyn Clock, origin: &String) -> String {
        let expiry = i64::try_from(TOKEN_EXPIRY.as_secs()).unwrap_or(i64::MAX);
        let token = self.tokens.get_or_mint(clock, origin, |now_unix| {
            self.signer.sign_jwt(
                // RFC 8292 §2: the JWT is signed with ES256; `typ` is
                // carried because the services check it.
                &json!({ "typ": "JWT", "alg": "ES256" }),
                &json!({
                    "aud": origin,
                    "exp": now_unix.saturating_add(expiry),
                    "sub": self.subject,
                }),
            )
        });
        format!("vapid t={token}, k={}", self.public_key)
    }

    /// Drops the cached token for `origin`, so the next send re-signs — what
    /// the adapter does when a push service rejects the token.
    // `&String` for the reason [`Vapid::authorization`] gives.
    #[allow(clippy::ptr_arg)]
    pub fn invalidate(&self, origin: &String) {
        self.tokens.invalidate(origin);
    }
}

impl std::fmt::Debug for Vapid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vapid")
            .field("signer", &self.signer)
            .field("public_key", &self.public_key)
            .field("subject", &self.subject)
            .field("tokens", &self.tokens)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway P-256 key, generated for these tests only — NOT a real
    // VAPID key. The same one `crates/push-auth` and `crates/adapter-apns`
    // use, so the three suites assert bytes from one key.
    const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n-----END PRIVATE KEY-----";
    // The same key as the bare 32-byte scalar: the DER above carries it at
    // the `OCTET STRING` after `04 20`.
    const TEST_SCALAR: &str = "cXMgRpW-eLn7ZvCxIuTdd8csWMZ69azlRzS0dy2FN6E";

    fn vapid(private_key: &str, subject: &str) -> Result<Vapid, VapidError> {
        Vapid::new(VapidKeys::new(private_key, subject))
    }

    #[test]
    fn both_private_key_forms_give_the_same_key() {
        let pem = vapid(TEST_PEM, "mailto:ops@example.test").unwrap();
        let raw = vapid(TEST_SCALAR, "mailto:ops@example.test").unwrap();
        assert_eq!(pem.public_key(), raw.public_key());
        // Padded base64url is accepted too: the same key out of a library
        // that pads.
        let padded = URL_SAFE.encode(URL_SAFE_NO_PAD.decode(TEST_SCALAR).unwrap());
        assert_eq!(
            vapid(&padded, "mailto:ops@example.test")
                .unwrap()
                .public_key(),
            pem.public_key()
        );
    }

    #[test]
    fn the_configured_keys_never_print_the_private_one() {
        let printed = format!("{:?}", VapidKeys::new(TEST_PEM, "mailto:ops@example.test"));
        assert!(!printed.contains("MIGHAgEA"), "{printed}");
        assert!(printed.contains("[redacted]"), "{printed}");
        assert!(printed.contains("mailto:ops@example.test"), "{printed}");
    }

    #[test]
    fn a_key_that_is_neither_form_is_refused() {
        for bad in [
            "not a key",
            "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----",
            // Right encoding, wrong length.
            "cXMgRpW-eLn7ZvCxIuTdd8csWMZ69azl",
        ] {
            let error = vapid(bad, "mailto:ops@example.test").unwrap_err();
            assert!(matches!(error, VapidError::Key(_)), "{bad}: {error}");
        }
    }

    #[test]
    fn the_subject_must_be_a_contact_uri() {
        for bad in ["ops@example.test", "http://example.test", ""] {
            let error = vapid(TEST_PEM, bad).unwrap_err();
            assert!(matches!(error, VapidError::Subject(_)), "{bad}: {error}");
        }
        assert!(vapid(TEST_PEM, "mailto:ops@example.test").is_ok());
        assert!(vapid(TEST_PEM, "https://example.test/contact").is_ok());
        assert!(vapid(TEST_PEM, "MAILTO:ops@example.test").is_ok());
    }

    #[test]
    fn the_audience_is_the_origin_and_never_the_path() {
        // The path of a push endpoint is the subscription capability.
        assert_eq!(
            origin_of("https://updates.push.services.mozilla.com/wpush/v2/gAAAAA_long_token")
                .unwrap(),
            "https://updates.push.services.mozilla.com"
        );
        assert_eq!(
            origin_of("https://fcm.googleapis.com/fcm/send/abc:DEF-ghi").unwrap(),
            "https://fcm.googleapis.com"
        );
        // A non-default port is part of the origin; the default one is not.
        assert_eq!(
            origin_of("http://ntfy.local:8080/up1234abcd?up=1").unwrap(),
            "http://ntfy.local:8080"
        );
        assert_eq!(
            origin_of("https://push.example:443/x").unwrap(),
            "https://push.example"
        );
        assert_eq!(
            origin_of("http://push.example:80/x").unwrap(),
            "http://push.example"
        );
        // Query strings and fragments are not part of it either.
        assert_eq!(
            origin_of("https://push.example/x?y=1#z").unwrap(),
            "https://push.example"
        );
    }

    #[test]
    fn an_endpoint_without_an_origin_is_refused() {
        for bad in [
            "/relative/path",
            "not a url",
            "ftp://push.example/x",
            "data:,x",
        ] {
            let error = origin_of(bad).unwrap_err();
            assert!(matches!(error, VapidError::Endpoint(_)), "{bad}: {error}");
        }
    }
}
