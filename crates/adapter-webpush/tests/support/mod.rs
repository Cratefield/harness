//! Test doubles shared by the two suites: a scripted `HttpClient`, a clock
//! the test advances by hand, and **the user agent's half of RFC 8291** —
//! the decryptor a browser runs.
//!
//! The decryptor is written from the RFC text rather than from
//! `src/ece.rs`, and shares no code with it. That is the point: a round trip
//! against the encoder's own inverse would agree with any consistent
//! mistake (a `key_info` assembled in the wrong operand order decrypts
//! perfectly against itself), and the published vector alone would not catch
//! a regression that only fires on inputs the vector does not contain — an
//! empty payload, one at the size limit, one ending in zero octets. The two
//! together do.

// Each integration-test binary compiles its own copy of this module and
// uses a different part of it, so unused-item warnings here are structural,
// not a sign of dead test code.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Key, KeyInit, Nonce};
use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, HttpError};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// The browser's half of RFC 8291

/// Why a decrypt failed, named the way the RFC names the rule.
#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// Shorter than the RFC 8188 §2.1 header, or the header claims a `keyid`
    /// the body does not contain.
    Truncated,
    /// The record is longer than the `rs` the header declares.
    RecordTooLong,
    /// The `keyid` is not a P-256 point, so there is nothing to ECDH with.
    ServerKey,
    /// AES-128-GCM refused: wrong key, wrong nonce, or a tampered body.
    Aead,
    /// RFC 8188 §2: "A decrypter MUST fail if the record contains no
    /// non-zero octet."
    NoDelimiter,
    /// RFC 8291 §4: "The padding delimiter octet MUST be checked; values
    /// other than 0x02 MUST cause the message to be discarded."
    BadDelimiter(u8),
}

/// Decrypts one `aes128gcm` Web Push body with the subscription's private
/// key, exactly as a user agent does.
///
/// # Errors
///
/// One [`DecryptError`] per rule the body breaks.
pub fn decrypt(
    ua_private: &[u8; 32],
    auth_secret: &[u8; 16],
    body: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    // RFC 8188 §2.1: salt(16) | rs(4) | idlen(1) | keyid(idlen)
    if body.len() < 21 {
        return Err(DecryptError::Truncated);
    }
    let salt = &body[..16];
    let rs = u32::from_be_bytes(body[16..20].try_into().expect("4 bytes"));
    let idlen = usize::from(body[20]);
    if body.len() < 21 + idlen {
        return Err(DecryptError::Truncated);
    }
    let as_public_bytes = &body[21..21 + idlen];
    let record = &body[21 + idlen..];
    if record.len() > rs as usize {
        return Err(DecryptError::RecordTooLong);
    }

    // RFC 8291 §3.1: the user agent combines its private key with the public
    // key the server put in `keyid`.
    let ua_secret = SecretKey::from_slice(ua_private).map_err(|_| DecryptError::ServerKey)?;
    let ua_public = ua_secret.public_key().to_encoded_point(false);
    let as_public =
        PublicKey::from_sec1_bytes(as_public_bytes).map_err(|_| DecryptError::ServerKey)?;
    let shared = p256::ecdh::diffie_hellman(ua_secret.to_nonzero_scalar(), as_public.as_affine());

    // RFC 8291 §3.3: key_info = "WebPush: info" || 0x00 || ua_public || as_public
    let mut key_info = Vec::from(&b"WebPush: info\x00"[..]);
    key_info.extend_from_slice(ua_public.as_bytes());
    key_info.extend_from_slice(as_public_bytes);
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(auth_secret), shared.raw_secret_bytes())
        .expand(&key_info, &mut ikm)
        .expect("32 octets");

    // RFC 8188 §2.2/§2.3.
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0u8; 16];
    hkdf.expand(b"Content-Encoding: aes128gcm\x00", &mut cek)
        .expect("16 octets");
    let mut nonce = [0u8; 12];
    hkdf.expand(b"Content-Encoding: nonce\x00", &mut nonce)
        .expect("12 octets");

    // Record sequence number 0, so the nonce needs no XOR.
    let padded = Aes128Gcm::new(&Key::<Aes128Gcm>::from(cek))
        .decrypt(&Nonce::<Aes128Gcm>::from(nonce), record)
        .map_err(|_| DecryptError::Aead)?;

    // RFC 8188 §2: "the padding delimiter is the last non-zero-valued octet
    // of the record."
    let end = padded
        .iter()
        .rposition(|&byte| byte != 0)
        .ok_or(DecryptError::NoDelimiter)?;
    if padded[end] != 0x02 {
        return Err(DecryptError::BadDelimiter(padded[end]));
    }
    Ok(padded[..end].to_vec())
}

/// The public key a subscription with this private key would publish as
/// `p256dh`.
#[must_use]
pub fn public_key_of(private: &[u8; 32]) -> [u8; 65] {
    let secret = SecretKey::from_slice(private).expect("a valid P-256 scalar");
    let encoded = secret.public_key().to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(encoded.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Ports

/// A clock the test advances by hand.
pub struct StepClock(AtomicI64);

impl StepClock {
    #[must_use]
    pub fn at(secs: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(secs)))
    }
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl Clock for StepClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::Relaxed)).expect("in range")
    }
}

/// One request as the adapter built it.
pub struct Seen {
    pub method: String,
    pub uri: String,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl Seen {
    /// A header as a string, panicking with the header named when it is
    /// absent — an assertion failure that says which header is missing beats
    /// an `unwrap` on `None`.
    #[must_use]
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("request has no {name} header"))
            .to_str()
            .expect("header is ASCII")
    }

    #[must_use]
    pub fn maybe_header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().expect("ASCII"))
    }
}

/// What the fake answers with.
#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: &'static str,
}

impl Reply {
    /// RFC 8030's own success: `201 Created` with a `Location`.
    #[must_use]
    pub fn created() -> Self {
        Self {
            status: 201,
            headers: vec![("location", "https://push.example/message/abc123".to_owned())],
            body: "",
        }
    }

    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: "",
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: &'static str) -> Self {
        self.body = body;
        self
    }
}

/// Records every request and answers with whatever the test last set.
// The doubles record calls through a Mutex; ADR 0007 bans it for request
// state, not for a test double.
#[allow(clippy::disallowed_types)]
pub struct ScriptedHttp {
    seen: std::sync::Mutex<Vec<Seen>>,
    reply: std::sync::Mutex<Reply>,
    transport_error: std::sync::atomic::AtomicBool,
}

#[allow(clippy::disallowed_types)]
impl ScriptedHttp {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: std::sync::Mutex::new(Vec::new()),
            reply: std::sync::Mutex::new(Reply::created()),
            transport_error: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// What the next sends answer with.
    pub fn set(&self, reply: Reply) {
        *self.reply.lock().expect("reply") = reply;
    }

    /// The port itself fails, as a DNS or TLS failure would.
    pub fn fail_transport(&self) {
        self.transport_error
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.seen.lock().expect("seen").len()
    }

    /// The most recent request.
    ///
    /// # Panics
    ///
    /// If nothing was sent — which is the assertion, said out loud.
    pub fn last<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        let guard = self.seen.lock().expect("seen");
        read(guard.last().expect("at least one request was sent"))
    }

    /// The `n`th request, oldest first.
    pub fn nth<T>(&self, n: usize, read: impl FnOnce(&Seen) -> T) -> T {
        let guard = self.seen.lock().expect("seen");
        read(guard.get(n).expect("that many requests were sent"))
    }
}

#[async_trait::async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.seen.lock().expect("seen").push(Seen {
            method: request.method().to_string(),
            uri: request.uri().to_string(),
            headers: request.headers().clone(),
            body: request.body().clone(),
        });
        if self
            .transport_error
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(HttpError::Transport("connection reset".to_owned()));
        }
        let reply = self.reply.lock().expect("reply").clone();
        let mut builder = http::Response::builder().status(reply.status);
        for (name, value) in &reply.headers {
            builder = builder.header(*name, value);
        }
        Ok(builder.body(Bytes::from(reply.body)).expect("response"))
    }
}
