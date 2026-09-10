//! The payload encryption: the `aes128gcm` HTTP content coding
//! ([RFC 8188]) and the Web Push key schedule layered on top of it
//! ([RFC 8291]).
//!
//! The two are kept apart on purpose. RFC 8188 is a self-contained content
//! coding — salt, record size, key id, `HKDF-SHA256` to a content-encryption
//! key and nonce, one `AEAD_AES_128_GCM` record — and it has its own test
//! vector (RFC 8188 §3.1) that needs nothing from Web Push. RFC 8291 only
//! decides *what the input keying material and the key id are*: an ECDH
//! between a per-message server key and the browser's `p256dh`, mixed with
//! the subscription's `auth` secret. Splitting them means each half is
//! checked against its own published vector rather than only through the
//! other.
//!
//! Everything here is pure Rust ([`p256`], [`hkdf`], [`aes_gcm`]) and builds
//! for `wasm32-unknown-unknown`.
//!
//! [RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188
//! [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Key, KeyInit, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use p256::PublicKey;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The fixed part of the RFC 8188 §2.1 header: `salt(16) | rs(4) | idlen(1)`.
pub const HEADER_FIXED_LEN: usize = 21;
/// The `salt` field, and the salt input to HKDF.
pub const SALT_LEN: usize = 16;
/// RFC 8291 §3.2: the subscription's authentication secret is 16 octets.
pub const AUTH_SECRET_LEN: usize = 16;
/// An uncompressed SEC1 P-256 point: `0x04 || x(32) || y(32)`.
pub const PUBLIC_KEY_LEN: usize = 65;
/// `AEAD_AES_128_GCM` expands its input by a 16-octet authentication tag.
pub const GCM_TAG_LEN: usize = 16;
/// Every record carries exactly one padding delimiter octet (RFC 8188 §2);
/// this adapter adds no further padding, so that octet is the whole cost.
pub const PAD_DELIMITER_LEN: usize = 1;
/// The last (here: only) record's delimiter. A user agent MUST discard a
/// message whose final delimiter is anything else (RFC 8291 §4).
const LAST_RECORD_DELIMITER: u8 = 0x02;

/// The header a Web Push body always carries: the fixed part plus the
/// 65-octet application-server public key that RFC 8291 §4 requires as the
/// `keyid`. The 86 in "86-octet header" throughout the RFCs is this.
pub const WEB_PUSH_HEADER_LEN: usize = HEADER_FIXED_LEN + PUBLIC_KEY_LEN;

/// What a push service is required to accept as a whole request body
/// (RFC 8030 §7.2, quoted again by RFC 8291 §4). Vendors are known to cap
/// there and answer `413` above it, so it is the budget the default record
/// size is derived from rather than a number to hope about.
pub const MIN_SUPPORTED_BODY_LEN: usize = 4096;

/// RFC 8188 §2.1: "Values smaller than 18 are invalid" — a record has to
/// hold at least a delimiter and a tag.
pub const MIN_RECORD_SIZE: u32 = 18;

/// The record size this adapter uses unless a venture raises it.
///
/// It is **derived, not chosen**: the header sits outside the record budget,
/// so a body that must fit [`MIN_SUPPORTED_BODY_LEN`] leaves
/// `4096 - 86 = 4010` octets for the record. Feeding that through
/// [`max_plaintext`] gives 3993 octets of plaintext, which is the number RFC
/// 8291 §4 arrives at by the same arithmetic ("Absent header (86 octets),
/// padding (minimum 1 octet), and expansion for `AEAD_AES_128_GCM` (16
/// octets), this equates to, at most, 3993 octets of plaintext").
///
/// The folklore numbers — 4078, 4079, 3052 — come from setting `rs` to 4096
/// and forgetting that the header is *added* to it, which produces a
/// 4182-octet body that a service capping at 4096 rejects.
pub const DEFAULT_RECORD_SIZE: u32 = {
    #[allow(clippy::cast_possible_truncation)] // 4010 fits u32
    let size = (MIN_SUPPORTED_BODY_LEN - WEB_PUSH_HEADER_LEN) as u32;
    size
};

/// RFC 8188 §2.2 / §2.3: the two `info` strings, each terminated by a single
/// zero octet that is part of the input and not a C string terminator.
const CEK_INFO: &[u8] = b"Content-Encoding: aes128gcm\x00";
const NONCE_INFO: &[u8] = b"Content-Encoding: nonce\x00";
/// RFC 8291 §3.3: `key_info = "WebPush: info" || 0x00 || ua_public || as_public`.
const KEY_INFO_PREFIX: &[u8] = b"WebPush: info\x00";

/// How much plaintext fits in one record of `record_size` octets.
///
/// RFC 8188 §2 draws it directly: "content — any length up to rs-17 octets",
/// because a valid record always contains at least a padding delimiter octet
/// (1) and an authentication tag (16). The header is **not** part of this: it
/// precedes the records, which is why [`DEFAULT_RECORD_SIZE`] subtracts it
/// from the body budget first.
#[must_use]
pub const fn max_plaintext(record_size: u32) -> usize {
    // `usize::try_from` is not const; u32 -> usize is lossless on both
    // targets this workspace builds for (64-bit native and wasm32).
    #[allow(clippy::cast_possible_truncation)]
    let size = record_size as usize;
    size.saturating_sub(GCM_TAG_LEN + PAD_DELIMITER_LEN)
}

/// Encryption refused the inputs. Nothing here carries key material: the
/// `Display` of every variant is safe to log.
#[derive(Debug, thiserror::Error)]
pub enum EceError {
    /// The subscription's `p256dh` is not an uncompressed P-256 point.
    #[error("subscription p256dh is not a {PUBLIC_KEY_LEN}-byte uncompressed P-256 point: {0}")]
    SubscriptionKey(String),
    /// The subscription's `auth` is not the 16 octets RFC 8291 §3.2 requires.
    #[error("subscription auth secret must be {AUTH_SECRET_LEN} bytes, got {0}")]
    AuthSecret(usize),
    /// The subscription's `auth` is not base64url at all.
    #[error("subscription auth secret is not base64url")]
    AuthSecretEncoding,
    /// The application server's own private key is unusable.
    #[error("application server key is not a valid P-256 private key")]
    ServerKey,
    /// A record size below RFC 8188's floor.
    #[error("record size {0} is invalid: RFC 8188 requires at least {MIN_RECORD_SIZE}")]
    RecordSize(u32),
    /// The plaintext does not fit one record. Checked before any key is
    /// derived and long before any request is built.
    #[error(
        "payload too large: {plaintext} bytes of plaintext exceeds the {limit}-byte \
         limit for a {record_size}-byte record"
    )]
    PayloadTooLarge {
        plaintext: usize,
        limit: usize,
        record_size: u32,
    },
    /// AES-128-GCM refused. Deliberately opaque — an AEAD failure detail is
    /// never useful to a caller and can be useful to an attacker.
    #[error("AES-128-GCM encryption failed")]
    Aead,
    /// The platform would not produce random bytes, so no salt and no
    /// ephemeral key. Failing is the only safe answer.
    #[error("could not draw random bytes: {0}")]
    Random(String),
}

/// Decodes a subscription key: base64url or standard base64, padded or not.
///
/// Browsers hand the keys over as **unpadded base64url**, which is the only
/// form RFC 8291 needs — but a subscription is routinely stored and shipped
/// by something other than the browser that made it, and every other form
/// turns up on the way back:
///
/// - **padded** (`=`), from a JSON round trip through a library that pads;
/// - the **standard alphabet** (`+` and `/` where base64url has `-` and
///   `_`), from any encoder that re-encodes the raw bytes without asking for
///   the URL-safe alphabet — Python's `base64.b64encode`, PHP's
///   `base64_encode`, `JSON.stringify` over a `Buffer`.
///
/// The two alphabets do not overlap, so accepting both is unambiguous: a
/// value is decoded by exactly one of them. Refusing the standard alphabet
/// meant a `p256dh` that happens to contain a `+` or a `/` — roughly one
/// subscription in a hundred does not, at 65 random-looking octets — could
/// never be pushed to, and would look like a corrupt subscription rather
/// than an encoding the adapter declined to read.
fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .ok()
}

/// The two keys a browser hands over with a subscription, validated.
///
/// Holding the parsed form means a malformed subscription is one
/// [`EceError`] at the top of a send rather than a mystery `400` from the
/// push service — or, worse, a body no browser can decrypt.
#[derive(Clone)]
pub struct SubscriptionKeys {
    /// The user agent's P-256 public key, uncompressed, exactly as it goes
    /// into `key_info`.
    ua_public: [u8; PUBLIC_KEY_LEN],
    /// The RFC 8291 §3.2 authentication secret — the shared secret the
    /// payload is encrypted under, so it is cleared on drop (the workspace
    /// manifest's `zeroize` convention, the same one `crates/kms`,
    /// `crates/secrets` and `module-linkedin` follow).
    auth: Zeroizing<[u8; AUTH_SECRET_LEN]>,
}

impl SubscriptionKeys {
    /// Parses the base64url `p256dh` and `auth` of a
    /// [`Recipient::WebPush`](cratefield_core::Recipient::WebPush).
    ///
    /// # Errors
    ///
    /// [`EceError::SubscriptionKey`] if `p256dh` is not base64url of an
    /// uncompressed P-256 point that is actually on the curve;
    /// [`EceError::AuthSecret`] if `auth` is not 16 octets.
    pub fn parse(p256dh: &str, auth: &str) -> Result<Self, EceError> {
        let p256dh = decode_base64url(p256dh)
            .ok_or_else(|| EceError::SubscriptionKey("not base64url".to_owned()))?;
        // The decoded secret is wrapped before anything else can hold it:
        // wrapping only the copy inside `SubscriptionKeys` would leave this
        // `Vec` to drop uncleared on both the success and the error path.
        let auth = Zeroizing::new(decode_base64url(auth).ok_or(EceError::AuthSecretEncoding)?);
        Self::from_bytes(&p256dh, &auth)
    }

    /// The same, from already-decoded bytes.
    ///
    /// # Errors
    ///
    /// As [`SubscriptionKeys::parse`].
    pub fn from_bytes(p256dh: &[u8], auth: &[u8]) -> Result<Self, EceError> {
        let ua_public: [u8; PUBLIC_KEY_LEN] = p256dh.try_into().map_err(|_| {
            EceError::SubscriptionKey(format!("{} bytes, expected {PUBLIC_KEY_LEN}", p256dh.len()))
        })?;
        if ua_public[0] != 0x04 {
            return Err(EceError::SubscriptionKey(
                "not the uncompressed point form (no 0x04 prefix)".to_owned(),
            ));
        }
        // RFC 8291 Security Considerations: "The user agent and application
        // MUST verify that the public key they receive is on the P-256
        // curve. Failure to validate a public key can allow an attacker to
        // extract a private key." `from_sec1_bytes` is that check — it
        // rejects the point at infinity, out-of-range coordinates, and
        // anything off the curve.
        PublicKey::from_sec1_bytes(&ua_public)
            .map_err(|err| EceError::SubscriptionKey(err.to_string()))?;
        if auth.len() != AUTH_SECRET_LEN {
            return Err(EceError::AuthSecret(auth.len()));
        }
        // Copied *into* the cleared-on-drop buffer rather than built beside
        // it: `[u8; 16]` is `Copy`, so `Zeroizing::new(array)` would leave
        // the original array on the stack uncleared.
        let mut secret = Zeroizing::new([0u8; AUTH_SECRET_LEN]);
        secret.copy_from_slice(auth);
        Ok(Self {
            ua_public,
            auth: secret,
        })
    }
}

impl std::fmt::Debug for SubscriptionKeys {
    /// Never prints the keys: `auth` is the secret the payload is encrypted
    /// under, and `ua_public` identifies the subscriber.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubscriptionKeys { .. }")
    }
}

/// What the RFC 8291 §3.4 key schedule produces and a send actually reads:
/// the input keying material for the content coding, and the public key the
/// header carries as its `keyid`.
///
/// **Only what a send reads.** An earlier revision also carried
/// `ecdh_secret`, `prk_key` and `key_info`, purely so one step-by-step test
/// could assert them against Appendix A — the `#[cfg_attr(not(test),
/// allow(dead_code))]` admitted it — so every production send copied ~96
/// octets of key material that a release build never looks at and (before
/// the `zeroize` wrapping below) never cleared. Those assertions live on
/// against [`ecdh_secret`] and [`key_info`], which are the same functions the
/// send itself calls, so the test still pins production's code rather than
/// its own restatement of it.
struct Schedule {
    ikm: Zeroizing<[u8; 32]>,
    as_public: [u8; PUBLIC_KEY_LEN],
}

/// RFC 8188 §2.2/§2.3, the record's own keys.
///
/// The PRK they are expanded from is not kept, for the reason [`Schedule`]
/// gives: it is a plain `HKDF-Extract` of values the tests already hold, so
/// the vectors' published PRK is asserted straight off `Hkdf::extract` there.
struct RecordKeys {
    cek: Zeroizing<[u8; 16]>,
    nonce: Zeroizing<[u8; 12]>,
}

/// RFC 8291 §3.1: the ECDH shared secret between the per-message
/// application-server key and the subscription's `p256dh`.
///
/// `p256`'s own `SharedSecret` zeroizes on drop, so the copy taken out of it
/// is wrapped as well — an unwrapped copy outlives the protection the
/// library already provides, which is the worst of both.
fn ecdh_secret(as_secret: &SecretKey, ua_public: &PublicKey) -> Zeroizing<[u8; 32]> {
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.raw_secret_bytes());
    out
}

/// RFC 8291 §3.3: `key_info = "WebPush: info" || 0x00 || ua_public || as_public`.
///
/// Order matters and is not symmetric: user agent first, application server
/// second. Swapping them yields a body that decrypts to garbage on every real
/// browser while every round-trip test still passes, which is why Appendix
/// A's `key_info` is asserted byte for byte against this function.
fn key_info(ua_public: &[u8; PUBLIC_KEY_LEN], as_public: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut info = Vec::with_capacity(KEY_INFO_PREFIX.len() + 2 * PUBLIC_KEY_LEN);
    info.extend_from_slice(KEY_INFO_PREFIX);
    info.extend_from_slice(ua_public);
    info.extend_from_slice(as_public);
    info
}

/// RFC 8291 §3.1–§3.3: ECDH, then combine with the authentication secret.
fn schedule(keys: &SubscriptionKeys, as_private: &[u8; 32]) -> Result<Schedule, EceError> {
    let as_secret = SecretKey::from_slice(as_private).map_err(|_| EceError::ServerKey)?;
    let encoded = as_secret.public_key().to_encoded_point(false);
    let mut as_public = [0u8; PUBLIC_KEY_LEN];
    // An uncompressed P-256 point is always 65 bytes.
    as_public.copy_from_slice(encoded.as_bytes());

    // Validated in `SubscriptionKeys::from_bytes`, so this cannot fail.
    let ua_public = PublicKey::from_sec1_bytes(&keys.ua_public)
        .map_err(|err| EceError::SubscriptionKey(err.to_string()))?;
    let ecdh = ecdh_secret(&as_secret, &ua_public);
    let info = key_info(&keys.ua_public, &as_public);

    // salt = the authentication secret, IKM = the ECDH secret (RFC 8291 §3.3).
    let hkdf = Hkdf::<Sha256>::new(Some(keys.auth.as_slice()), ecdh.as_slice());
    let mut ikm = Zeroizing::new([0u8; 32]);
    // L = 32, well inside HKDF's 255*HashLen ceiling.
    hkdf.expand(&info, ikm.as_mut_slice())
        .expect("HKDF-Expand of 32 octets is always in range");

    Ok(Schedule { ikm, as_public })
}

/// RFC 8188 §2.2/§2.3.
fn record_keys(salt: &[u8; SALT_LEN], ikm: &[u8]) -> RecordKeys {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut cek = Zeroizing::new([0u8; 16]);
    hkdf.expand(CEK_INFO, cek.as_mut_slice())
        .expect("HKDF-Expand of 16 octets is always in range");
    let mut nonce = Zeroizing::new([0u8; 12]);
    hkdf.expand(NONCE_INFO, nonce.as_mut_slice())
        .expect("HKDF-Expand of 12 octets is always in range");
    RecordKeys { cek, nonce }
}

/// One RFC 8188 body: the §2.1 header followed by a single record.
///
/// A single record is what RFC 8291 §4 requires of an application server, so
/// the record sequence number is always zero and the nonce needs no XOR.
fn encode(
    ikm: &[u8],
    salt: &[u8; SALT_LEN],
    keyid: &[u8],
    record_size: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, EceError> {
    if record_size < MIN_RECORD_SIZE {
        return Err(EceError::RecordSize(record_size));
    }
    let limit = max_plaintext(record_size);
    if plaintext.len() > limit {
        return Err(EceError::PayloadTooLarge {
            plaintext: plaintext.len(),
            limit,
            record_size,
        });
    }
    let idlen = u8::try_from(keyid.len()).map_err(|_| EceError::ServerKey)?;

    let RecordKeys { cek, nonce } = record_keys(salt, ikm);

    let mut padded = Vec::with_capacity(plaintext.len() + PAD_DELIMITER_LEN);
    padded.extend_from_slice(plaintext);
    padded.push(LAST_RECORD_DELIMITER);

    // `aes-gcm` is built with its `zeroize` feature (see the workspace
    // manifest), so the cipher clears its expanded round keys on drop; the
    // `Key` here is a statement temporary and goes with it.
    let cipher = Aes128Gcm::new(&Key::<Aes128Gcm>::from(*cek));
    let ciphertext = cipher
        .encrypt(&Nonce::<Aes128Gcm>::from(*nonce), padded.as_slice())
        .map_err(|_| EceError::Aead)?;

    let mut body = Vec::with_capacity(HEADER_FIXED_LEN + keyid.len() + ciphertext.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&record_size.to_be_bytes());
    body.push(idlen);
    body.extend_from_slice(keyid);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

/// The RFC 8291 sender: a subscription's keys and a record size in, one
/// `Content-Encoding: aes128gcm` body out.
#[derive(Debug, Clone, Copy)]
pub struct Ece {
    record_size: u32,
}

impl Default for Ece {
    fn default() -> Self {
        Self {
            record_size: DEFAULT_RECORD_SIZE,
        }
    }
}

impl Ece {
    /// An encoder with an explicit record size.
    ///
    /// Raising it past [`DEFAULT_RECORD_SIZE`] is a deliberate bet that the
    /// push services a venture's subscribers use accept a body larger than
    /// the [`MIN_SUPPORTED_BODY_LEN`] they are required to.
    ///
    /// # Errors
    ///
    /// [`EceError::RecordSize`] below RFC 8188's floor of 18.
    pub fn new(record_size: u32) -> Result<Self, EceError> {
        if record_size < MIN_RECORD_SIZE {
            return Err(EceError::RecordSize(record_size));
        }
        Ok(Self { record_size })
    }

    /// The `rs` this encoder writes into the header.
    #[must_use]
    pub const fn record_size(self) -> u32 {
        self.record_size
    }

    /// The largest plaintext this encoder accepts, computed from
    /// [`Ece::record_size`] — see [`max_plaintext`].
    #[must_use]
    pub const fn max_plaintext(self) -> usize {
        max_plaintext(self.record_size)
    }

    /// The whole body length a plaintext of `len` produces, header included.
    /// The check a vendor's body cap actually applies.
    #[must_use]
    pub const fn body_len(len: usize) -> usize {
        WEB_PUSH_HEADER_LEN + len + PAD_DELIMITER_LEN + GCM_TAG_LEN
    }

    /// Encrypts `plaintext` for `keys`, drawing a fresh salt and a fresh
    /// application-server key pair for this one message — which is what
    /// makes reusing a `(CEK, nonce)` pair impossible.
    ///
    /// # Errors
    ///
    /// [`EceError::PayloadTooLarge`] before any key is derived,
    /// [`EceError::Random`] if the platform has no randomness, and the
    /// key errors of [`Ece::seal_with`].
    pub fn seal(self, keys: &SubscriptionKeys, plaintext: &[u8]) -> Result<Vec<u8>, EceError> {
        let limit = self.max_plaintext();
        if plaintext.len() > limit {
            return Err(EceError::PayloadTooLarge {
                plaintext: plaintext.len(),
                limit,
                record_size: self.record_size,
            });
        }
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|err| EceError::Random(err.to_string()))?;
        let as_private = random_scalar()?;
        self.seal_with(keys, plaintext, &salt, &as_private)
    }

    /// The same, with the salt and the application-server private key
    /// supplied.
    ///
    /// This is the seam the RFC 8291 Appendix A vector is reproduced
    /// through: the vector fixes both, and nothing else about the encoding
    /// is a choice. **Production code must use [`Ece::seal`]** — a reused
    /// salt with a reused key repeats a `(CEK, nonce)` pair, which loses the
    /// GCM authentication key.
    ///
    /// # Errors
    ///
    /// [`EceError::PayloadTooLarge`] if the plaintext does not fit one
    /// record, [`EceError::ServerKey`] if `as_private` is not a P-256
    /// scalar, [`EceError::SubscriptionKey`] if the subscription's key is
    /// not on the curve, [`EceError::Aead`] if AES-GCM refuses.
    pub fn seal_with(
        self,
        keys: &SubscriptionKeys,
        plaintext: &[u8],
        salt: &[u8; SALT_LEN],
        as_private: &[u8; 32],
    ) -> Result<Vec<u8>, EceError> {
        let schedule = schedule(keys, as_private)?;
        encode(
            schedule.ikm.as_slice(),
            salt,
            &schedule.as_public,
            self.record_size,
            plaintext,
        )
    }
}

/// A uniformly random P-256 private scalar, cleared on drop.
///
/// Drawn as 32 raw octets and offered to [`SecretKey::from_slice`], which
/// rejects zero and anything at or above the curve order. Both rejections
/// are astronomically unlikely (roughly 2^-32 for the order, 2^-256 for
/// zero), so the retry is bookkeeping rather than a hot path — but retrying
/// is the only correct answer, since clamping or reducing the value would
/// bias the key.
fn random_scalar() -> Result<Zeroizing<[u8; 32]>, EceError> {
    const ATTEMPTS: usize = 8;
    let mut bytes = Zeroizing::new([0u8; 32]);
    for _ in 0..ATTEMPTS {
        getrandom::fill(bytes.as_mut_slice()).map_err(|err| EceError::Random(err.to_string()))?;
        if SecretKey::from_slice(bytes.as_slice()).is_ok() {
            return Ok(bytes);
        }
    }
    Err(EceError::Random(
        "no valid P-256 scalar in 8 draws".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8291 Appendix A, the inputs. The user agent's half comes from
    /// `cratefield-testing`, which is where the workspace keeps these:
    /// four crates used to hold their own copy of a key pair that only
    /// works if every copy agrees to the character.
    use cratefield_testing::vectors::{
        RFC8291_AUTH_SECRET as AUTH_SECRET, RFC8291_PLAINTEXT as PLAINTEXT,
        RFC8291_UA_PUBLIC as UA_PUBLIC,
    };
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const AS_PUBLIC: &str =
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";

    /// RFC 8291 Appendix A, the intermediate values.
    const ECDH_SECRET: &str = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
    const PRK_KEY: &str = "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k";
    const KEY_INFO: &str = "V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OL\
                            r4BhZe9MEebhuPI-OztV3ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0EwbZI\
                            HMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP";
    const IKM: &str = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg";
    const PRK: &str = "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc";
    const CEK: &str = "oIhVW04MRdy2XN9CiKLxTg";
    const NONCE: &str = "4h_95klXJ5E_qnoN";
    const HEADER: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZ\
                          IIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const CIPHERTEXT: &str =
        "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ";

    fn b64(value: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(value).expect("base64url")
    }

    fn fixed<const N: usize>(value: &str) -> [u8; N] {
        b64(value).try_into().expect("fixed-size vector value")
    }

    fn vector_keys() -> SubscriptionKeys {
        SubscriptionKeys::parse(UA_PUBLIC, AUTH_SECRET).expect("the RFC's own subscription")
    }

    /// Every published intermediate, in the order RFC 8291 §3.4 derives
    /// them. Asserting the whole chain rather than only the body means a
    /// break names the step it happened in — an ECDH that agrees but a
    /// `key_info` assembled in the wrong order look identical from the
    /// outside.
    ///
    /// Each step is read off the function the *send* calls
    /// ([`ecdh_secret`], [`key_info`], [`schedule`], [`record_keys`]) rather
    /// than off fields carried through a send for the test's benefit: the
    /// assertions pin production code, and a release build carries none of
    /// these values (see [`Schedule`]). The two PRKs are plain
    /// `HKDF-Extract` outputs that no code here shapes, so they come
    /// straight from `Hkdf`.
    #[test]
    fn the_rfc8291_key_schedule_matches_appendix_a_step_by_step() {
        let keys = vector_keys();
        let as_private: [u8; 32] = fixed(AS_PRIVATE);
        let schedule = schedule(&keys, &as_private).expect("the RFC's own keys");
        assert_eq!(schedule.as_public.as_slice(), b64(AS_PUBLIC), "as_public");

        let as_secret = SecretKey::from_slice(&as_private).expect("the RFC's own key");
        let ua_public = PublicKey::from_sec1_bytes(&keys.ua_public).expect("on the curve");
        let ecdh = ecdh_secret(&as_secret, &ua_public);
        assert_eq!(ecdh.as_slice(), b64(ECDH_SECRET), "ecdh");
        assert_eq!(
            key_info(&keys.ua_public, &schedule.as_public),
            b64(KEY_INFO),
            "key_info"
        );
        let (prk_key, _) = Hkdf::<Sha256>::extract(Some(keys.auth.as_slice()), ecdh.as_slice());
        assert_eq!(prk_key.as_slice(), b64(PRK_KEY), "PRK_key");
        assert_eq!(schedule.ikm.as_slice(), b64(IKM), "IKM");

        let salt: [u8; SALT_LEN] = fixed(SALT);
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), schedule.ikm.as_slice());
        assert_eq!(prk.as_slice(), b64(PRK), "PRK");
        let record = record_keys(&salt, schedule.ikm.as_slice());
        assert_eq!(record.cek.as_slice(), b64(CEK), "CEK");
        assert_eq!(record.nonce.as_slice(), b64(NONCE), "NONCE");
    }

    /// The production key schedule carries the two values a send reads and
    /// nothing else.
    ///
    /// A size assertion rather than prose, because the thing that went wrong
    /// before was silent: three extra fields of key material rode every send
    /// for a test's benefit, admitted only by an `allow(dead_code)`. Adding
    /// a field back — for a test, for a log line, for "we might need it" —
    /// fails here.
    #[test]
    fn the_key_schedule_carries_no_test_only_key_material() {
        assert_eq!(
            size_of::<Schedule>(),
            32 + PUBLIC_KEY_LEN,
            "Schedule is the 32-octet IKM and the 65-octet public key, nothing else"
        );
        assert_eq!(
            size_of::<RecordKeys>(),
            16 + 12,
            "RecordKeys is the CEK and the nonce, nothing else"
        );
    }

    /// The header and the ciphertext are published separately in Appendix A,
    /// so each half of the body is pinned on its own.
    #[test]
    fn the_body_halves_match_appendix_a() {
        let body = Ece::new(4096)
            .expect("4096 is a legal record size")
            .seal_with(
                &vector_keys(),
                PLAINTEXT.as_bytes(),
                &fixed(SALT),
                &fixed(AS_PRIVATE),
            )
            .expect("the RFC's own inputs");

        assert_eq!(&body[..WEB_PUSH_HEADER_LEN], b64(HEADER), "86-octet header");
        assert_eq!(&body[WEB_PUSH_HEADER_LEN..], b64(CIPHERTEXT), "ciphertext");
    }

    /// The record-size field really is the `rs` argument, in network byte
    /// order, at the offset RFC 8188 §2.1 puts it.
    #[test]
    fn the_header_carries_the_record_size_and_the_key_id() {
        let body = Ece::default()
            .seal_with(&vector_keys(), b"x", &fixed(SALT), &fixed(AS_PRIVATE))
            .expect("valid");
        let rs = u32::from_be_bytes(body[SALT_LEN..SALT_LEN + 4].try_into().unwrap());
        assert_eq!(rs, DEFAULT_RECORD_SIZE);
        assert_eq!(rs, 4010, "4096 body budget minus the 86-octet header");
        assert_eq!(usize::from(body[SALT_LEN + 4]), PUBLIC_KEY_LEN, "idlen");
        assert_eq!(&body[HEADER_FIXED_LEN..WEB_PUSH_HEADER_LEN], b64(AS_PUBLIC));
    }

    /// RFC 8188 §3.1: the content coding on its own, with an empty `keyid`
    /// and the input keying material handed over directly. Nothing in this
    /// vector touches ECDH, so it isolates the half RFC 8291 builds on.
    #[test]
    fn the_rfc8188_content_coding_matches_the_section_3_1_vector() {
        let ikm = b64("yqdlZ-tYemfogSmv7Ws5PQ");
        let salt: [u8; SALT_LEN] = fixed("I1BsxtFttlv3u_Oo94xnmw");

        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
        assert_eq!(
            prk.as_slice(),
            b64("zyeH5phsIsgUyd4oiSEIy35x-gIi4aM7y0hCF8mwn9g"),
            "PRK"
        );
        let keys = record_keys(&salt, &ikm);
        assert_eq!(keys.cek.as_slice(), b64("_wniytB-ofscZDh4tbSjHw"), "CEK");
        assert_eq!(keys.nonce.as_slice(), b64("Bcs8gkIRKLI8GeI8"), "NONCE");

        let body = encode(&ikm, &salt, b"", 4096, b"I am the walrus").expect("valid");
        assert_eq!(
            body,
            b64("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg")
        );
        // The body is 53 octets: the RFC's prose ("shown here using 71
        // base64url characters") agrees, and 71 unpadded base64url
        // characters are 53 octets. The `Content-Length: 54` printed above
        // the example is off by one, as is RFC 8291 §5's `Content-Length:
        // 145` for a 144-octet body. The base64url is the normative part
        // and it matches byte for byte.
        assert_eq!(body.len(), 53);
        // "unencrypted data = SSBhbSB0aGUgd2FscnVzAg" — the plaintext with
        // the 0x02 delimiter appended, which is what was encrypted.
        assert_eq!(b64("SSBhbSB0aGUgd2FscnVzAg"), b"I am the walrus\x02");
    }

    /// The limit is arithmetic on the record size, not a remembered number.
    #[test]
    fn the_plaintext_limit_is_computed_from_the_record_size() {
        assert_eq!(max_plaintext(4096), 4096 - 16 - 1);
        assert_eq!(max_plaintext(DEFAULT_RECORD_SIZE), 3993);
        assert_eq!(max_plaintext(MIN_RECORD_SIZE), 1);
        assert_eq!(max_plaintext(0), 0, "saturates rather than wrapping");
        assert_eq!(Ece::default().max_plaintext(), 3993);

        // 3993 is exactly RFC 8291 §4's own number, and it is the number
        // that makes the whole body fit the 4096 octets RFC 8030 §7.2
        // requires a push service to accept.
        assert_eq!(Ece::body_len(3993), MIN_SUPPORTED_BODY_LEN);
        assert_eq!(Ece::body_len(3994), MIN_SUPPORTED_BODY_LEN + 1);
    }

    /// The computed limit is the limit the encoder actually enforces, and
    /// the body it produces at the limit is exactly the promised size.
    #[test]
    fn a_body_at_the_limit_is_exactly_4096_octets_and_one_over_is_refused() {
        let ece = Ece::default();
        let keys = vector_keys();
        let salt: [u8; SALT_LEN] = fixed(SALT);
        let as_private: [u8; 32] = fixed(AS_PRIVATE);

        let at_limit = vec![b'a'; ece.max_plaintext()];
        let body = ece
            .seal_with(&keys, &at_limit, &salt, &as_private)
            .expect("the limit is inclusive");
        assert_eq!(body.len(), MIN_SUPPORTED_BODY_LEN);
        assert_eq!(body.len(), WEB_PUSH_HEADER_LEN + at_limit.len() + 17);

        let one_over = vec![b'a'; ece.max_plaintext() + 1];
        let error = ece
            .seal_with(&keys, &one_over, &salt, &as_private)
            .unwrap_err();
        assert!(
            matches!(error, EceError::PayloadTooLarge { plaintext, limit, .. }
                if plaintext == 3994 && limit == 3993),
            "{error}"
        );
        assert!(error.to_string().contains("payload too large"), "{error}");

        // A raised record size raises the limit with it, by the same
        // arithmetic — nothing is hardcoded.
        let wide = Ece::new(8192).expect("valid");
        assert_eq!(wide.max_plaintext(), 8175);
        assert!(wide.seal_with(&keys, &one_over, &salt, &as_private).is_ok());
    }

    #[test]
    fn a_record_size_below_the_rfc_floor_is_refused() {
        assert!(matches!(Ece::new(17), Err(EceError::RecordSize(17))));
        assert!(Ece::new(MIN_RECORD_SIZE).is_ok());
    }

    #[test]
    fn a_malformed_subscription_is_refused_by_name() {
        // Not base64url at all.
        assert!(matches!(
            SubscriptionKeys::parse("!!!!", AUTH_SECRET),
            Err(EceError::SubscriptionKey(_))
        ));
        // A compressed point: right curve, wrong form, and `key_info` would
        // silently disagree with the browser's.
        let compressed = URL_SAFE_NO_PAD.encode([0x02u8; 33]);
        assert!(matches!(
            SubscriptionKeys::parse(&compressed, AUTH_SECRET),
            Err(EceError::SubscriptionKey(_))
        ));
        // Right length and prefix, not on the curve.
        let mut off_curve = b64(UA_PUBLIC);
        off_curve[64] ^= 0x01;
        assert!(matches!(
            SubscriptionKeys::parse(&URL_SAFE_NO_PAD.encode(&off_curve), AUTH_SECRET),
            Err(EceError::SubscriptionKey(_))
        ));
        // A 12-byte auth secret is not a 16-byte one.
        assert!(matches!(
            SubscriptionKeys::parse(UA_PUBLIC, &URL_SAFE_NO_PAD.encode([0u8; 12])),
            Err(EceError::AuthSecret(12))
        ));
        // Padded base64url is accepted: the same keys, after a round trip
        // through a library that pads.
        assert!(
            SubscriptionKeys::parse(
                &URL_SAFE.encode(b64(UA_PUBLIC)),
                &URL_SAFE.encode(b64(AUTH_SECRET))
            )
            .is_ok()
        );
    }

    #[test]
    fn the_subscription_keys_never_print_themselves() {
        let printed = format!("{:?}", vector_keys());
        assert_eq!(printed, "SubscriptionKeys { .. }");
    }

    /// Two calls to `seal` must not agree on anything: a repeated salt with
    /// a repeated ephemeral key repeats the (CEK, nonce) pair, which is the
    /// one thing AES-GCM cannot survive.
    #[test]
    fn seal_draws_a_fresh_salt_and_key_every_time() {
        let keys = vector_keys();
        let first = Ece::default()
            .seal(&keys, b"same plaintext")
            .expect("sealed");
        let second = Ece::default()
            .seal(&keys, b"same plaintext")
            .expect("sealed");
        assert_ne!(first[..SALT_LEN], second[..SALT_LEN], "salt");
        assert_ne!(
            first[HEADER_FIXED_LEN..WEB_PUSH_HEADER_LEN],
            second[HEADER_FIXED_LEN..WEB_PUSH_HEADER_LEN],
            "ephemeral public key"
        );
        assert_ne!(first, second);
        assert_eq!(first.len(), second.len());
    }

    #[test]
    fn an_oversize_payload_is_refused_before_any_randomness_is_drawn() {
        let ece = Ece::default();
        let error = ece
            .seal(&vector_keys(), &vec![b'a'; ece.max_plaintext() + 1])
            .unwrap_err();
        assert!(matches!(error, EceError::PayloadTooLarge { .. }), "{error}");
    }

    #[test]
    fn a_random_scalar_is_a_usable_private_key() {
        let scalar = random_scalar().expect("randomness");
        assert!(SecretKey::from_slice(scalar.as_slice()).is_ok());
        assert_ne!(scalar, random_scalar().expect("randomness"));
    }

    /// A subscription that came back through an encoder using the
    /// **standard** base64 alphabet is the same subscription.
    ///
    /// The `p256dh` below contains both `+` and `/` in that alphabet, which
    /// is exactly the value that could never be pushed to while only the
    /// URL-safe alphabet was accepted — and "never" meant permanently, since
    /// only the browser can re-subscribe.
    #[test]
    fn a_subscription_re_encoded_with_the_standard_alphabet_is_accepted() {
        let standard = STANDARD_NO_PAD.encode(b64(UA_PUBLIC));
        assert!(standard.contains('+'), "{standard}");
        assert!(standard.contains('/'), "{standard}");

        // The same keys, three encodings, one body: whichever alphabet the
        // subscription arrived in, the schedule is identical.
        let canonical = vector_keys();
        for p256dh in [standard.clone(), STANDARD.encode(b64(UA_PUBLIC))] {
            let keys = SubscriptionKeys::parse(&p256dh, AUTH_SECRET)
                .unwrap_or_else(|err| panic!("{p256dh}: {err}"));
            let salt: [u8; SALT_LEN] = fixed(SALT);
            let as_private: [u8; 32] = fixed(AS_PRIVATE);
            assert_eq!(
                Ece::default()
                    .seal_with(&keys, b"x", &salt, &as_private)
                    .ok(),
                Ece::default()
                    .seal_with(&canonical, b"x", &salt, &as_private)
                    .ok(),
                "{p256dh}"
            );
        }

        // The `auth` secret travels the same road.
        assert!(
            SubscriptionKeys::parse(UA_PUBLIC, &STANDARD_NO_PAD.encode(b64(AUTH_SECRET))).is_ok()
        );
    }
}
