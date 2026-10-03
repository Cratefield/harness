//! Client-secret cryptography (issue #6). Plaintext secrets exist once,
//! in the create/rotate response; the database stores only argon2id PHC
//! strings. Parameters are the ADR 0200 recommendation (m=19456 KiB,
//! t=2, p=1 — OWASP minimal, measured on a Worker).
//!
//! Verification re-derives the hash with the parameters read back from
//! the stored PHC string and compares digests with the harness
//! [`constant_time_eq`](cratefield_core::constant_time_eq) helper, so no
//! secret comparison is timing-sensitive.

use argon2::{Algorithm, Argon2, Params, Version, password_hash::phc::PasswordHash};
use base64ct::{Base64Unpadded as PhcB64, Base64UrlUnpadded, Encoding};
use cratefield_core::{Config, constant_time_eq};

use crate::store::{CLIENT_CONFIDENTIAL, ClientRow};

/// Random bytes in a generated secret or session value.
pub const SECRET_BYTES: usize = 32;

const M_COST: u32 = 19_456;
const T_COST: u32 = 2;
const P_COST: u32 = 1;
const SALT_BYTES: usize = 16;

/// A generated secret that could not be hashed (OS entropy or argon2
/// failure). The plaintext never leaves the failing call.
#[derive(Debug, thiserror::Error)]
#[error("secret hashing failed: {0}")]
pub struct SecretError(String);

/// 32 random bytes, base64url, no padding: the shape of every client
/// secret this module hands out.
///
/// # Errors
///
/// [`SecretError`] when the OS entropy source fails.
pub fn generate_secret() -> Result<String, SecretError> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|err| SecretError(err.to_string()))?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

/// Hashes a secret as an argon2id PHC string with a fresh random salt.
///
/// # Errors
///
/// [`SecretError`] when the OS entropy source or argon2 fails.
pub fn hash_secret(secret: &str) -> Result<String, SecretError> {
    let mut salt = [0u8; SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|err| SecretError(err.to_string()))?;
    let params = Params::new(M_COST, T_COST, P_COST, Some(SECRET_BYTES))
        .map_err(|err| SecretError(err.to_string()))?;
    let mut out = [0u8; SECRET_BYTES];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret.as_bytes(), &salt, &mut out)
        .map_err(|err| SecretError(err.to_string()))?;
    Ok(format!(
        "$argon2id$v={v}$m={m},t={t},p={p}${salt}${hash}",
        v = Version::V0x13 as u32,
        m = M_COST,
        t = T_COST,
        p = P_COST,
        salt = PhcB64::encode_string(&salt),
        hash = PhcB64::encode_string(&out),
    ))
}

/// Verifies a presented secret against one stored PHC string: parses the
/// PHC, re-derives with its own parameters and salt, and compares the
/// digests in constant time. Malformed stored strings and non-argon2id
/// algorithms verify as `false`, never panic.
#[must_use]
pub fn verify_secret(presented: &str, stored_phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_phc) else {
        return false;
    };
    if parsed.algorithm.as_str() != Algorithm::Argon2id.as_str() {
        return false;
    }
    let (Some(salt), Some(expected)) = (parsed.salt, parsed.hash) else {
        return false;
    };
    let Ok(params) = Params::try_from(&parsed) else {
        return false;
    };
    let mut derived = vec![0u8; expected.as_ref().len()];
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(presented.as_bytes(), salt.as_ref(), &mut derived)
        .is_ok()
        && constant_time_eq(&derived, expected.as_ref())
}

/// Verifies a presented secret against a client, honoring the rotation
/// overlap: the current secret always verifies; the previous one
/// verifies only while `previous_hash_expires_at` is still in the
/// future (`now`, RFC 3339, from the `Clock` port). Public clients hold
/// a hash of a discarded secret, so nothing ever verifies — they have no
/// secret by construction.
#[must_use]
pub fn verify_client_secret(client: &ClientRow, presented: &str, now: &str) -> bool {
    if verify_secret(presented, &client.secret_hash.0) {
        return true;
    }
    match (
        client.previous_secret_hash.as_ref(),
        &client.previous_hash_expires_at,
    ) {
        (Some(previous), Some(expires_at)) if expires_at.as_str() > now => {
            verify_secret(presented, &previous.0)
        }
        _ => false,
    }
}

/// Whether a client may take part in any runtime flow. Disabled clients
/// fail every flow with one stable problem type (issue #6).
///
/// # Errors
///
/// The `auth/client-disabled` problem when the client is disabled.
pub fn ensure_client_usable(client: &ClientRow) -> Result<(), cratefield_core::Problem> {
    if client.status != crate::store::STATUS_ACTIVE {
        return Err(cratefield_core::Problem::new(&CLIENT_DISABLED));
    }
    Ok(())
}

/// Stable problem for a disabled client, refused at `/authorize` and
/// `/token` (wired there by issues #9 and #10).
pub const CLIENT_DISABLED: cratefield_core::ProblemDef = cratefield_core::ProblemDef {
    slug: "auth/client-disabled",
    status: axum::http::StatusCode::FORBIDDEN,
    title: "Client is disabled",
    description: "A disabled client is refused by every flow",
};

/// A confidential client authenticates with a secret; a public client
/// (browser or native app) has none and relies on PKCE.
#[must_use]
pub fn kind_allows_secret(kind: &str) -> bool {
    kind == CLIENT_CONFIDENTIAL
}

// ---------------------------------------------------------------------------
// Passwords (issues #19, #20)

/// Hashes a password as an argon2id PHC string.
///
/// The same parameters and the same code path as a client secret, on
/// purpose: ADR 0200 measured one set of parameters on Workers and there
/// is no reason a password should get weaker ones. Wrapping rather than
/// duplicating means the ADR's numbers live in exactly one place.
///
/// # Errors
///
/// [`SecretError`] when the OS entropy source or argon2 fails.
pub fn hash_password(password: &str) -> Result<String, SecretError> {
    hash_secret(password)
}

/// Verifies a password against a stored PHC string, in constant time.
///
/// `false` for a malformed or non-argon2id stored value, which is what
/// makes it safe to call with a dummy hash when no credential exists.
/// A caller signing people in should use [`verify_password_with`], which
/// adds the legacy formats a deployment has opted into; this function
/// stays argon2id-only so existing callers cannot silently widen.
#[must_use]
pub fn verify_password(presented: &str, stored_phc: &str) -> bool {
    verify_secret(presented, stored_phc)
}

/// Whether a stored hash was written with parameters we no longer use.
///
/// Login is the only moment the plaintext is available, so it is the only
/// moment a hash can be upgraded. Any bcrypt value says `true` (issue
/// #650): it is the format we used to write, so a login that verified
/// against one is exactly the moment to replace it.
///
/// Beyond that, a stored hash that cannot be parsed says `false`: it will
/// fail verification anyway, and rehashing on the strength of an unreadable
/// value would be guessing.
#[must_use]
pub fn password_needs_rehash(stored_phc: &str) -> bool {
    if BCRYPT_PREFIXES
        .iter()
        .any(|prefix| stored_phc.starts_with(prefix))
    {
        return true;
    }
    let Ok(parsed) = PasswordHash::new(stored_phc) else {
        return false;
    };
    if parsed.algorithm.as_str() != Algorithm::Argon2id.as_str() {
        return true;
    }
    let Ok(params) = Params::try_from(&parsed) else {
        return true;
    };
    params.m_cost() != M_COST || params.t_cost() != T_COST || params.p_cost() != P_COST
}

// ---------------------------------------------------------------------------
// Legacy hashes (issue #650)

/// The config key that lists legacy hash formats login may still accept.
/// Unprefixed: it is a deployment's statement about the hashes it imported,
/// not a module knob.
pub const LEGACY_HASHES_KEY: &str = "AUTH_LEGACY_HASHES";

/// The largest bcrypt cost this service will verify or import.
///
/// A bcrypt hash's cost is its work factor, and the work happens inside one
/// request's CPU budget. Fourteen is already far above what Workers can
/// afford; a hash above it is one we refuse rather than turn into a way to
/// stall the service.
pub const BCRYPT_MAX_COST: u32 = 14;

/// Which legacy hash formats login may accept, resolved from
/// [`LEGACY_HASHES_KEY`] (issue #650).
///
/// Empty by default, because accepting a weaker format is a decision a
/// deployment makes, not one this crate makes for it. Today the only format
/// is bcrypt; the type is a struct rather than a bool so a second one is a
/// field and not a new parameter everywhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyHashes {
    bcrypt: bool,
}

impl LegacyHashes {
    /// Parses the comma-separated [`LEGACY_HASHES_KEY`] value.
    ///
    /// Unset, empty or blank means no legacy formats. `bcrypt` turns on
    /// bcrypt verification; any other entry is an error, because a typo
    /// that silently disabled the flag would present as every legacy
    /// password failing at once.
    ///
    /// # Errors
    ///
    /// A message naming the entry that is not a known format.
    pub fn from_config(cfg: &dyn Config) -> Result<Self, String> {
        let Some(raw) = cfg.get(LEGACY_HASHES_KEY) else {
            return Ok(Self::default());
        };
        let mut legacy = Self::default();
        for entry in raw.split(',').map(str::trim) {
            match entry {
                "" => {}
                "bcrypt" => legacy.bcrypt = true,
                other => {
                    return Err(format!(
                        "{LEGACY_HASHES_KEY} does not know {other:?}; it accepts \"bcrypt\""
                    ));
                }
            }
        }
        Ok(legacy)
    }

    /// Whether bcrypt is one of the formats this deployment opted into.
    ///
    /// The import path reads it (issue #650, part B): a bcrypt hash stored
    /// while login would refuse bcrypt is an account nobody can sign in to,
    /// so the import refuses it instead of writing one.
    #[must_use]
    pub fn allows_bcrypt(&self) -> bool {
        self.bcrypt
    }
}

/// The cost of a well-formed bcrypt hash — `$2a$`, `$2b$` or `$2y$` — and
/// `None` for anything else, including an argon2id PHC string.
///
/// Shape only, which is what makes it usable as an import check: it reads
/// the two-digit cost, insists on the separator and the 22-char salt and
/// 31-char digest that follow it, and leaves the arithmetic to
/// [`verify_password_with`]. It does not apply [`BCRYPT_MAX_COST`]; the
/// caller decides what to do with a cost it does not like.
#[must_use]
pub fn bcrypt_cost(stored: &str) -> Option<u32> {
    let rest = BCRYPT_PREFIXES
        .iter()
        .find_map(|prefix| stored.strip_prefix(prefix))?;
    let (cost, rest) = rest.split_at_checked(2)?;
    let digest = rest.strip_prefix('$')?;
    // 22-char salt + 31-char digest is the only digest a bcrypt hash has.
    if digest.len() != 53 || !digest.chars().all(is_bcrypt_b64) {
        return None;
    }
    let cost: u32 = cost.parse().ok()?;
    (4..=31).contains(&cost).then_some(cost)
}

/// The bcrypt base64 alphabet: `./A-Za-z0-9`.
fn is_bcrypt_b64(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '/'
}

/// The three bcrypt version prefixes, the only values a bcrypt hash starts
/// with.
const BCRYPT_PREFIXES: [&str; 3] = ["$2a$", "$2b$", "$2y$"];

/// Whether a stored value is the argon2id PHC string this crate writes and
/// can verify: it parses, names argon2id, carries a salt and digest, and
/// its parameters are readable.
///
/// Shape only, for the import path (issue #650, part B): a value that says
/// `true` here is one [`verify_password`] will accept the right plaintext
/// against, so an import can store it verbatim rather than silently
/// locking the person out.
#[must_use]
pub fn is_argon2id_phc(stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    parsed.algorithm.as_str() == Algorithm::Argon2id.as_str()
        && parsed.salt.is_some()
        && parsed.hash.is_some()
        && Params::try_from(&parsed).is_ok()
}

/// Verifies a password against a stored value that may be a legacy hash
/// (issue #650).
///
/// argon2id is verified exactly as [`verify_password`] does, so a stored
/// value in the format we write now behaves identically.
///
/// A bcrypt hash is accepted only when `legacy.bcrypt` is set, the hash is
/// well-formed, and its cost is at most [`BCRYPT_MAX_COST`]. The bcrypt
/// crate compares the digest in constant time, so no secret comparison here
/// is timing-sensitive. Flag off, cost above the cap, or an unknown format
/// verifies as `false`, never a panic.
#[must_use]
pub fn verify_password_with(presented: &str, stored: &str, legacy: LegacyHashes) -> bool {
    match bcrypt_cost(stored) {
        // A bcrypt-shaped value is never handed to the argon2 parser: it
        // is either verified as bcrypt, or refused.
        Some(cost) => {
            legacy.bcrypt
                && cost <= BCRYPT_MAX_COST
                && bcrypt::verify(presented, stored).unwrap_or(false)
        }
        None => verify_password(presented, stored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CLIENT_PUBLIC, Redacted};
    use cratefield_core::MapConfig;

    // Never a real secret: fixed test material, obviously fake.
    const SECRET: &str = "test-client-secret-0123456789abcdef";
    const OTHER: &str = "totally-different-secret";

    fn client_with_hashes(
        current: &str,
        previous: Option<&str>,
        expires: Option<&str>,
    ) -> ClientRow {
        ClientRow {
            id: "app1".to_owned(),
            name: "App".to_owned(),
            secret_hash: Redacted(current.to_owned()),
            previous_secret_hash: previous.map(|phc| Redacted(phc.to_owned())),
            previous_hash_expires_at: expires.map(str::to_owned),
            kind: CLIENT_CONFIDENTIAL.to_owned(),
            status: crate::store::STATUS_ACTIVE.to_owned(),
            created_at: "2027-01-15T06:40:00Z".to_owned(),
        }
    }

    #[test]
    fn hash_verifies_and_mismatches_reject() {
        let phc = hash_secret(SECRET).expect("hash");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_secret(SECRET, &phc));
        assert!(!verify_secret(OTHER, &phc));
    }

    #[test]
    fn salts_differ_so_identical_secrets_hash_differently() {
        let a = hash_secret(SECRET).expect("hash a");
        let b = hash_secret(SECRET).expect("hash b");
        assert_ne!(a, b);
        assert!(verify_secret(SECRET, &a) && verify_secret(SECRET, &b));
    }

    #[test]
    fn malformed_stored_strings_verify_false() {
        assert!(!verify_secret(SECRET, "not-a-phc-string"));
        assert!(!verify_secret(
            SECRET,
            "$argon2i$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA"
        ));
        assert!(!verify_secret(SECRET, ""));
    }

    #[test]
    fn rotation_overlap_honors_the_expiry_instant() {
        let old = hash_secret("old-secret-abcdef").expect("old hash");
        let new = hash_secret("new-secret-abcdef").expect("new hash");
        let expires = "2027-01-16T06:40:00Z";
        let client = client_with_hashes(&new, Some(&old), Some(expires));

        assert!(verify_client_secret(
            &client,
            "new-secret-abcdef",
            "2027-01-15T07:00:00Z"
        ));
        assert!(verify_client_secret(
            &client,
            "old-secret-abcdef",
            "2027-01-15T07:00:00Z"
        ));
        assert!(
            !verify_client_secret(&client, "old-secret-abcdef", "2027-01-16T06:40:00Z"),
            "the overlap ends at the instant itself"
        );
        assert!(verify_client_secret(
            &client,
            "new-secret-abcdef",
            "2027-01-16T06:40:00Z"
        ));
        assert!(!verify_client_secret(
            &client,
            "unrelated",
            "2027-01-15T07:00:00Z"
        ));
    }

    #[test]
    fn expired_overlap_only_ever_held_the_previous_hash() {
        let old = hash_secret("old-secret-abcdef").expect("old hash");
        let client = client_with_hashes(&old, None, None);
        assert!(verify_client_secret(
            &client,
            "old-secret-abcdef",
            "2099-01-01T00:00:00Z"
        ));
    }

    #[test]
    fn public_clients_hold_only_discarded_secrets() {
        let discarded =
            hash_secret(&generate_secret().expect("generate")).expect("hash of a discarded secret");
        let mut client = client_with_hashes(&discarded, None, None);
        client.kind = CLIENT_PUBLIC.to_owned();
        assert!(
            !verify_client_secret(&client, "anything-at-all", "2027-01-15T07:00:00Z"),
            "nobody can know a discarded secret's preimage"
        );
    }

    #[test]
    fn disabled_clients_fail_the_usability_check_with_the_stable_problem() {
        let phc = hash_secret(SECRET).expect("hash");
        let mut client = client_with_hashes(&phc, None, None);
        assert!(ensure_client_usable(&client).is_ok());
        client.status = crate::store::STATUS_DISABLED.to_owned();
        let problem = ensure_client_usable(&client).expect_err("disabled");
        assert_eq!(problem.slug, "auth/client-disabled");
        assert_eq!(problem.status, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn generated_secrets_are_43_chars_of_base64url() {
        let secret = generate_secret().expect("generate");
        assert_eq!(secret.len(), 43);
        assert!(!secret.contains(['+', '/', '=']));
        assert_ne!(secret, generate_secret().expect("second"));
        assert!(kind_allows_secret(CLIENT_CONFIDENTIAL));
        assert!(!kind_allows_secret(CLIENT_PUBLIC));
    }

    // Legacy bcrypt material (issue #650). Deterministic cost-4 hashes —
    // the same salt and digest under each of the three version spellings,
    // generated once with the bcrypt crate at cost 4 so a test run pays the
    // lowest work factor the format allows. Obviously fake.
    const BCRYPT_PASSWORD: &str = "legacy-password-1";
    const BCRYPT_2A: &str = "$2a$04$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2";
    const BCRYPT_2B: &str = "$2b$04$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2";
    const BCRYPT_2Y: &str = "$2y$04$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2";
    /// A well-formed cost-15 hash (the digest is irrelevant; the cap is
    /// checked before any work is done, and the string is never verified).
    const BCRYPT_TOO_EXPENSIVE: &str =
        "$2b$15$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2";

    fn bcrypt_only() -> LegacyHashes {
        LegacyHashes { bcrypt: true }
    }

    #[test]
    fn bcrypt_verifies_when_the_flag_is_set() {
        for hash in [BCRYPT_2A, BCRYPT_2B, BCRYPT_2Y] {
            assert_eq!(bcrypt_cost(hash), Some(4), "{hash}");
            assert!(
                verify_password_with(BCRYPT_PASSWORD, hash, bcrypt_only()),
                "{hash} did not verify"
            );
        }
    }

    #[test]
    fn a_wrong_password_fails_against_bcrypt() {
        assert!(!verify_password_with("not it", BCRYPT_2B, bcrypt_only()));
        assert!(!verify_password_with("", BCRYPT_2B, bcrypt_only()));
    }

    #[test]
    fn bcrypt_needs_the_flag() {
        assert!(!verify_password_with(
            BCRYPT_PASSWORD,
            BCRYPT_2B,
            LegacyHashes::default()
        ));
        // The argon2id form is unaffected by the flag either way.
        let argon = hash_password(BCRYPT_PASSWORD).expect("hash");
        assert!(verify_password_with(
            BCRYPT_PASSWORD,
            &argon,
            LegacyHashes::default()
        ));
        assert!(verify_password_with(BCRYPT_PASSWORD, &argon, bcrypt_only()));
    }

    #[test]
    fn an_expensive_bcrypt_hash_is_refused() {
        assert_eq!(bcrypt_cost(BCRYPT_TOO_EXPENSIVE), Some(15));
        assert!(!verify_password_with(
            BCRYPT_PASSWORD,
            BCRYPT_TOO_EXPENSIVE,
            bcrypt_only()
        ));
    }

    #[test]
    fn only_well_formed_bcrypt_is_recognised() {
        for unknown in [
            // MD5-crypt: a `$1$` PHC, not bcrypt.
            "$1$abcdefgh$0123456789abcdefghijklmnop",
            "plain",
            "",
            // A bcrypt prefix with the wrong shape.
            "$2b$04$tooshort",
            "$2b$zz$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2",
            // Cost out of the format's own range.
            "$2b$99$.OGB/.SE/ueHAeqKBO2NC.Idt9kRB2ygG15erMmtNyb.8scW/Kmw2",
        ] {
            assert_eq!(bcrypt_cost(unknown), None, "{unknown:?}");
            assert!(
                !verify_password_with(BCRYPT_PASSWORD, unknown, bcrypt_only()),
                "{unknown:?} was accepted"
            );
        }
    }

    #[test]
    fn bcrypt_is_always_rehashed() {
        for hash in [BCRYPT_2A, BCRYPT_2B, BCRYPT_2Y, BCRYPT_TOO_EXPENSIVE] {
            assert!(password_needs_rehash(hash), "{hash}");
        }
        // Any bcrypt prefix counts, well-formed or not: a login that
        // verified against one is the moment to replace it.
        assert!(password_needs_rehash("$2b$04$not-really-a-hash"));
        let argon = hash_password("a password").expect("hash");
        assert!(!password_needs_rehash(&argon));
        // Unparseable and not bcrypt: rehashing on it would be guessing.
        assert!(!password_needs_rehash("not-a-phc-string"));
    }

    #[test]
    fn from_config_parses_the_legacy_list() {
        let cfg = |value: &str| MapConfig::from_pairs([(LEGACY_HASHES_KEY, value)]);
        // Unset and empty both mean none.
        assert_eq!(
            LegacyHashes::from_config(&MapConfig::default()).expect("unset"),
            LegacyHashes::default()
        );
        assert_eq!(
            LegacyHashes::from_config(&cfg("")).expect("empty"),
            LegacyHashes::default()
        );
        assert_eq!(
            LegacyHashes::from_config(&cfg(" , ")).expect("blank"),
            LegacyHashes::default()
        );
        // `bcrypt` turns on bcrypt, whatever the spacing.
        assert!(
            LegacyHashes::from_config(&cfg("bcrypt"))
                .expect("bcrypt")
                .bcrypt,
            "the flag reads as on"
        );
        assert!(
            LegacyHashes::from_config(&cfg("  bcrypt , "))
                .expect("spaced")
                .bcrypt,
            "spacing and an empty entry are tolerated"
        );
        // Anything else is a configuration error.
        for bad in ["sha1", "bcrypt,sha1", "true", "BCRYPT"] {
            assert!(
                LegacyHashes::from_config(&cfg(bad)).is_err(),
                "{bad:?} was accepted"
            );
        }
    }
}
