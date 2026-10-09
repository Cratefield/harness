//! Pure policy builders: the `EFFECT_ALLOW` conditions and the
//! delegated-access consensus Turnkey's policy engine evaluates, plus
//! the strict validators that make them injection-proof.
//!
//! The policy language is a small expression language over single-quoted
//! strings (only single quotes, no escape syntax — anything carrying a
//! `'` can only ever break out by *being* a quote), so every caller
//! string that reaches a condition passes a validator that admits
//! nothing but the exact shape Turnkey itself would accept: lowercase
//! `0x` + 40 hex for an address, `0x` + 8 hex for a selector, and a
//! base58 string decoding to 32 bytes for a Solana program key. What a
//! builder emits is what the validator let in — nothing more.

use cratefield_signer::SignerError;

/// One allow rule: the shapes of signing the delegated access user may
/// approve, each turned into one `EFFECT_ALLOW` policy scoped to that
/// user. Anything not covered by a rule is refused by Turnkey itself —
/// the default answer out there, as in [`cratefield_signer`]'s own
/// guardrails, is no.
///
/// The string fields are validated newtypes with no other constructor,
/// so a struct literal cannot forge a rule: [`Self::condition`] can
/// interpolate them raw because validation happened where they were
/// built.
///
/// ```compile_fail
/// use cratefield_adapter_turnkey::AllowRule;
///
/// // `to` is an `EvmAddress`, not a `String`: a raw string — a quoted
/// // address, or a policy-expression fragment — has no way in.
/// let _forged = AllowRule::Evm {
///     chain_id: 1,
///     to: String::from("0x000000000000000000000000000000000000aaaa"),
///     selector: None,
///     max_value: None,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowRule {
    /// An EVM transaction: on `chain_id`, to `to`, and — when set —
    /// calling `selector` and sending at most `max_value` wei.
    Evm {
        /// The chain the transaction must commit to.
        chain_id: u64,
        /// The recipient address. Not the zero address unless that is
        /// meant: Turnkey compares the literal string.
        to: EvmAddress,
        /// The four-byte function selector, matched against the first
        /// four calldata bytes.
        selector: Option<Selector>,
        /// The largest value the rule allows, in wei. A cap past
        /// `i128::MAX` is refused by [`Self::evm`]: Turnkey's policy
        /// engine computes in `i128`, and a condition it cannot
        /// evaluate is one it errors on.
        max_value: Option<u128>,
    },
    /// A Solana message every one of whose instructions calls
    /// `program_key`.
    Solana {
        /// The program pubkey.
        program_key: ProgramKey,
    },
}

impl AllowRule {
    /// An EVM rule, validating `to` and `selector` on the way in.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when an address or selector is not the
    /// strict shape the policy condition embeds.
    pub fn evm(
        chain_id: u64,
        to: &str,
        selector: Option<&str>,
        max_value: Option<u128>,
    ) -> Result<Self, SignerError> {
        if let Some(max_value) = max_value {
            // Turnkey's policy engine computes in i128; a cap it cannot
            // represent is a condition that errors instead of deciding.
            if max_value > i128::MAX as u128 {
                return Err(SignerError::Invalid(
                    "a value cap must fit the policy engine's i128".to_owned(),
                ));
            }
        }
        Ok(Self::Evm {
            chain_id,
            to: EvmAddress::new(to)?,
            selector: selector.map(Selector::new).transpose()?,
            max_value,
        })
    }

    /// A Solana rule, validating the program key on the way in.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when the program key is not base58
    /// decoding to exactly 32 bytes.
    pub fn solana(program_key: &str) -> Result<Self, SignerError> {
        Ok(Self::Solana {
            program_key: ProgramKey::new(program_key)?,
        })
    }

    /// The condition expression this rule becomes, as sent in
    /// `ACTIVITY_TYPE_CREATE_POLICY_V3`'s `condition`.
    #[must_use]
    pub fn condition(&self) -> String {
        match self {
            Self::Evm {
                chain_id,
                to,
                selector,
                max_value,
            } => {
                let mut clauses = vec![
                    format!("eth.tx.to == '{}'", to.as_str()),
                    format!("eth.tx.chain_id == {chain_id}"),
                ];
                if let Some(selector) = selector {
                    clauses.push(format!("eth.tx.data[0..10] == '{}'", selector.as_str()));
                }
                if let Some(max_value) = max_value {
                    clauses.push(format!("eth.tx.value <= {max_value}"));
                }
                clauses.join(" && ")
            }
            Self::Solana { program_key } => format!(
                "solana.tx.instructions.all(i, i.program_key == '{}')",
                program_key.as_str()
            ),
        }
    }
}

/// An EVM address: lowercase `0x` + 40 hex, and nothing else. The inner
/// string is private and there is no `From`, so a struct literal — or a
/// caller string that skipped [`Self::new`] — cannot forge one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmAddress(String);

impl EvmAddress {
    /// Validates and lowercases `address`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when it is not `0x` + 40 hex.
    pub fn new(address: &str) -> Result<Self, SignerError> {
        validate_address(address).map(Self)
    }

    /// The validated address, as a condition embeds it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A four-byte function selector: lowercase `0x` + 8 hex, private inner
/// string, constructible only through [`Self::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector(String);

impl Selector {
    /// Validates and lowercases `selector`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when it is not `0x` + 8 hex.
    pub fn new(selector: &str) -> Result<Self, SignerError> {
        validate_selector(selector).map(Self)
    }

    /// The validated selector, as a condition embeds it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Solana program key: base58 decoding to exactly 32 bytes, private
/// inner string, constructible only through [`Self::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramKey(String);

impl ProgramKey {
    /// Validates `program_key` by decoding it.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when it is not base58 decoding to
    /// exactly 32 bytes.
    pub fn new(program_key: &str) -> Result<Self, SignerError> {
        validate_program_key(program_key).map(Self)
    }

    /// The validated key, as a condition embeds it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The consensus expression scoping a policy to the delegated access
/// user: the activity happens when that user's API-key stamp approves
/// it, and no one else's.
///
/// # Errors
///
/// [`SignerError::Invalid`] when `da_user_id` is not a Turnkey-style
/// UUID.
pub fn da_consensus(da_user_id: &str) -> Result<String, SignerError> {
    validate_turnkey_id(da_user_id)?;
    Ok(format!("approvers.any(user, user.id == '{da_user_id}')"))
}

/// An address: lowercase `0x` + 40 hex. Anything else — uppercase,
/// wrong length, a quote, a non-hex byte — is refused rather than
/// embedded.
///
/// # Errors
///
/// [`SignerError::Invalid`] with the reason.
pub fn validate_address(address: &str) -> Result<String, SignerError> {
    hex_word(address, 40).map_err(|reason| {
        SignerError::Invalid(format!(
            "an EVM address is 0x + 40 hex, got `{address}`: {reason}"
        ))
    })
}

/// A four-byte function selector: lowercase `0x` + 8 hex.
///
/// # Errors
///
/// [`SignerError::Invalid`] with the reason.
pub fn validate_selector(selector: &str) -> Result<String, SignerError> {
    hex_word(selector, 8).map_err(|reason| {
        SignerError::Invalid(format!(
            "a selector is 0x + 8 hex, got `{selector}`: {reason}"
        ))
    })
}

/// A Solana program key: base58 decoding to exactly 32 bytes. Decoding
/// is the check — a string that only *looks* base58 (`0OIl` are not in
/// the alphabet, a quote is not either) never reaches a condition.
///
/// # Errors
///
/// [`SignerError::Invalid`] with the reason.
pub fn validate_program_key(program_key: &str) -> Result<String, SignerError> {
    match bs58::decode(program_key).into_vec() {
        Ok(bytes) if bytes.len() == 32 => Ok(program_key.to_owned()),
        Ok(bytes) => Err(SignerError::Invalid(format!(
            "a Solana program key decodes to 32 bytes, `{program_key}` decodes to {}",
            bytes.len()
        ))),
        Err(err) => Err(SignerError::Invalid(format!(
            "a Solana program key is base58, got `{program_key}`: {err}"
        ))),
    }
}

/// A Turnkey object id (sub-organization, user, policy): a UUID. This is
/// the injection guard for ids this crate embeds in conditions, paths
/// and body fields.
///
/// # Errors
///
/// [`SignerError::Invalid`] when the id is not 8-4-4-4-12 hex.
pub fn validate_turnkey_id(id: &str) -> Result<String, SignerError> {
    let valid = id.len() == 36
        && id.as_bytes()[8] == b'-'
        && id.as_bytes()[13] == b'-'
        && id.as_bytes()[18] == b'-'
        && id.as_bytes()[23] == b'-'
        && id
            .bytes()
            .enumerate()
            .all(|(at, byte)| matches!(at, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit());
    if valid {
        Ok(id.to_owned())
    } else {
        Err(SignerError::Invalid(format!(
            "a Turnkey id is a UUID, got `{id}`"
        )))
    }
}

/// One `0x`-prefixed hex word of exactly `digits` digits, lowercased.
fn hex_word(text: &str, digits: usize) -> Result<String, String> {
    let body = text.strip_prefix("0x").ok_or("missing the 0x prefix")?;
    if body.len() != digits {
        return Err(format!(
            "{digits} hex digits expected, found {}",
            body.len()
        ));
    }
    if !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("non-hex character".to_owned());
    }
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "0x000000000000000000000000000000000000aaaa";
    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    #[test]
    fn the_evm_condition_names_to_chain_selector_and_cap() {
        let rule =
            AllowRule::evm(1, ADDRESS, Some("0xA9059CBB"), Some(1_000_000)).expect("a valid rule");
        assert_eq!(
            rule.condition(),
            concat!(
                "eth.tx.to == '0x000000000000000000000000000000000000aaaa'",
                " && eth.tx.chain_id == 1",
                " && eth.tx.data[0..10] == '0xa9059cbb'",
                " && eth.tx.value <= 1000000"
            )
        );
    }

    #[test]
    fn the_solana_condition_binds_every_instruction() {
        let rule = AllowRule::solana(TOKEN_PROGRAM).expect("a valid program key");
        assert_eq!(
            rule.condition(),
            format!("solana.tx.instructions.all(i, i.program_key == '{TOKEN_PROGRAM}')")
        );
    }

    #[test]
    fn the_consensus_scopes_to_the_delegated_user() {
        let id = "11111111-2222-3333-4444-555555555555";
        assert_eq!(
            da_consensus(id).expect("a valid id"),
            format!("approvers.any(user, user.id == '{id}')")
        );
    }

    #[test]
    fn validators_reject_injection_and_typo_shapes() {
        for bad in [
            "' OR '1'=='1",                               // a quote never survives validation
            "0xAAAA",                                     // right prefix, wrong length
            "0x000000000000000000000000000000000000aaa",  // 39 digits
            "0x000000000000000000000000000000000000aaag", // `g` is not hex
            "000000000000000000000000000000000000aaaa",   // no prefix
        ] {
            assert!(validate_address(bad).is_err(), "`{bad}` must not pass");
        }
        for bad in [
            "0xA9059CBB0",    // nine digits
            "0xa9059c",       // four bytes of a twenty-byte address
            "\"0xa9059cbb\"", // JSON quoting is not hex
        ] {
            assert!(validate_selector(bad).is_err(), "`{bad}` must not pass");
        }
        for bad in [
            // 45 characters — decodes past 32 bytes. (A *single-character*
            // typo decodes to a different but valid 32-byte key: base58
            // carries no checksum, so shape-validation cannot catch it —
            // the policies are what bound the key to real programs.)
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DAA",
            "0xdeadbeef", // hex is not base58 (0, x are not in the alphabet)
            "l1O0placeholderl1O0placeholderl1O0placeholderxx", // 0, O, l, I excluded
            "' OR '1'=='1",
        ] {
            assert!(validate_program_key(bad).is_err(), "`{bad}` must not pass");
        }
        for bad in [
            "not-a-uuid",
            "11111111-2222-3333-4444-55555555555",  // 35 chars
            "11111111-2222-3333-4444-55555555555'", // a quote past the shape
            "111111112222333344445555555555555555", // no dashes
        ] {
            assert!(validate_turnkey_id(bad).is_err(), "`{bad}` must not pass");
        }
    }

    #[test]
    fn validators_normalise_hex_case_and_keep_base58_exactly() {
        assert_eq!(
            validate_address("0x000000000000000000000000000000000000AAAA").expect("valid"),
            ADDRESS
        );
        assert_eq!(
            validate_selector("0xA9059CBB").expect("valid"),
            "0xa9059cbb"
        );
        assert_eq!(
            validate_program_key(TOKEN_PROGRAM).expect("valid"),
            TOKEN_PROGRAM
        );
    }

    #[test]
    fn a_rule_cannot_be_forged_by_struct_literal() {
        // The compile_fail doctest on `AllowRule` pins the type-level
        // half; this is the runtime twin: the newtype constructors are
        // the validators, so a rule assembled from their output embeds
        // exactly what was validated.
        let rule = AllowRule::Evm {
            chain_id: 1,
            to: EvmAddress::new(ADDRESS).expect("a valid address"),
            selector: Some(Selector::new("0xA9059CBB").expect("a valid selector")),
            max_value: Some(1_000),
        };
        assert_eq!(
            rule.condition(),
            concat!(
                "eth.tx.to == '0x000000000000000000000000000000000000aaaa'",
                " && eth.tx.chain_id == 1",
                " && eth.tx.data[0..10] == '0xa9059cbb'",
                " && eth.tx.value <= 1000"
            )
        );
        // And the constructors themselves validate: a fragment that
        // would break out of the single-quoted string has nowhere to go.
        for bad in ["' OR '1'=='1", "0xAAAA"] {
            assert!(EvmAddress::new(bad).is_err(), "`{bad}` must not pass");
            assert!(Selector::new(bad).is_err(), "`{bad}` must not pass");
            assert!(ProgramKey::new(bad).is_err(), "`{bad}` must not pass");
        }
    }

    #[test]
    fn a_cap_past_the_policy_engines_int_width_is_refused() {
        let err = AllowRule::evm(1, ADDRESS, None, Some(u128::MAX))
            .expect_err("i128 is the engine's width");
        assert!(matches!(err, SignerError::Invalid(_)), "got: {err:?}");
    }
}
