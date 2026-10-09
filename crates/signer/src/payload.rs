//! The payloads a venture asks to have signed, and what this crate can
//! say about each of them: which scheme signs it, what digest the
//! signature is over, and the decoded [`Intent`] the guardrails read.
//!
//! The signing hashes are computed here, from first principles, not
//! trusted from the caller: RLP + keccak256 for the EIP-1559 transaction,
//! the v0.7 `userOpHash` for the packed `UserOperation`, and
//! `keccak256(0x1901 || domain separator || struct hash)` for EIP-712.

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::port::SignerError;
use crate::rlp;

/// A selector this crate recognises when decoding intent: ERC-4337 v0.7
/// `execute(address,uint256,bytes)`.
pub const SELECTOR_EXECUTE: [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];

/// Which chain a payload is for. Carries the EVM chain id, which the
/// signing hashes commit to, so a signed payload replayed on another
/// chain fails at verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    /// An EVM chain, by id.
    Evm {
        /// The chain id (1 for mainnet).
        chain_id: u64,
    },
    /// Solana.
    Solana,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Evm { chain_id } => write!(f, "eip155:{chain_id}"),
            Self::Solana => f.write_str("solana"),
        }
    }
}

/// What a call does, once decoded — the thing the guardrails read
/// instead of raw calldata. One shape for every payload kind; fields the
/// payload has no answer for are `None`, never invented.
///
/// Downstream comparisons (allowlists) can rely on `to` and
/// `verifying_contract` being lowercase `0x` hex and `programs` base58
/// pubkeys — this crate never emits any other form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// Which chain the payload commits to.
    pub chain: Chain,
    /// The recipient, for an EVM transaction (`None` for a contract
    /// creation) or the callee of a decoded `UserOperation` `execute`.
    pub to: Option<String>,
    /// The first four bytes of EVM calldata, `0x`-prefixed, when there
    /// are at least four.
    pub selector: Option<String>,
    /// The value sent, in decimal, when the payload carries one and it
    /// fits a `u128`. A value that does not fit refuses to sign rather
    /// than truncate.
    pub value: Option<String>,
    /// The base58 program ids the Solana message invokes. A program id
    /// behind a v0 lookup table, which the message alone cannot resolve,
    /// is reported as `lt:{index}` — a string that is not valid base58,
    /// so an allowlist entry can never silently absorb it.
    pub programs: Vec<String>,
    /// The contract the intent is aimed at beyond the recipient: the
    /// EIP-712 domain's `verifyingContract`, or the `UserOperation`'s
    /// entry point — the contract a guardrail should pin before
    /// trusting anything else about the payload.
    pub verifying_contract: Option<String>,
}

/// Something to sign. Every variant is a plain serialisable struct; the
/// signing hash is derived on demand by [`Payload::payload_hash`], and
/// the guardrail view by [`Payload::intent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    /// An EIP-1559 (type 2) transaction. The crate computes the signing
    /// hash `keccak256(0x02 || rlp([...]))` itself.
    EvmTransaction(EvmTransaction),
    /// An ERC-4337 v0.7 packed `UserOperation`, plus the coordinates the
    /// `userOpHash` binds it with. The crate computes the hash per the
    /// v0.7 `EntryPoint.getUserOpHash`.
    UserOperation(UserOperation),
    /// EIP-712 typed data, split into the domain and the caller's
    /// already-encoded primary struct hash (the crate encodes the
    /// domain; encoding arbitrary nested structs is the caller's ABI
    /// job). The digest is `keccak256(0x1901 || domain separator ||
    /// struct hash)`, per the EIP.
    Eip712(Eip712),
    /// A raw Solana wire message (legacy or v0): header, account keys,
    /// blockhash, instructions. ed25519 signs the bytes as they are.
    SolanaMessage(SolanaMessage),
}

impl Payload {
    /// Which scheme signs this payload.
    #[must_use]
    pub fn scheme(&self) -> crate::keys::Scheme {
        match self {
            Self::EvmTransaction(_) | Self::UserOperation(_) | Self::Eip712(_) => {
                crate::keys::Scheme::Secp256k1
            }
            Self::SolanaMessage(_) => crate::keys::Scheme::Ed25519,
        }
    }

    /// The digest a signature over this payload commits to: the chain's
    /// signing hash for the three EVM kinds, and sha256 of the raw
    /// message for Solana (ed25519 itself signs the raw bytes; an audit
    /// record still wants one hash per payload, and this is it).
    ///
    /// # Errors
    ///
    /// [`SignerError::Payload`] when a field cannot take part in the
    /// hash: a malformed address, calldata that claims an ABI layout it
    /// does not have, an `execute` value past `u128`.
    pub fn payload_hash(&self) -> Result<[u8; 32], SignerError> {
        match self {
            Self::EvmTransaction(tx) => tx.signing_hash(),
            Self::UserOperation(op) => op.user_op_hash(),
            Self::Eip712(data) => data.digest(),
            Self::SolanaMessage(message) => Ok(crypto::sha256(&message.0)),
        }
    }

    /// The decoded intent, as the guardrails see it.
    ///
    /// # Errors
    ///
    /// [`SignerError::Payload`] when the payload does not decode — a
    /// malformed address, calldata that claims a layout it does not
    /// have, a Solana message that stops mid-field.
    pub fn intent(&self) -> Result<Intent, SignerError> {
        match self {
            Self::EvmTransaction(tx) => tx.intent(),
            Self::UserOperation(op) => op.intent(),
            Self::Eip712(data) => data.intent(),
            Self::SolanaMessage(message) => message.intent(),
        }
    }
}

/// An EIP-1559 (type 2) transaction, minus the signature and minus the
/// access list — a session key signing ordinary sends has no use for
/// one, and its absence is a documented limit, not an oversight. The
/// signing hash is `keccak256(0x02 || rlp([chain_id, nonce,
/// max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value,
/// data, access_list]))`, with an empty access list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmTransaction {
    /// The chain the transaction is for; the signing hash commits to it.
    pub chain_id: u64,
    /// The sender's nonce.
    pub nonce: u64,
    /// Max priority fee per gas, in wei.
    #[serde(with = "serde_u128")]
    pub max_priority_fee_per_gas: u128,
    /// Max fee per gas, in wei.
    #[serde(with = "serde_u128")]
    pub max_fee_per_gas: u128,
    /// Gas limit.
    #[serde(with = "serde_u128")]
    pub gas_limit: u128,
    /// The recipient as `0x` hex, any case; `None` creates a contract.
    pub to: Option<String>,
    /// Value in wei.
    #[serde(with = "serde_u128")]
    pub value: u128,
    /// Calldata, `0x`-hex on the wire.
    #[serde(with = "serde_hex_bytes")]
    pub data: Vec<u8>,
}

impl EvmTransaction {
    /// The signing hash: `keccak256(0x02 || rlp([...]))`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Payload`] when `to` is present but not an address.
    pub fn signing_hash(&self) -> Result<[u8; 32], SignerError> {
        let recipient = match &self.to {
            Some(to) => {
                crypto::parse_address(to).map_err(|err| context(err, "the transaction's `to`"))?
            }
            None => [0_u8; 20],
        };
        let mut fields = Vec::with_capacity(160);
        rlp::encode_uint(&mut fields, u128::from(self.chain_id));
        rlp::encode_uint(&mut fields, u128::from(self.nonce));
        rlp::encode_uint(&mut fields, self.max_priority_fee_per_gas);
        rlp::encode_uint(&mut fields, self.max_fee_per_gas);
        rlp::encode_uint(&mut fields, self.gas_limit);
        if self.to.is_some() {
            rlp::encode_bytes(&mut fields, &recipient);
        } else {
            rlp::encode_bytes(&mut fields, &[]);
        }
        rlp::encode_uint(&mut fields, self.value);
        rlp::encode_bytes(&mut fields, &self.data);
        fields.push(0xc0); // access_list: the empty list.
        rlp::wrap_list(&mut fields, 0);
        let mut envelope = Vec::with_capacity(fields.len() + 1);
        envelope.push(0x02);
        envelope.extend_from_slice(&fields);
        Ok(crypto::keccak256(&envelope))
    }

    fn intent(&self) -> Result<Intent, SignerError> {
        let to = self
            .to
            .as_deref()
            .map(|to| {
                crypto::parse_address(to)
                    .map(|address| lower_hex(&address))
                    .map_err(|err| context(err, "the transaction's `to`"))
            })
            .transpose()?;
        Ok(Intent {
            chain: Chain::Evm {
                chain_id: self.chain_id,
            },
            to,
            selector: selector_of(&self.data),
            value: Some(self.value.to_string()),
            programs: Vec::new(),
            verifying_contract: None,
        })
    }
}

/// An ERC-4337 v0.7 **packed** `UserOperation`. The gas figures are the
/// unpacked values; `userOpHash` packs the pairs
/// (`verification_gas_limit`, `call_gas_limit`) and
/// (`max_priority_fee_per_gas`, `max_fee_per_gas`) into their bytes32
/// halves, so each must fit 128 bits — which its type already says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserOperation {
    /// The account the operation goes through, `0x` hex, any case.
    pub sender: String,
    /// The account's nonce.
    #[serde(with = "serde_u128")]
    pub nonce: u128,
    /// Init code, `0x`-hex on the wire; empty once the account exists.
    #[serde(with = "serde_hex_bytes")]
    pub init_code: Vec<u8>,
    /// Calldata, `0x`-hex on the wire — usually `execute` or
    /// `executeBatch` on the account.
    #[serde(with = "serde_hex_bytes")]
    pub call_data: Vec<u8>,
    /// Verification gas limit.
    #[serde(with = "serde_u128")]
    pub verification_gas_limit: u128,
    /// Call gas limit.
    #[serde(with = "serde_u128")]
    pub call_gas_limit: u128,
    /// Pre-verification gas.
    #[serde(with = "serde_u128")]
    pub pre_verification_gas: u128,
    /// Max priority fee per gas, in wei.
    #[serde(with = "serde_u128")]
    pub max_priority_fee_per_gas: u128,
    /// Max fee per gas, in wei.
    #[serde(with = "serde_u128")]
    pub max_fee_per_gas: u128,
    /// Paymaster data, `0x`-hex on the wire; empty without one.
    #[serde(with = "serde_hex_bytes")]
    pub paymaster_and_data: Vec<u8>,
    /// The entry point this operation is for, `0x` hex, any case —
    /// `userOpHash` binds it, and the intent surfaces it as
    /// `verifying_contract` for the guardrails to pin.
    pub entry_point: String,
    /// The chain the operation is for.
    pub chain_id: u64,
}

impl UserOperation {
    /// The `userOpHash` the v0.7 entry point signs:
    /// `keccak256(abi.encode(keccak256(abi.encode(<the operation>)),
    /// entryPoint, chainId))`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Payload`] when `sender` or `entry_point` is not an
    /// address.
    pub fn user_op_hash(&self) -> Result<[u8; 32], SignerError> {
        let sender = Self::field_address(&self.sender, "sender")?;
        let entry_point = Self::field_address(&self.entry_point, "entry_point")?;
        let operation: [[u8; 32]; 8] = [
            crypto::address_word(&sender),
            crypto::uint256_word(self.nonce),
            crypto::keccak256(&self.init_code),
            crypto::keccak256(&self.call_data),
            packed_half_words(self.verification_gas_limit, self.call_gas_limit),
            crypto::uint256_word(self.pre_verification_gas),
            packed_half_words(self.max_priority_fee_per_gas, self.max_fee_per_gas),
            crypto::keccak256(&self.paymaster_and_data),
        ];
        let inner = crypto::keccak256(&concat_words(&operation));
        Ok(crypto::keccak256(&concat_words(&[
            inner,
            crypto::address_word(&entry_point),
            crypto::uint256_word(u128::from(self.chain_id)),
        ])))
    }

    fn field_address(text: &str, field: &str) -> Result<[u8; 20], SignerError> {
        crypto::parse_address(text).map_err(|err| context(err, &format!("`{field}`")))
    }

    fn intent(&self) -> Result<Intent, SignerError> {
        let entry_point = Self::field_address(&self.entry_point, "entry_point")?;
        let (to, value) = decoded_execute(&self.call_data)
            .map_err(|err| context(err, "the UserOperation's call_data"))?;
        Ok(Intent {
            chain: Chain::Evm {
                chain_id: self.chain_id,
            },
            to,
            selector: selector_of(&self.call_data),
            value,
            programs: Vec::new(),
            verifying_contract: Some(lower_hex(&entry_point)),
        })
    }
}

/// Decodes `execute(address,uint256,bytes)` calldata into `(to, value)`
/// when it is there in canonical ABI shape: head of three words, the
/// bytes offset at `0x60`, and a tail that matches its own length word.
/// Returns `Ok((None, None))` for any other selector or shape — the
/// intent keeps its selector and its entry point and nothing more, and
/// the guardrails see a payload they have not been told to allow.
fn decoded_execute(call_data: &[u8]) -> Result<(Option<String>, Option<String>), SignerError> {
    if call_data
        .get(..4)
        .is_none_or(|head| head != SELECTOR_EXECUTE.as_slice())
    {
        return Ok((None, None));
    }
    let Some(tail) = call_data.get(4..4 + 96) else {
        return Err(SignerError::Payload(
            "an `execute` head with no room for its three words".to_owned(),
        ));
    };
    let (to_word, value_word, offset_word) = (&tail[..32], &tail[32..64], &tail[64..96]);
    let to = lower_hex(
        &to_word[12..]
            .try_into()
            .map_err(|_| SignerError::Payload("an address word is 32 bytes".to_owned()))?,
    );
    if value_word[..16].iter().any(|&b| b != 0) {
        return Err(SignerError::Payload(
            "the `execute` value does not fit a u128, so the guardrails would be reading a \
             decimal that lies about the wei; refine the policy instead"
                .to_owned(),
        ));
    }
    let value = u128::from_be_bytes(
        value_word[16..]
            .try_into()
            .map_err(|_| SignerError::Payload("a uint256 word is 32 bytes".to_owned()))?,
    );
    if offset_word[..31].iter().any(|&b| b != 0) || offset_word[31] != 0x60 {
        return Err(SignerError::Payload(
            "the `execute` bytes offset is not the canonical 0x60".to_owned(),
        ));
    }
    let Some(len_word) = call_data.get(100..132) else {
        return Err(SignerError::Payload(
            "the `execute` tail has no bytes-length word".to_owned(),
        ));
    };
    if len_word[..16].iter().any(|&b| b != 0) {
        return Err(SignerError::Payload(
            "the `execute` bytes length does not fit a u128".to_owned(),
        ));
    }
    let bytes_len = usize::try_from(u128::from_be_bytes(
        len_word[16..].try_into().expect("a 16-byte slice"),
    ))
    .map_err(|_| {
        SignerError::Payload("the `execute` bytes length does not fit the platform".to_owned())
    })?;
    if call_data.len() != 132 + bytes_len {
        return Err(SignerError::Payload(
            "the `execute` bytes length does not match the calldata".to_owned(),
        ));
    }
    Ok((Some(to), Some(value.to_string())))
}

/// EIP-712 typed data: this crate encodes the domain separator; the
/// caller supplies the primary struct's hash, because encoding arbitrary
/// nested structs is the caller's ABI job and passing a hash keeps the
/// boundary honest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip712 {
    /// Domain `name`, when the domain has one.
    pub name: Option<String>,
    /// Domain `version`, when the domain has one.
    pub version: Option<String>,
    /// Domain `chainId`, when the domain has one.
    pub chain_id: Option<u64>,
    /// Domain `verifyingContract`, when the domain has one.
    pub verifying_contract: Option<String>,
    /// Domain `salt`, when the domain has one.
    #[serde(default, with = "serde_opt_hex32")]
    pub salt: Option<[u8; 32]>,
    /// The primary type's name, as the audit record shows it.
    pub primary_type: String,
    /// The primary struct's hash:
    /// `keccak256(abi.encode(keccak256(type string), ...values))`.
    #[serde(with = "serde_hex32")]
    pub struct_hash: [u8; 32],
}

impl Eip712 {
    /// The domain separator, over exactly the fields present, in the
    /// EIP's canonical order (name, version, chainId,
    /// verifyingContract, salt).
    ///
    /// # Errors
    ///
    /// [`SignerError::Payload`] when `verifying_contract` is present but
    /// not an address.
    pub fn domain_separator(&self) -> Result<[u8; 32], SignerError> {
        let verifying_contract = self
            .verifying_contract
            .as_deref()
            .map(|text| {
                crypto::parse_address(text)
                    .map_err(|err| context(err, "the EIP-712 domain's `verifying_contract`"))
            })
            .transpose()?;

        let mut type_string = String::from("EIP712Domain(");
        let mut value_words: Vec<[u8; 32]> = Vec::with_capacity(5);
        if self.name.is_some() {
            type_string.push_str("string name,");
        }
        if self.version.is_some() {
            type_string.push_str("string version,");
        }
        if let Some(chain_id) = self.chain_id {
            type_string.push_str("uint256 chainId,");
            value_words.push(crypto::uint256_word(u128::from(chain_id)));
        }
        if let Some(address) = verifying_contract {
            type_string.push_str("address verifyingContract,");
            value_words.push(crypto::address_word(&address));
        }
        if let Some(salt) = self.salt {
            type_string.push_str("bytes32 salt,");
            value_words.push(salt);
        }
        type_string.pop(); // the trailing comma.
        type_string.push(')');

        let mut encoded = Vec::with_capacity(32 * value_words.len() + 64);
        encoded.extend_from_slice(&crypto::keccak256(type_string.as_bytes()));
        if let Some(name) = &self.name {
            encoded.extend_from_slice(&crypto::keccak256(name.as_bytes()));
        }
        if let Some(version) = &self.version {
            encoded.extend_from_slice(&crypto::keccak256(version.as_bytes()));
        }
        for word in &value_words {
            encoded.extend_from_slice(word);
        }
        Ok(crypto::keccak256(&encoded))
    }

    /// The digest a signature is over:
    /// `keccak256(0x1901 || domain separator || struct hash)`.
    ///
    /// # Errors
    ///
    /// As [`Eip712::domain_separator`].
    pub fn digest(&self) -> Result<[u8; 32], SignerError> {
        let domain = self.domain_separator()?;
        let mut bytes = Vec::with_capacity(66);
        bytes.extend_from_slice(&[0x19, 0x01]);
        bytes.extend_from_slice(&domain);
        bytes.extend_from_slice(&self.struct_hash);
        Ok(crypto::keccak256(&bytes))
    }

    fn intent(&self) -> Result<Intent, SignerError> {
        let verifying_contract = self
            .verifying_contract
            .as_deref()
            .map(|text| {
                crypto::parse_address(text)
                    .map(|address| lower_hex(&address))
                    .map_err(|err| context(err, "the EIP-712 domain's `verifying_contract`"))
            })
            .transpose()?;
        Ok(Intent {
            chain: Chain::Evm {
                chain_id: self.chain_id.unwrap_or(0),
            },
            to: None,
            selector: None,
            value: None,
            programs: Vec::new(),
            verifying_contract,
        })
    }
}

/// A raw Solana wire message. ed25519 signs the bytes as they are, so
/// this is bytes and a parser, not a builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaMessage(pub Vec<u8>);

impl SolanaMessage {
    /// Parses the message and resolves each instruction's program id
    /// against the message's static account keys: header (three
    /// compact-u16 counts; a v0 message sets the high bit of the first
    /// byte and carries its version there), keys, blockhash,
    /// instructions. A legacy message's account keys are all static; a
    /// v0 message's indexes past them come from lookup tables this
    /// message does not carry, and those surface as `lt:{index}`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Payload`] when the message stops mid-field: a
    /// truncated header, fewer keys than an index names, an instruction
    /// that runs off the end, a version past v0.
    pub fn intent(&self) -> Result<Intent, SignerError> {
        let mut bytes = self.0.as_slice();
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            let version = bytes[0] & 0x7f;
            if version != 0 {
                return Err(SignerError::Payload(format!(
                    "this crate reads legacy and v0 messages, not v{version}"
                )));
            }
            bytes = &bytes[1..];
        }
        let _num_required_signatures = compact_u16(&mut bytes)?;
        let _num_readonly_signed = compact_u16(&mut bytes)?;
        let _num_readonly_unsigned = compact_u16(&mut bytes)?;

        let num_account_keys = compact_u16(&mut bytes)?;
        if num_account_keys == 0 {
            return Err(SignerError::Payload(
                "a message with no account keys cannot name a program".to_owned(),
            ));
        }
        let keys_len = num_account_keys
            .checked_mul(32)
            .filter(|len| *len <= bytes.len())
            .ok_or_else(truncated)?;
        let (keys, rest) = bytes.split_at(keys_len);
        bytes = rest;
        let static_keys: Vec<String> = keys
            .as_chunks::<32>()
            .0
            .iter()
            .map(bs58::encode)
            .map(bs58::encode::EncodeBuilder::into_string)
            .collect();
        // The recent blockhash: present, uninterpreted — the signature
        // binds it, the intent does not need it.
        if bytes.len() < 32 {
            return Err(truncated());
        }
        bytes = &bytes[32..];

        let num_instructions = compact_u16(&mut bytes)?;
        let mut programs = Vec::with_capacity(num_instructions.min(64));
        for _ in 0..num_instructions {
            let program_id_index = compact_u16(&mut bytes)?;
            let num_accounts = compact_u16(&mut bytes)?;
            if bytes.len() < num_accounts {
                return Err(truncated());
            }
            bytes = &bytes[num_accounts..];
            let data_len = compact_u16(&mut bytes)?;
            if bytes.len() < data_len {
                return Err(truncated());
            }
            bytes = &bytes[data_len..];
            match static_keys.get(program_id_index) {
                Some(pubkey) => programs.push(pubkey.clone()),
                None => programs.push(format!("lt:{program_id_index}")),
            }
        }
        Ok(Intent {
            chain: Chain::Solana,
            to: None,
            selector: None,
            value: None,
            programs,
            verifying_contract: None,
        })
    }
}

impl Serialize for SolanaMessage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&bs58::encode(&self.0).into_string())
    }
}

impl<'de> Deserialize<'de> for SolanaMessage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = bs58::decode(&text)
            .into_vec()
            .map_err(|_| serde::de::Error::custom("a Solana message is base58 text"))?;
        Ok(Self(bytes))
    }
}

/// The two gas pairs packed into their bytes32 halves: left half the
/// first value, right half the second, both 16-byte big-endian — the
/// v0.7 packed form's `accountGasLimits` and `gasFees`.
fn packed_half_words(left: u128, right: u128) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[..16].copy_from_slice(&left.to_be_bytes());
    out[16..].copy_from_slice(&right.to_be_bytes());
    out
}

fn concat_words(words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 32);
    for word in words {
        out.extend_from_slice(word);
    }
    out
}

fn truncated() -> SignerError {
    SignerError::Payload("the Solana message stops mid-field".to_owned())
}

/// Rewraps a validation failure so the audit record says which field it
/// was about.
fn context(err: SignerError, what: &str) -> SignerError {
    match err {
        SignerError::Invalid(bad) => SignerError::Payload(format!("{what}: {bad}")),
        other => other,
    }
}

/// A compact-u16, Solana's "short" encoding: little-endian base 128,
/// high bit as the continue flag, three bytes at most.
fn compact_u16(bytes: &mut &[u8]) -> Result<usize, SignerError> {
    let mut value = 0_usize;
    for shift in 0..3 {
        let byte = *bytes.first().ok_or_else(truncated)?;
        *bytes = &bytes[1..];
        value |= usize::from(byte & 0x7f) << (7 * shift);
        if byte < 0x80 {
            return Ok(value);
        }
    }
    Err(SignerError::Payload(
        "a compact-u16 is at most three bytes".to_owned(),
    ))
}

/// The first four bytes of EVM calldata, `0x`-prefixed, when there are
/// at least four.
fn selector_of(data: &[u8]) -> Option<String> {
    if data.len() >= 4 {
        Some(format!("0x{}", hex::encode(&data[..4])))
    } else {
        None
    }
}

fn lower_hex(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

/// `Vec<u8>` fields as `0x`-hex on the wire.
mod serde_hex_bytes {
    pub(super) fn serialize<S: serde::Serializer>(
        bytes: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        hex::decode(text.strip_prefix("0x").unwrap_or(&text))
            .map_err(|_| serde::de::Error::custom("expected 0x-hex bytes"))
    }
}

/// A wei amount as a decimal string on the wire: JSON numbers cannot
/// carry a u128, and JavaScript clients lose integer precision past
/// 2^53, which is less than one ether in wei.
mod serde_u128 {
    pub(super) fn serialize<S: serde::Serializer>(
        value: &u128,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<u128, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        text.parse()
            .map_err(|_| serde::de::Error::custom(format!("`{text}` is not a decimal wei amount")))
    }
}

/// A `[u8; 32]` as `0x`-hex on the wire.
mod serde_hex32 {
    pub(super) fn serialize<S: serde::Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        super::serde_hex_bytes::deserialize(deserializer)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// An optional `[u8; 32]` as `0x`-hex on the wire.
mod serde_opt_hex32 {
    // The `&Option<_>` is the signature serde's `serialize_with` calls:
    // not a hand-written borrow of an optional.
    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S: serde::Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => super::serde_hex32::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let text = <Option<String> as serde::Deserialize>::deserialize(deserializer)?;
        match text.as_deref() {
            None | Some("") => Ok(None),
            Some(text) => {
                let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
                    .map_err(|_| serde::de::Error::custom("expected 0x-hex bytes"))?;
                bytes
                    .try_into()
                    .map(Some)
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_known_encodings() {
        // The short-u16 examples from Solana's message format: little
        // endian, base 128, high bit continues.
        for (value, wire) in [
            (0, &[0x00_u8][..]),
            (127, &[0x7f][..]),
            (128, &[0x80, 0x01][..]),
            (300, &[0xac, 0x02][..]),
            (16_383, &[0xff, 0x7f][..]),
        ] {
            let mut slice: &[u8] = wire;
            assert_eq!(compact_u16(&mut slice).expect("decodes"), value);
            assert!(slice.is_empty());
        }
    }

    #[test]
    fn reject_malformed_compact_u16() {
        // Four bytes of continuation is past the ceiling.
        let mut slice: &[u8] = &[0xff, 0xff, 0xff, 0xff];
        assert!(compact_u16(&mut slice).is_err());
        // The message ends before the value does.
        let mut slice: &[u8] = &[0x80];
        assert!(compact_u16(&mut slice).is_err());
    }

    #[test]
    fn execute_decodes_only_canonical_shapes() {
        // The canonical execute calldata from tests/vectors.rs, rebuilt
        // here shape-first: selector, to, value 123, empty bytes at 0x60.
        let mut data = SELECTOR_EXECUTE.to_vec();
        data.extend_from_slice(&crypto::address_word(&[0x22; 20]));
        data.extend_from_slice(&crypto::uint256_word(123));
        data.extend_from_slice(&crypto::uint256_word(0x60));
        data.extend_from_slice(&crypto::uint256_word(0));
        let (to, value) = decoded_execute(&data).expect("decodes");
        assert_eq!(
            to.as_deref(),
            Some("0x2222222222222222222222222222222222222222")
        );
        assert_eq!(value.as_deref(), Some("123"));

        // A value past u128 refuses rather than truncates.
        data[36] = 0x01;
        assert!(decoded_execute(&data).is_err());
    }
}
