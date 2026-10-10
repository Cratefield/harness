//! The EIP-1559 wire forms this crate trades in: the **unsigned**
//! transaction hex `ACTIVITY_TYPE_SIGN_TRANSACTION_V2` asks for —
//! `0x02 ‖ rlp([chain_id, nonce, max_priority_fee, max_fee, gas, to,
//! value, data, access_list])`, the exact bytes whose keccak256 is the
//! signing hash the signer port computes — and the **signed**
//! transaction back, RLP-decoded into the `(r, s, v)` the port returns.
//!
//! The encoder duplicates the shape `cratefield-signer`'s private `rlp`
//! module encodes; the cross-check test below pins the two together: if
//! this crate's encoding ever drifted from the port's signing
//! pre-image, `keccak256(unsigned) == Payload::payload_hash()` would
//! fail.

use cratefield_signer::{EvmTransaction, SignerError};

/// The EIP-2718 type byte of an EIP-1559 transaction.
const TYPE_EIP1559: u8 = 0x02;

/// The unsigned EIP-1559 transaction bytes, ready to hex into
/// `signWith`'s `unsignedTransaction`.
///
/// # Errors
///
/// [`SignerError::Invalid`] when `to` is set but is not a 20-byte hex
/// address.
pub fn unsigned_transaction(tx: &EvmTransaction) -> Result<Vec<u8>, SignerError> {
    let to = match &tx.to {
        Some(address) => {
            // Same rule the port's signing hash applies; a mismatch
            // would be caught by the hash cross-check in tests, and
            // refusing here keeps a malformed address from riding out.
            let address = crate::policy::validate_address(address)?;
            hex::decode(&address[2..])
                .map_err(|_| SignerError::Invalid("an address must be hex".to_owned()))?
        }
        // Contract creation carries no recipient.
        None => Vec::new(),
    };
    let mut out = vec![TYPE_EIP1559];
    let payload = out.len();
    encode_uint(&mut out, u128::from(tx.chain_id));
    encode_uint(&mut out, u128::from(tx.nonce));
    encode_uint(&mut out, tx.max_priority_fee_per_gas);
    encode_uint(&mut out, tx.max_fee_per_gas);
    encode_uint(&mut out, tx.gas_limit);
    encode_bytes(&mut out, &to);
    encode_uint(&mut out, tx.value);
    encode_bytes(&mut out, &tx.data);
    // The access list: this crate sends none, so an empty list.
    encode_list(&mut out, &[]);
    wrap_list(&mut out, payload);
    Ok(out)
}

/// Splits a signed EIP-1559 transaction hex back into `(r, s,
/// y_parity + 27)`. The signed form is the unsigned list plus the three
/// signature fields at the end; `y_parity` of a typed transaction *is*
/// the recovery id, so the port's `v` is 27 plus it.
///
/// # Errors
///
/// [`SignerError::Provider`] when the hex is not an EIP-1559
/// transaction or the RLP does not carry the twelve fields.
pub fn decode_signed(signed_hex: &str) -> Result<([u8; 32], [u8; 32], u8), SignerError> {
    let malformed = |detail: String| {
        SignerError::Provider(format!(
            "turnkey returned an unparsable transaction: {detail}"
        ))
    };
    let bytes = hex::decode(signed_hex.strip_prefix("0x").unwrap_or(signed_hex))
        .map_err(|err| malformed(format!("not hex: {err}")))?;
    if bytes.first() != Some(&TYPE_EIP1559) {
        return Err(malformed(format!(
            "expected the EIP-1559 type byte {TYPE_EIP1559:#04x}, found {:?}",
            bytes.first()
        )));
    }
    // The transaction is one list of twelve fields behind the type byte.
    let outer = rlp_items(&bytes[1..]).map_err(malformed)?;
    let [RlpItem::List(payload)] = outer.as_slice() else {
        return Err(malformed("expected one transaction list".to_owned()));
    };
    let items = rlp_items(payload).map_err(malformed)?;
    let [.., parity, r, s] = items.as_slice() else {
        return Err(malformed(format!(
            "expected twelve fields, found {}",
            items.len()
        )));
    };
    let RlpItem::Bytes(parity) = parity else {
        return Err(malformed("the y-parity is not a byte string".to_owned()));
    };
    let RlpItem::Bytes(r) = r else {
        return Err(malformed("`r` is not a byte string".to_owned()));
    };
    let RlpItem::Bytes(s) = s else {
        return Err(malformed("`s` is not a byte string".to_owned()));
    };
    let r: [u8; 32] =
        left_pad(r).ok_or_else(|| malformed("`r` is longer than 32 bytes".to_owned()))?;
    let s: [u8; 32] =
        left_pad(s).ok_or_else(|| malformed("`s` is longer than 32 bytes".to_owned()))?;
    let y_parity = parity.first().copied().unwrap_or(0);
    if y_parity > 1 {
        return Err(malformed(format!("the y-parity is {y_parity}")));
    }
    Ok((r, s, 27 + y_parity))
}

/// One decoded RLP item: a byte string, or a list with its raw payload
/// (which this crate skips over, never inspects — the access list is
/// the only list in an EIP-1559 transaction and it rides as sent).
#[derive(Debug, PartialEq, Eq)]
enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<u8>),
}

/// Decodes one RLP stream of top-level items into its parts.
fn rlp_items(bytes: &[u8]) -> Result<Vec<RlpItem>, String> {
    let mut items = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (item, tail) = rlp_item(rest)?;
        items.push(item);
        rest = tail;
    }
    Ok(items)
}

/// Decodes the one item at the head of `bytes`, returning it and the
/// remainder.
fn rlp_item(bytes: &[u8]) -> Result<(RlpItem, &[u8]), String> {
    let (&first, rest) = bytes.split_first().ok_or("empty RLP stream")?;
    let (length, rest) = match first {
        // A byte under 0x80 *is* its own payload — it encodes itself.
        0x00..=0x7f => return Ok((RlpItem::Bytes(vec![first]), rest)),
        0x80..=0xb7 => {
            let len = usize::from(first - 0x80);
            (len, rest)
        }
        0xb8..=0xbf => {
            let len_bytes = usize::from(first - 0xb7);
            let slice = rest.get(..len_bytes).ok_or("truncated length")?;
            let len = be_usize(slice).ok_or("a length past usize")?;
            (len, &rest[len_bytes..])
        }
        0xc0..=0xf7 => {
            let len = usize::from(first - 0xc0);
            return list_payload(rest, len);
        }
        0xf8..=0xff => {
            let len_bytes = usize::from(first - 0xf7);
            let slice = rest.get(..len_bytes).ok_or("truncated length")?;
            let len = be_usize(slice).ok_or("a length past usize")?;
            let rest = &rest[len_bytes..];
            return list_payload(rest, len);
        }
    };
    let payload = rest.get(..length).ok_or("truncated item")?;
    Ok((RlpItem::Bytes(payload.to_vec()), &rest[length..]))
}

/// Takes `len` bytes of list payload from `rest`, decoding them as the
/// list's items (the payload bytes themselves are re-decoded).
fn list_payload(rest: &[u8], len: usize) -> Result<(RlpItem, &[u8]), String> {
    let payload = rest.get(..len).ok_or("truncated list")?;
    rlp_items(payload)?;
    Ok((RlpItem::List(payload.to_vec()), &rest[len..]))
}

/// A big-endian slice as a `usize`, or `None` past the platform width.
fn be_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.len() > usize::BITS as usize / 8 {
        return None;
    }
    let mut out = 0_usize;
    for byte in bytes {
        out = (out << 8) | usize::from(*byte);
    }
    Some(out)
}

/// A byte string of at most 32 bytes as a left-padded word.
fn left_pad(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() > 32 {
        return None;
    }
    let mut out = [0_u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

/// Appends `bytes` as an RLP string.
fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
        return;
    }
    length_prefix(out, bytes.len(), 0x80, 0xb7);
    out.extend_from_slice(bytes);
}

/// Appends `value` as an RLP string holding its minimal big-endian form
/// (a zero is the empty string).
fn encode_uint(out: &mut Vec<u8>, value: u128) {
    let be = value.to_be_bytes();
    let first = be.iter().position(|&byte| byte != 0).unwrap_or(be.len());
    encode_bytes(out, &be[first..]);
}

/// Appends an empty-payload list header for `payload`, which the caller
/// appends right after.
fn encode_list(out: &mut Vec<u8>, payload: &[u8]) {
    length_prefix(out, payload.len(), 0xc0, 0xf7);
    out.extend_from_slice(payload);
}

/// Writes the list header for the payload already appended to `out`
/// since `payload_start`, splicing it in in front.
fn wrap_list(out: &mut Vec<u8>, payload_start: usize) {
    let payload = out.split_off(payload_start);
    length_prefix(out, payload.len(), 0xc0, 0xf7);
    out.extend_from_slice(&payload);
}

/// One RLP length prefix: short form up to 55 bytes, long form past it.
fn length_prefix(out: &mut Vec<u8>, len: usize, short_offset: u8, long_offset: u8) {
    if len <= 55 {
        out.push(short_offset + u8::try_from(len).expect("a short item is at most 55 bytes"));
    } else {
        let be = (len as u64).to_be_bytes();
        let first = be.iter().position(|&byte| byte != 0).unwrap_or(7);
        let len_bytes = &be[first..];
        out.push(long_offset + u8::try_from(len_bytes.len()).expect("the length is at most 8"));
        out.extend_from_slice(len_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> EvmTransaction {
        // The Besu EIP-1559 fixture `cratefield-signer` pins its signing
        // hash against (chain 4, nonce 819).
        EvmTransaction {
            chain_id: 4,
            nonce: 819,
            max_priority_fee_per_gas: 75_853,
            max_fee_per_gas: 121_212,
            gas_limit: 35_552,
            to: Some("0x000000000000000000000000000000000000aaaa".to_owned()),
            value: 43_203_529,
            data: Vec::new(),
        }
    }

    #[test]
    fn the_unsigned_encoding_is_the_ports_signing_preimage() {
        use sha3::Digest as _;
        let unsigned = unsigned_transaction(&tx()).expect("encodes");
        assert_eq!(unsigned[0], TYPE_EIP1559);
        let keccak: [u8; 32] = sha3::Keccak256::digest(&unsigned).into();
        assert_eq!(
            hex::encode(keccak),
            hex::encode(tx().signing_hash().expect("the port hashes")),
            "this crate's unsigned bytes hash to exactly the port's signing hash"
        );
    }

    #[test]
    fn contract_creation_and_large_fields_still_match_the_preimage() {
        use sha3::Digest as _;
        let tx = EvmTransaction {
            to: None,
            value: u128::MAX,
            data: vec![0xde, 0xad, 0xbe, 0xef],
            nonce: u64::MAX,
            ..tx()
        };
        let unsigned = unsigned_transaction(&tx).expect("encodes");
        let keccak: [u8; 32] = sha3::Keccak256::digest(&unsigned).into();
        assert_eq!(
            hex::encode(keccak),
            hex::encode(tx.signing_hash().expect("the port hashes")),
        );
    }

    #[test]
    fn a_signed_transaction_decodes_to_r_s_and_v() {
        // Simulate Turnkey's answer: the unsigned list's items with
        // y-parity, r and s appended, re-wrapped. The fixture's list is
        // short-form, so its header is the single byte at index 1.
        let unsigned = unsigned_transaction(&tx()).expect("encodes");
        assert!(unsigned[1] < 0xf8, "the fixture list is short-form");
        let mut body = unsigned[2..].to_vec();
        encode_uint(&mut body, 1); // y_parity
        encode_uint(&mut body, 0x8000_0000_0000_0001); // r, minimal big-endian
        encode_uint(&mut body, 0x00c0_ffee); // s
        let mut signed = vec![TYPE_EIP1559];
        signed.extend_from_slice(&body);
        wrap_list(&mut signed, 1);
        let hex_signed = format!("0x{}", hex::encode(&signed));

        let (r, s, v) = decode_signed(&hex_signed).expect("decodes");
        let mut expected_r = [0_u8; 32];
        expected_r[24..].copy_from_slice(&0x8000_0000_0000_0001_u64.to_be_bytes());
        assert_eq!(r, expected_r);
        assert_eq!(s[28..], [0x00, 0xc0, 0xff, 0xee]);
        assert_eq!(v, 28);
    }

    #[test]
    fn junk_answers_are_provider_errors() {
        for junk in ["not hex", "0x00", "0x01c0"] {
            let err = decode_signed(junk).expect_err(junk);
            assert!(matches!(err, SignerError::Provider(_)), "got: {err:?}");
        }
    }
}
