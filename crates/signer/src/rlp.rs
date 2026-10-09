//! Minimal RLP encoding — private, and just wide enough for the EIP-1559
//! signing pre-image: byte strings, lists, and integers as minimal
//! big-endian byte strings (a `uint` zero is the empty string).

/// Appends `bytes` as an RLP string.
pub(crate) fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
        return;
    }
    length_prefix(out, bytes.len(), 0x80, 0xb7);
    out.extend_from_slice(bytes);
}

/// Appends `value` as an RLP string holding its minimal big-endian form.
pub(crate) fn encode_uint(out: &mut Vec<u8>, value: u128) {
    let be = value.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    encode_bytes(out, &be[first..]);
}

/// Writes the list header for the payload already appended to `out` since
/// `payload_start`, splicing it in in front. Call once per list.
pub(crate) fn wrap_list(out: &mut Vec<u8>, payload_start: usize) {
    let payload = out.split_off(payload_start);
    length_prefix(out, payload.len(), 0xc0, 0xf7);
    out.extend_from_slice(&payload);
}

/// One RLP length prefix: short form up to 55 bytes, long form past that.
fn length_prefix(out: &mut Vec<u8>, len: usize, short_offset: u8, long_offset: u8) {
    if len <= 55 {
        out.push(short_offset + u8::try_from(len).expect("a short item is at most 55 bytes"));
    } else {
        let be = (len as u64).to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(7);
        let len_bytes = &be[first..];
        out.push(
            long_offset + u8::try_from(len_bytes.len()).expect("the length is at most 8 bytes"),
        );
        out.extend_from_slice(len_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(f: impl FnOnce(&mut Vec<u8>, usize)) -> Vec<u8> {
        let mut out = Vec::new();
        let start = out.len();
        f(&mut out, start);
        wrap_list(&mut out, start);
        out
    }

    #[test]
    fn rlp_reference_vectors() {
        // The RLP appendix of the Yellow Paper: `dog` -> 0x83 dog; an
        // empty list -> 0xc0; the list [cat, dog] -> c8 83 cat 83 dog
        // (its payload is the two 4-byte strings); the empty string ->
        // 0x80.
        let mut out = Vec::new();
        encode_bytes(&mut out, b"dog");
        assert_eq!(out, [0x83, b'd', b'o', b'g']);

        assert_eq!(encoded(|_, _| {}), [0xc0]);

        let cat_dog = encoded(|out, _| {
            encode_bytes(out, b"cat");
            encode_bytes(out, b"dog");
        });
        assert_eq!(
            cat_dog,
            [0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );

        let mut out = Vec::new();
        encode_bytes(&mut out, b"");
        assert_eq!(out, [0x80]);

        // Past 55 payload bytes the list goes long-form: 0xf9 marks two
        // length bytes, then the payload length, here four strings of
        // 1024 bytes (each 0xb9-prefixed) for 4 * 1027.
        let long = encoded(|out, _| {
            for _ in 0..4 {
                encode_bytes(out, &[0x00; 1024]);
            }
        });
        assert_eq!(long[0], 0xf9);
        let payload_len = u16::try_from(4 * (1024 + 3)).expect("it fits");
        assert_eq!(&long[1..3], &payload_len.to_be_bytes());
    }
}
