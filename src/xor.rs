/// XOR two byte slices with adaptive zero-padding.
///
/// If the slices differ in length, the operation behaves as if the shorter slice
/// were zero-padded to match the longer one. This ensures that smaller metadata
///  blocks can be combined with larger payload blocks without truncation.
///
/// # Returns
/// A `Vec<u8>` with length `max(a.len(), b.len())`.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
    let mut result = long.to_vec();

    for (r, &s) in result.iter_mut().zip(short) {
        *r ^= s;
    }
    result
}

/// XORs `block` into `buf`, extending `buf` if necessary.
///
/// If `block` is longer than `buf`, `buf` is extended to match the length
/// of `block`. Existing bytes in `buf` are XOR'd with the corresponding
/// bytes from `block`, while any additional bytes from `block` are
/// appended directly to `buf`.
pub fn xor_into(buf: &mut Vec<u8>, block: &[u8]) {
    let buf_len = buf.len();
    let block_len = block.len();

    buf.iter_mut().zip(block.iter()).for_each(|(b, &s)| *b ^= s);

    if block_len > buf_len {
        buf.extend_from_slice(&block[buf_len..]);
    }
}

/// XOR src into a fixed-size destination without resizing.
///
/// Returns `false` if `src` is longer than `dst` (caller should treat as error).
/// Used during peeling decode where payload growth indicates a malformed droplet.
pub fn xor_into_fixed(dst: &mut [u8], src: &[u8]) -> bool {
    if src.len() > dst.len() {
        return false;
    }
    for (d, &s) in dst[..src.len()].iter_mut().zip(src.iter()) {
        *d ^= s;
    }
    true
}

/// XORs multiple byte slices together with adaptive zero-padding.
///
/// Each slice is XOR'd into the result. If slices have different lengths,
/// they are treated as if they were zero-padded to the length of the longest slice.
///
/// # Returns
/// A `Vec<u8>` with length equal to the longest input slice.
/// If the input is empty, an empty `Vec` is returned.
pub fn xor_blocks(blocks: &[&[u8]]) -> Vec<u8> {
    let max_len = blocks.iter().map(|b| b.len()).max().unwrap_or(0);
    let mut result = vec![0u8; max_len];

    for block in blocks {
        for (r, &b) in result[..block.len()].iter_mut().zip(block.iter()) {
            *r ^= b;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_equal_length() {
        let a = vec![0xFF, 0x00, 0xAA];
        let b = vec![0x0F, 0xF0, 0x55];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, vec![0xF0, 0xF0, 0xFF]);
    }

    #[test]
    fn test_xor_different_lengths() {
        let a = vec![0xFF, 0x00];
        let b = vec![0x0F, 0xF0, 0x55];
        let result = xor_bytes(&a, &b); // a gets padded with 0x00: [0xFF, 0x00, 0x00]
        assert_eq!(result, vec![0xF0, 0xF0, 0x55]);
    }

    #[test]
    fn test_xor_self_is_zero() {
        let a = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = xor_bytes(&a, &a);
        assert_eq!(result, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_xor_with_zero() {
        let a = vec![0xDE, 0xAD];
        let zero = vec![0x00, 0x00];
        let result = xor_bytes(&a, &zero);
        assert_eq!(result, a);
    }

    #[test]
    fn test_xor_into_extending() {
        let mut buf = vec![0xFF, 0x00];
        let block = vec![0x0F, 0xF0, 0xAA];
        xor_into(&mut buf, &block);
        assert_eq!(buf, vec![0xF0, 0xF0, 0xAA]);
    }

    #[test]
    fn test_xor_blocks_multiple() {
        let a = vec![0xFF, 0x00, 0xAA];
        let b = vec![0x0F, 0xF0];
        let c = vec![0x01, 0x02, 0x03, 0x04];
        let result = xor_blocks(&[&a, &b, &c]);
        // a ^ b ^ c (with zero padding):
        // [0xFF^0x0F^0x01, ..., 0x00^0x00^0x04]
        assert_eq!(result, vec![0xF1, 0xF2, 0xA9, 0x04]);
    }

    #[test]
    fn test_blocks_single() {
        let a = vec![0xDE, 0xAD];
        let result = xor_blocks(&[&a]);
        assert_eq!(result, a);
    }

    #[test]
    fn test_xor_blocks_empty() {
        let result = xor_blocks(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_xor_is_commutative_with_different_lengths() {
        let a = vec![0x12, 0x34, 0x56]; // 3 bytes
        let b = vec![0x78]; // 1 byte

        // This checks if (a ^ b_padded) == (b ^ a_padded)
        assert_eq!(xor_bytes(&a, &b), xor_bytes(&b, &a));
    }

    #[test]
    fn test_xor_is_associative_with_different_lengths() {
        let a = vec![0x12];
        let b = vec![0x56, 0x78];
        let c = vec![0x9A, 0xBC, 0xDE];

        let ab_c = xor_bytes(&xor_bytes(&a, &b), &c);
        let a_bc = xor_bytes(&a, &xor_bytes(&b, &c));

        assert_eq!(ab_c, a_bc);
    }
}
