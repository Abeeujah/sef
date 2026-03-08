//! Bitwise XOR primitives with adaptive zero-padding for the fountain encoder
//! and decoder pipelines.
//!
//! XOR is the core algebraic operation in LT codes. During encoding,
//! [`Encoder::generate`](crate::droplet::Encoder::generate) forms each
//! [`Droplet`](crate::droplet::Droplet) by XORing $d$ source blocks together.
//! During decoding, the peeling algorithm recovers source blocks by XORing
//! already-recovered blocks *out* of higher-degree droplets, reducing their
//! degree until new singletons emerge.
//!
//! All functions in this module treat shorter operands as implicitly
//! zero-padded to the length of the longest operand, so variable-size
//! Bitcoin blocks can be combined without pre-normalization.
//!
//! ```
//! use sef::xor::xor_bytes;
//!
//! let a = vec![0xFF, 0x00];
//! let b = vec![0x0F, 0xF0, 0x55]; // implicitly pads `a` with 0x00
//! assert_eq!(xor_bytes(&a, &b), vec![0xF0, 0xF0, 0x55]);
//! ```

/// XORs two byte slices with adaptive zero-padding, returning a new allocation.
///
/// Produces a `Vec<u8>` of length `max(a.len(), b.len())`. When the slices
/// differ in length the shorter one is treated as if zero-padded, allowing
/// variable-size blocks (e.g., metadata vs. payload) to be combined without
/// prior normalization.
///
/// Primarily used during encoding to combine pairs of source blocks.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
    let mut result = long.to_vec();

    for (r, &s) in result.iter_mut().zip(short) {
        *r ^= s;
    }
    result
}

/// XORs `block` into `buf` in place, extending `buf` if `block` is longer.
///
/// Mutates `buf` by XORing each existing byte with the corresponding byte
/// from `block`. If `block` is longer than `buf`, the surplus bytes are
/// appended verbatim (equivalent to XOR with zero). This grow-on-demand
/// behavior supports the encoder's accumulation loop where the running
/// buffer starts empty and absorbs blocks of varying lengths.
pub fn xor_into(buf: &mut Vec<u8>, block: &[u8]) {
    let buf_len = buf.len();
    let block_len = block.len();

    buf.iter_mut().zip(block.iter()).for_each(|(b, &s)| *b ^= s);

    if block_len > buf_len {
        buf.extend_from_slice(&block[buf_len..]);
    }
}

/// XORs `src` into a fixed-size `dst` buffer without resizing.
///
/// Returns `false` if `src.len() > dst.len()`, signalling that the droplet
/// payload grew beyond the expected padded length — a reliable corruption
/// indicator during the peeling decode. Callers should treat a `false`
/// return as a [`VerifyError`](crate::decoder::VerifyError)-level fault.
pub fn xor_into_fixed(dst: &mut [u8], src: &[u8]) -> bool {
    if src.len() > dst.len() {
        return false;
    }
    for (d, &s) in dst[..src.len()].iter_mut().zip(src.iter()) {
        *d ^= s;
    }
    true
}

/// Folds an arbitrary number of byte slices into a single XOR result.
///
/// This is the primary multi-block XOR used by
/// [`Encoder::generate`](crate::droplet::Encoder::generate) to form a
/// droplet payload from $d$ source blocks. Shorter slices are implicitly
/// zero-padded to the length of the longest slice.
///
/// Returns a `Vec<u8>` of length `max(blocks[i].len())`, or an empty
/// `Vec` if `blocks` is empty.
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
