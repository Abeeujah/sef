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
//! use sef::xor::xor_blocks;
//!
//! let a = vec![0xFF, 0x00];
//! let b = vec![0x0F, 0xF0, 0x55]; // implicitly pads `a` with 0x00
//! assert_eq!(xor_blocks(&[&a, &b]), vec![0xF0, 0xF0, 0x55]);
//! ```

/// XORs `src[..src.len()]` into the prefix of `dst`, using word-width
/// unaligned loads for throughput.
///
/// # Safety contract (upheld internally)
///
/// Caller must guarantee `src.len() <= dst.len()`. This is asserted in
/// debug builds and assumed in release builds for elision of the bounds
/// check inside the word loop.
#[inline]
fn xor_prefix_unchecked(dst: &mut [u8], src: &[u8]) {
    debug_assert!(src.len() <= dst.len());

    const W: usize = std::mem::size_of::<u64>();
    let len = src.len();
    let tail_start = (len / W) * W;

    let dst_ptr = dst.as_mut_ptr();
    let src_ptr = src.as_ptr();

    // Process full u64 words via unaligned reads/writes — no alignment UB.
    for offset in (0..tail_start).step_by(W) {
        // SAFETY: `offset + W <= len <= dst.len()` and `offset + W <= len`
        // so both pointer ranges are in-bounds. `read_unaligned` /
        // `write_unaligned` impose no alignment requirements.
        unsafe {
            let d = std::ptr::read_unaligned(dst_ptr.add(offset).cast::<u64>());
            let s = std::ptr::read_unaligned(src_ptr.add(offset).cast::<u64>());
            std::ptr::write_unaligned(dst_ptr.add(offset).cast::<u64>(), d ^ s);
        }
    }

    for i in tail_start..len {
        dst[i] ^= src[i];
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
    xor_prefix_unchecked(dst, src);
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
        xor_prefix_unchecked(&mut result, block);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_blocks_multiple() {
        let a = vec![0xFF, 0x00, 0xAA];
        let b = vec![0x0F, 0xF0];
        let c = vec![0x01, 0x02, 0x03, 0x04];
        let result = xor_blocks(&[&a, &b, &c]);
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
    fn test_xor_blocks_unaligned_inputs() {
        let mut a_backing = vec![0xAA];
        a_backing.extend(0u8..17);
        let mut b_backing = vec![0xBB];
        b_backing.extend(17u8..34);

        let a = &a_backing[1..];
        let b = &b_backing[1..];

        let result_blocks = xor_blocks(&[a, b]);
        let result_fixed = {
            let mut dst = a.to_vec();
            xor_into_fixed(&mut dst, b);
            dst
        };
        assert_eq!(result_blocks, result_fixed);
    }

    #[test]
    fn test_xor_into_fixed_word_path() {
        let mut dst_backing = vec![0xAA];
        dst_backing.extend(0u8..17);
        let mut src_backing = vec![0xBB];
        src_backing.extend(17u8..34);

        let original = dst_backing[1..].to_vec();
        let src = &src_backing[1..];

        assert!(xor_into_fixed(&mut dst_backing[1..], src));
        assert_eq!(&dst_backing[1..], xor_blocks(&[&original, src]).as_slice());
    }

    #[test]
    fn test_xor_into_fixed_rejects_oversized_src_without_mutating() {
        let mut dst = vec![0x12, 0x34];
        assert!(!xor_into_fixed(&mut dst, &[0xAA, 0xBB, 0xCC]));
        assert_eq!(dst, vec![0x12, 0x34]);
    }
}
