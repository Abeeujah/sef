//! Epoch-level configuration and utility functions shared between the encoder
//! and decoder pipelines.
//!
//! An *epoch* is a contiguous group of $K$ blockchain blocks that are
//! fountain-encoded as a unit. This module provides [`EpochConfig`] (the
//! user-facing configuration struct passed to CLI commands),
//! [`compute_epoch_seed`] for deterministic seed derivation, and
//! [`auto_scale_droplets`] for heuristic droplet-count selection.
//!
//! ```
//! use sef::epoch::{compute_epoch_seed, auto_scale_droplets};
//!
//! let seed = compute_epoch_seed(0, "000000000019d6689c085ae165831e93");
//! let n = auto_scale_droplets(100, 0); // auto: 100 * 3 = 300
//! assert_eq!(n, 300);
//! ```

use sha2::{Digest, Sha256};

/// User-facing configuration for encoding and reconstruction of a single epoch.
///
/// Passed to CLI commands (`encode`, `decode`) and threaded through
/// both the [`crate::droplet::Encoder`] and [`crate::decoder`] pipelines.
#[derive(Debug, Clone)]
pub struct EpochConfig {
    /// Number of source blocks per epoch ($K$). Controls the Robust Soliton
    /// Distribution's probability mass function and the bipartite graph width.
    pub k: usize,

    /// Number of droplets to generate. When set to `0`,
    /// [`auto_scale_droplets`] selects a value based on `k`.
    pub n: u64,

    /// Number of most-recent blocks to retain in raw (unencoded) form.
    /// These blocks remain immediately readable without a decode step and
    /// are excluded from the current epoch's encoding pass.
    pub buffer: usize,

    /// Robust Soliton parameter $c$. Governs the height of the degree-1
    /// spike; smaller values improve efficiency but increase decoder-stall
    /// risk.
    pub c: f64,

    /// Robust Soliton parameter $\delta$. Upper bound on the probability
    /// that decoding fails after receiving $K(1+\varepsilon)$ droplets.
    pub delta: f64,

    /// Fixed symbol size in bytes for the optional
    /// [`symbol::blocks_to_symbols`](crate::symbol::blocks_to_symbols)
    /// normalization pass. Set to `0` to disable symbol slicing and encode
    /// raw variable-length blocks directly.
    pub symbol_size: usize,
}

/// Derives a deterministic 256-bit epoch seed via SHA-256 domain separation.
///
/// The hash input is `b"epoch_seed" || epoch_idx (LE-u64) || first_block_hash`.
/// Including the first block's hash binds the seed to actual chain data,
/// preventing seed replay across forks: two epochs with the same index on
/// different forks will produce distinct seeds because their genesis blocks
/// (and therefore their first-block hashes) differ.
pub fn compute_epoch_seed(epoch_idx: usize, first_block_hash: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"epoch_seed")
        .chain_update((epoch_idx as u64).to_le_bytes())
        .chain_update(first_block_hash.as_bytes())
        .finalize()
        .into()
}

/// Selects the droplet count $N$ when the user requests auto-scaling (`n == 0`).
///
/// Applies tiered multipliers to the source-unit count $K$:
///
/// | $K$         | Multiplier | Rationale |
/// |-------------|------------|-----------|
/// | $< 50$      | $5\times$  | Small epochs suffer proportionally higher RSD overhead; extra droplets ensure the ripple never stalls. |
/// | $50 – 199$  | $3\times$  | Moderate overhead; standard safety margin. |
/// | $\ge 200$   | $2\times$  | Large $K$ concentrates the RSD well; minimal surplus needed. |
///
/// If `n` is already nonzero it is returned unchanged.
pub fn auto_scale_droplets(unit_k: usize, n: u64) -> u64 {
    if n == 0 {
        let multiplier = if unit_k < 50 {
            5
        } else if unit_k < 200 {
            3
        } else {
            2
        };
        (unit_k as u64) * multiplier
    } else {
        n
    }
}
