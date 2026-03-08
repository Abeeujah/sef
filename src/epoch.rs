use sha2::{Digest, Sha256};

/// Shared configuration for encoding/reconstruction operations on epochs.
#[derive(Debug, Clone)]
pub struct EpochConfig {
    /// Epoch size (number of blocks per epoch).
    pub k: usize,

    /// Number of droplets to generate per epoch (0 = auto-scale).
    pub n: u64,

    /// Number of recent blocks to keep raw (not encode).
    pub buffer: usize,

    /// Robust Soliton parameter c.
    pub c: f64,

    /// Robust Soliton parameter delta.
    pub delta: f64,

    /// Symbol size in bytes for block concatenation (0 = disabled).
    pub symbol_size: usize,
}

/// Derive a deterministic epoch seed from epoch index and first block hash.
pub fn compute_epoch_seed(epoch_idx: usize, first_block_hash: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"epoch_seed")
        .chain_update((epoch_idx as u64).to_le_bytes())
        .chain_update(first_block_hash.as_bytes())
        .finalize()
        .into()
}

/// Auto-scale droplet count based on source unit count.
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
