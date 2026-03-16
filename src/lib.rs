//! Luby Transform (LT) fountain codes for slashing blockchain storage costs.
//!
//! `sef` implements the **Secure Fountain (SeF)** architecture proposed by
//! Kadhe, Chung, and Ramchandran in
//! [*"SeF: A Secure Fountain Architecture for Slashing Storage Costs in
//! Blockchains"*][sef-paper] (arXiv:1906.12140, 2019).
//!
//! In the SeF model, full nodes are replaced by *droplet nodes* that store a
//! small number of fountain-coded blocks per epoch rather than the raw chain.
//! A new *bucket node* joining the network contacts a set of droplet nodes,
//! collects their droplets, and reconstructs the original blockchain via the
//! error-resilient peeling decoder — even when some droplet nodes are
//! adversarial and supply *murky* (maliciously formed) droplets.
//!
//! When the network is tuned for $\gamma = k / s$ storage savings ($k$ blocks
//! per epoch, $s$ droplets stored per node), a bucket node can recover the
//! chain with probability $\geq 1 - \delta$ by contacting
//! $k + O(\sqrt{k} \ln^{2}(k / \delta))$ honest nodes. The header chain
//! serves as authenticated side-information: Merkle roots in block headers
//! allow the peeling decoder to detect and discard murky droplets on the fly
//! without propagating errors.
//!
//! [sef-paper]: https://arxiv.org/abs/1906.12140
//!
//! # Core Pipeline
//!
//! 1. **Ingest** — Read raw Bitcoin blocks from disk via the [`chain`] module.
//! 2. **Epoch grouping** — Partition blocks into fixed-size epochs configured
//!    by [`epoch::EpochConfig`].
//! 3. **Symbol normalization** *(optional)* — Concatenate variable-length blocks
//!    and slice them into uniform [`symbol::DEFAULT_SYMBOL_SIZE`]-byte symbols
//!    with [`symbol::blocks_to_symbols`], eliminating per-block padding waste.
//! 4. **Encode** — Sample degrees from the Robust Soliton Distribution
//!    ([`distribution::RobustSoliton`]) and XOR source blocks into
//!    [`droplet::Droplet`]s via [`droplet::Encoder`].
//! 5. **Decode** — Recover all $K$ source blocks from a sufficient subset of
//!    droplets using the peeling algorithm in [`decoder`].
//!
//! # Module Map
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`chain`] | Bitcoin block readers (`blk` files and `bitcoinkernel`). |
//! | [`decoder`] | Peeling decoder, block verification, and decode orchestration. |
//! | [`distribution`] | [`DegreeDistribution`](distribution::DegreeDistribution) trait and [`RobustSoliton`](distribution::RobustSoliton) implementation. |
//! | [`droplet`] | [`Droplet`](droplet::Droplet) struct, [`EpochParams`](droplet::EpochParams), and [`Encoder`](droplet::Encoder). |
//! | [`encode`] | Consensus serialization for droplets and file I/O helpers. |
//! | [`epoch`] | Epoch configuration, deterministic seed derivation, and auto-scaling heuristics. |
//! | [`experiment`] | Storage-reduction simulations (graph-only, no XOR payloads). |
//! | [`symbol`] | Fixed-size symbol slicing and [`SymbolManifest`](symbol::SymbolManifest) for reassembly. |
//! | [`xor`] | Bitwise XOR primitives with adaptive zero-padding. |
//!
//! # Example
//!
//! Encode-then-decode round-trip with synthetic data:
//!
//! ```
//! # fn main() {
//! use sef::distribution::RobustSoliton;
//! use sef::droplet::{Encoder, EpochParams};
//! use sef::decoder::peeling_check;
//!
//! let k = 50;
//! let blocks: Vec<Vec<u8>> = (0..k)
//!     .map(|i| vec![(i & 0xFF) as u8; 256])
//!     .collect();
//!
//! let params = EpochParams::new(0, k as u32, [0u8; 32]);
//! let dist = RobustSoliton::new(k, 0.1, 0.05);
//! let encoder = Encoder::new(&params, &dist, &blocks);
//!
//! let n = (k as u64) * 3;
//! let droplets = encoder.generate_n(n);
//!
//! // Verify recoverability via the peeling check.
//! let indices: Vec<Vec<u32>> = droplets.iter().map(|d| d.indices.clone()).collect();
//! let result = peeling_check(k, &indices);
//! assert!(result.success);
//! # }
//! ```
//!
//! # Feature Flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `kernel` | **yes** | Enables [`chain::KernelBlockReader`] backed by `bitcoinkernel` for reading blocks directly from a pruned or full datadir. |

pub mod chain;
pub mod decoder;
pub mod distribution;
pub mod droplet;
pub mod encode;
pub mod epoch;
pub mod experiment;
pub mod superblock;
pub mod symbol;
pub mod xor;
