# SeF — Secure Fountain Architecture for Blockchains

A Rust implementation of the **Secure Fountain (SeF)** architecture from
[Kadhe, Chung & Ramchandran (2019)](https://arxiv.org/abs/1906.12140),
which uses Luby Transform (LT) fountain codes to slash blockchain storage
costs by orders of magnitude.

## The Idea

Full nodes today must store the entire blockchain — hundreds of gigabytes for
Bitcoin, terabytes for high-throughput chains. **SeF** replaces archival full
nodes with lightweight *droplet nodes*:

1. The chain is partitioned into **epochs** of *k* blocks.
2. Each epoch is fountain-encoded: blocks are XOR'd together according to
   degrees sampled from the **Robust Soliton Distribution** to produce
   *droplets* (coded blocks).
3. Each droplet node stores only *s ≪ k* droplets per epoch.
4. A new node (*bucket node*) contacts a set of droplet nodes, unions their
   droplets, and runs the **error-resilient peeling decoder** to reconstruct
   the original blocks — even when some nodes supply adversarial *murky*
   droplets.

The header chain acts as authenticated side-information: Merkle roots in
block headers let the decoder detect and discard murky droplets on the fly,
without propagating errors.

When tuned for **γ = k/s** storage savings, a bucket node recovers the chain
with probability ≥ 1 − δ by contacting **k + O(√k · ln²(k/δ))** honest
nodes.

## Architecture

```
Bitcoin datadir (blk*.dat / bitcoinkernel)
  │
  ▼
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│ BlockSource  │────▶│ for_each_    │────▶│ blocks_to_    │
│ (chain)      │     │ epoch(k,buf) │     │ symbols(sz)   │
└─────────────┘     └──────────────┘     └───────┬───────┘
                                                 │ symbols
                                                 ▼
                    ┌──────────────┐     ┌───────────────┐
                    │ Encoder::    │◀────│ RobustSoliton │
                    │ generate(id) │     │ (distribution)│
                    └──────┬───────┘     └───────────────┘
                           │ droplets
                           ▼
                    ┌──────────────┐
                    │ Droplet files│  ← consensus-serialized to disk
                    └──────┬───────┘
                           │
              ─── network / storage ───
                           │
                           ▼
                    ┌──────────────┐     ┌───────────────┐
                    │ peeling_     │────▶│ BlockVerifier  │
                    │ decode(k,..) │     │ (hash check)   │
                    └──────┬───────┘     └───────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ symbols_to_  │────▶ Recovered blocks
                    │ blocks()     │
                    └──────────────┘
```

## Modules

| Module         | Purpose |
|----------------|---------|
| `chain`        | Bitcoin block readers (`blk*.dat` and `bitcoinkernel` backends). |
| `decoder`      | Peeling decoder with pluggable block verification. |
| `distribution` | Robust Soliton Distribution (RSD) for degree sampling. |
| `droplet`      | `Droplet` struct, `EpochParams`, and `Encoder`. |
| `encode`       | Bitcoin consensus serialization and file I/O for droplets. |
| `epoch`        | Epoch configuration, seed derivation, auto-scaling heuristics. |
| `experiment`   | Storage-reduction simulations (graph-only, no XOR payloads). |
| `symbol`       | Fixed-size symbol normalization and `SymbolManifest`. |
| `xor`          | Bitwise XOR with adaptive zero-padding. |

## Quick Start

```bash
# Build (bitcoinkernel feature is enabled by default)
cargo build --release

# Build without bitcoinkernel (uses raw blk*.dat parsing)
cargo build --release --no-default-features
```

### CLI Commands

```bash
# Show Robust Soliton Distribution statistics
sef dist-info --k 1000 --c 0.1 --delta 0.05

# Display chain info from a Bitcoin data directory
sef chain-info --blocks-dir ~/.bitcoin/signet/blocks

# Generate fountain-coded droplets from signet
sef generate --blocks-dir ~/.bitcoin/signet/blocks --output droplets/ \
    --k 100 --symbol-size 4096

# Decode droplets back into blk*.dat files
sef decode --input droplets/ --output decoded/

# Decode a single epoch
sef decode --input droplets/ --output decoded/ --epoch 42

# End-to-end encode → decode → verify round-trip
sef reconstruct --blocks-dir ~/.bitcoin/signet/blocks --k 100

# Run the storage reduction experiment from the paper
sef experiment --k 100 --trials 500
```

### Library Usage

```rust
use sef::distribution::RobustSoliton;
use sef::droplet::{Encoder, EpochParams};
use sef::decoder::peeling_check;

let k = 50;
let blocks: Vec<Vec<u8>> = (0..k)
    .map(|i| vec![(i & 0xFF) as u8; 256])
    .collect();

let params = EpochParams::new(0, k as u32, [0u8; 32]);
let dist = RobustSoliton::new(k, 0.1, 0.05);
let encoder = Encoder::new(&params, &dist, &blocks);

// Generate 3x overhead droplets
let droplets = encoder.generate_n((k as u64) * 3);

// Verify recoverability via the peeling check
let indices: Vec<Vec<u32>> = droplets.iter().map(|d| d.indices.clone()).collect();
let result = peeling_check(k, &indices);
assert!(result.success);
```

## Feature Flags

| Flag     | Default | Description |
|----------|---------|-------------|
| `kernel` | **yes** | Enables `KernelBlockReader` backed by `bitcoinkernel` for validated block access from a Bitcoin Core datadir. |

## Key Parameters

| Parameter | Typical | Role |
|-----------|---------|------|
| `k`       | 100–10000 | Epoch size — number of source blocks per epoch. |
| `s`       | 5–50    | Droplets stored per node; γ = k/s is the storage reduction factor. |
| `c`       | 0.1     | RSD tuning constant controlling the degree-1 spike. |
| `δ`       | 0.05    | Tolerable decoding failure probability. |
| `symbol_size` | 4096 | Fixed symbol size in bytes for block concatenation (0 = disabled). |
| `buffer`  | 10      | Recent blocks excluded from encoding (confirmation window). |

## References

- S. Kadhe, J. Chung, and K. Ramchandran,
  *"SeF: A Secure Fountain Architecture for Slashing Storage Costs in Blockchains,"*
  arXiv:1906.12140, 2019. <https://arxiv.org/abs/1906.12140>
- M. Luby, *"LT Codes,"* Proc. 43rd IEEE FOCS, 2002.

## License

See `Cargo.toml` for authorship. No license file is currently present —
contact the author for licensing terms.
