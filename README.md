# SeF — Secure Fountain Architecture for Blockchains

[![Rust](https://img.shields.io/badge/rust-2024_edition-orange)](https://www.rust-lang.org/)
[![arXiv](https://img.shields.io/badge/arXiv-1906.12140-b31b1b)](https://arxiv.org/abs/1906.12140)
[![GitHub](https://img.shields.io/badge/github-abeeujah%2Fsef-24292e)](https://github.com/abeeujah/sef)

A Rust implementation of the **Secure Fountain (SeF)** architecture from
[Kadhe, Chung & Ramchandran (2019)](https://arxiv.org/abs/1906.12140),
which uses Luby Transform (LT) fountain codes to slash blockchain storage
costs by orders of magnitude.

Full nodes are the backbone of the Bitcoin network, they store the entire
chain, validate every block, and keep the network honest. But that integrity
comes at a cost: hundreds of gigabytes of storage that grows without bound,
pricing out anyone without dedicated hardware. This creates a real tension:
the more storage costs, the fewer people run full nodes, and the more 
centralized (and vulnerable) the network becomes.

Pruning addresses the storage problem but undermines the security guarantee.
A pruned node that can't validate from its own state must request missing data
from peers — and has no way to know if those peers are lying.

This project implements a third path: using fountain codes to let a network of
pruned nodes collectively serve as an archive. Each node stores only a small
encoded fraction of the chain; any new node can reconstruct the full history by
querying enough peers — and the block header chain provides the authenticated
side-information needed to detect and reject malicious responses along the way.

The result is archive-class availability at a fraction of the per-node storage
cost, without weakening the trust model.

## Why SeF?

Full nodes today must store the entire blockchain — hundreds of gigabytes for
Bitcoin. SeF replaces archival full nodes with pruned nodes that can act as archives:

1. The chain is partitioned into **epochs** of *k* blocks.
2. Each epoch is fountain-encoded: blocks are XOR'd together according to
   degrees sampled from the **Robust Soliton Distribution**, producing
   *droplets* (coded blocks).
3. Each droplet node stores only **s ≪ k** droplets per epoch.
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
                        ╔═══════════════════╗
                        ║  Bitcoin datadir   ║
                        ║  blk*.dat files    ║
                        ╚════════╤══════════╝
                                 │
                                 ▼
                        ┌───────────────────┐
                        │   BlockSource     │  chain module
                        │  (Kernel / Blk)   │  blk*.dat or bitcoinkernel
                        └────────┬──────────┘
                                 │ raw blocks
                                 ▼
                        ┌───────────────────┐
                        │  for_each_epoch   │  epoch module
                        │  (k, buffer)      │  partition into epochs of k blocks
                        └────────┬──────────┘
                                 │ Vec<Block> per epoch
                                 ▼
              ┌──────────────────┼──────────────────┐
              │                  │                   │
              ▼                  ▼                   ▼
     ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
     │  Superblock    │ │  Raw blocks    │ │  Symbol mode   │
     │  (default)     │ │  (passthrough) │ │  (--symbol-    │
     │  --superblock- │ │                │ │   size N)      │
     │  size N        │ │                │ │                │
     │  ✓ SeF-secure  │ │  ✓ SeF-secure  │ │  ✗ NOT secure  │
     └───────┬────────┘ └───────┬────────┘ └───────┬────────┘
              └──────────────────┼──────────────────┘
                                 │ source units
                                 ▼
    ┌───────────────┐   ┌───────────────────┐
    │ RobustSoliton │──▶│     Encoder       │  droplet module
    │ (k, c, δ)     │   │  generate_into()  │  sample degree, XOR units
    └───────────────┘   └────────┬──────────┘
                                 │ Droplets
                                 ▼
                        ┌───────────────────┐
                        │  encode module    │  consensus-serialize
                        │  droplets.bin     │  + headers.bin
                        │  + manifests      │  + superblock.bin / manifest.bin
                        └────────┬──────────┘
                                 │
                    ═══ network / storage ═══
                                 │
                                 ▼
                        ┌───────────────────┐
                        │  peeling_decode   │  decoder module
                        │  (k, droplets,    │  iterative singleton resolution
                        │   verifier)       │
                        └────────┬──────────┘
                                 │          ┌───────────────────┐
                                 ├─────────▶│  BlockVerifier    │
                                 │  verify  │  • header hash    │
                                 │  each    │  • Merkle root    │
                                 │  block   │  (per singleton)  │
                                 │          └───────────────────┘
                                 ▼
              ┌──────────────────┼──────────────────┐
              │                  │                   │
              ▼                  ▼                   ▼
     ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
     │ superblocks_   │ │ (identity)     │ │ symbols_to_    │
     │ to_blocks()    │ │                │ │ blocks()       │
     └───────┬────────┘ └───────┬────────┘ └───────┬────────┘
              └──────────────────┼──────────────────┘
                                 │
                                 ▼
                        ┌───────────────────┐
                        │  Recovered blocks │  written as blk*.dat
                        │  (blk00000.dat …) │
                        └───────────────────┘
```

## Getting Started

### Prerequisites

- **Rust 2024 edition** (nightly or stable ≥ 1.85)
- A Bitcoin Core datadir with `blk*.dat` files (e.g. signet for testing)
- *(Optional)* [`bitcoinkernel`](https://crates.io/crates/bitcoinkernel) C library for validated block access

### Build

```bash
# Default build (with bitcoinkernel support)
cargo build --release

# Without bitcoinkernel (falls back to raw blk*.dat parsing)
cargo build --release --no-default-features

# Run tests
cargo test
```

## CLI Reference

### `sef dist-info` — Distribution Statistics

Print Robust Soliton Distribution statistics for given parameters.

```bash
sef dist-info --k 1000 --c 0.1 --delta 0.05
```

### `sef chain-info` — Inspect a Bitcoin Datadir

Display block count and metadata from a Bitcoin data directory.

```bash
sef chain-info --blocks-dir ~/.bitcoin/signet/blocks
```

### `sef generate` — Encode Blocks into Droplets

Fountain-encode blockchain epochs and write droplet files to disk. The
`generate` command also persists trusted headers (`headers.bin`) alongside
droplets for later verified decoding.

```bash
# Superblock mode (SeF-secure, default)
sef generate --blocks-dir ~/.bitcoin/signet/blocks --output droplets/ \
    --k 10000 --superblock-size 5000000

# Symbol mode (NOT SeF-secure)
sef generate --blocks-dir ~/.bitcoin/signet/blocks --output droplets/ \
    --k 100 --symbol-size 4096 --superblock-size 0
```

| Flag | Default | Description |
|------|---------|-------------|
| `--blocks-dir` | *(required)* | Path to Bitcoin `blocks/` directory |
| `--output` | `droplets` | Output directory for droplet files |
| `--k` | `100` | Epoch size (source blocks per epoch) |
| `--n` | `0` (auto) | Droplets per epoch; `0` = auto-scale to 2× source count |
| `--buffer` | `10` | Recent blocks excluded from encoding (confirmation window) |
| `--c` | `0.1` | RSD tuning constant |
| `--delta` | `0.05` | Tolerable failure probability |
| `--symbol-size` | `0` (off) | Fixed symbol size in bytes; non-zero enables symbol mode |
| `--superblock-size` | `10000000` | Target superblock size in bytes; `0` disables superblock grouping |

### `sef decode` — Recover Blocks from Droplets

Reconstruct source blocks from droplet files, optionally verifying each
recovered block against trusted headers.

```bash
# Decode all epochs (verified)
sef decode --input droplets/ --output decoded/

# Decode a single epoch
sef decode --input droplets/ --output decoded/ --epoch 42

# Skip header verification (NOT SeF-secure)
sef decode --input droplets/ --output decoded/ --no-verify
```

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | `droplets` | Directory containing `epoch_N/` subdirectories |
| `--output` | `decoded` | Output directory for recovered block files |
| `--epoch` | *(all)* | Decode only this epoch index |
| `--no-verify` | `false` | Skip block verification (not SeF-secure) |

### `sef reconstruct` — End-to-End Round-Trip

Encode → decode → verify in one shot, useful for testing and validation.

```bash
sef reconstruct --blocks-dir ~/.bitcoin/signet/blocks --k 100
```

### `sef experiment` — Storage Reduction Simulation

Run the graph-only storage reduction experiment from the paper (no XOR
payloads, fast).

```bash
sef experiment --k 100 --trials 500
```

| Flag | Default | Description |
|------|---------|-------------|
| `--k` | `100` | Epoch size |
| `--c` | `0.1` | RSD tuning constant |
| `--delta` | `0.05` | Failure probability |
| `--pool-size` | `500` | Total droplet pool size |
| `--trials` | `500` | Number of trials per configuration |

## Library Usage

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

// Generate 3× overhead droplets
let droplets = encoder.generate_n((k as u64) * 3);

// Verify recoverability via the peeling check
let indices: Vec<Vec<u32>> = droplets.iter().map(|d| d.indices.clone()).collect();
let result = peeling_check(k, &indices);
assert!(result.success);
```

## Modules

| Module | Purpose |
|--------|---------|
| `chain` | Bitcoin block readers — raw `blk*.dat` parser and `bitcoinkernel`-backed reader. |
| `decoder` | Peeling decoder with pluggable `BlockVerifier` trait (Bitcoin, superblock, symbol modes). |
| `distribution` | `DegreeDistribution` trait and Robust Soliton Distribution (RSD) implementation. |
| `droplet` | `Droplet` struct, `EpochParams`, and `Encoder` for fountain code generation. |
| `encode` | Bitcoin consensus serialization and file I/O for droplet persistence. |
| `epoch` | `EpochConfig`, deterministic seed derivation, and auto-scaling heuristics. |
| `experiment` | Storage-reduction simulations (graph-only, no XOR payloads). |
| `superblock` | Groups consecutive blocks into verifiable superblock source units. |
| `symbol` | Fixed-size symbol slicing and `SymbolManifest` for reassembly (**not SeF-secure**). |
| `xor` | Bitwise XOR with adaptive zero-padding. |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `kernel` | **yes** | Enables `KernelBlockReader` backed by `bitcoinkernel` for validated block access from a Bitcoin Core datadir. |

## Security Model

The SeF paper's core security property: during peeling decode, every
recovered singleton is verified against the **independently obtained trusted
header chain** before being accepted. This prevents murky (adversarial)
droplets from propagating errors through the decode graph.

Verification checks both the block header hash **and** the recomputed Merkle
root of the recovered transactions against the trusted header, ensuring
neither header-only nor payload-only forgeries can pass.

| Mode | SeF-secure? | Verification |
|------|-------------|--------------|
| **Superblock** | ✓ Yes | Header hash + Merkle root per constituent block |
| **Raw blocks** | ✓ Yes | Header hash + Merkle root per block |
| **Symbol** | ✗ No | SHA-256 manifest hashes (requires trusted manifest) |

## Key Parameters

| Parameter | Typical | Role |
|-----------|---------|------|
| `k` | 100–10,000 | Epoch size — number of source blocks per epoch. |
| `s` | 5–50 | Droplets stored per node; γ = k/s is the storage reduction factor. |
| `c` | 0.1 | RSD tuning constant controlling the degree-1 spike. |
| `δ` | 0.05 | Tolerable decoding failure probability. |
| `superblock_size` | 10 MB | Target superblock byte size for SeF-secure encoding. |
| `symbol_size` | 4096 | Fixed symbol size in bytes (symbol mode only, not SeF-secure). |
| `buffer` | 10 | Recent blocks excluded from encoding (confirmation window). |

## References

- S. Kadhe, J. Chung, and K. Ramchandran,
  *"SeF: A Secure Fountain Architecture for Slashing Storage Costs in Blockchains,"*
  arXiv:1906.12140, 2019. <https://arxiv.org/abs/1906.12140>
- M. Luby, *"LT Codes,"* Proc. 43rd IEEE FOCS, 2002.

## License

See `Cargo.toml` for authorship. No license file is currently present —
contact the author for licensing terms.
