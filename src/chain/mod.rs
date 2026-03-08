//! Blockchain data ingestion for the fountain encoder.
//!
//! This module abstracts over different Bitcoin Core data sources via the
//! [`BlockSource`](stream::BlockSource) trait, enabling streaming block access
//! with *O*(*epoch_size*) memory.
//!
//! Two backends are provided:
//!
//! - [`BlkFileReader`](blk_file_reader::BlkFileReader) — parses raw `blk*.dat`
//!   files directly, handling XOR obfuscation and chain-ordering internally.
//! - [`KernelBlockReader`] *(behind the
//!   `kernel` feature flag)* — provides validated, index-ordered block access
//!   via the `bitcoinkernel` C library FFI.
//!
//! # Submodules
//!
//! - [`stream`] — core traits ([`BlockSource`](stream::BlockSource)) and epoch
//!   grouping ([`for_each_epoch`](stream::for_each_epoch)).
//! - [`blk_file_reader`] — raw `blk*.dat` file backend.
//! - `kernel_reader` — kernel FFI backend (requires `kernel` feature).
//! - [`error`] — unified [`ChainError`](error::ChainError) type.

pub mod blk_file_reader;
pub mod error;
#[cfg(feature = "kernel")]
pub mod kernel_reader;
pub mod stream;

#[cfg(feature = "kernel")]
pub use kernel_reader::KernelBlockReader;
