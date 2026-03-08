use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sef")]
#[command(about = "Fountain code based blockchain pruning prototype")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Show distribution statistics for given parameters
    DistInfo {
        /// Epoch size (number of blocks)
        #[arg(short, long, default_value_t = 1000)]
        k: usize,
        /// Tuning constant c
        #[arg(short, long, default_value_t = 0.1)]
        c: f64,
        /// Failure probability delta
        #[arg(short, long, default_value_t = 0.05)]
        delta: f64,
    },

    /// Generate fountain-coded droplets from the signet chain
    Generate {
        /// Path to Bitcoin blocks directory (e.g., ~/.bitcoin/signet/blocks)
        #[arg(short, long)]
        blocks_dir: PathBuf,

        /// Output directory for droplet files
        #[arg(short, long, default_value = "droplets")]
        output: PathBuf,

        /// Epoch size (number of blocks per epoch)
        #[arg(short, long, default_value_t = 100)]
        k: usize,

        /// Number of droplets to generate per epoch (0 = auto-scale to 2x symbol count)
        #[arg(short, long, default_value_t = 0)]
        n: u64,

        /// Buffer: number of recent blocks to keep raw (not encode)
        #[arg(long, default_value_t = 10)]
        buffer: usize,

        /// Robust Soliton parameter c
        #[arg(short, long, default_value_t = 0.1)]
        c: f64,

        /// Robust Soliton parameter delta
        #[arg(long, default_value_t = 0.05)]
        delta: f64,

        /// Symbol size in bytes for block concatenation (0 = disabled)
        #[arg(long, default_value_t = 4096)]
        symbol_size: usize,
    },

    /// Show info about blocks in a data directory
    ChainInfo {
        /// Path to Bitcoin blocks directory
        #[arg(short, long)]
        blocks_dir: PathBuf,
    },

    /// End-to-end reconstruction: encode → droplets → decode → verify
    Reconstruct {
        /// Path to Bitcoin blocks directory
        #[arg(short, long)]
        blocks_dir: PathBuf,

        /// Epoch size
        #[arg(short, long, default_value_t = 100)]
        k: usize,

        /// Number of droplets per epoch (0 = auto-scale to 2x symbol count)
        #[arg(short, long, default_value_t = 0)]
        n: u64,

        /// Buffer: recent blocks to exclude
        #[arg(long, default_value_t = 10)]
        buffer: usize,

        /// Robust Soliton parameter c
        #[arg(short, long, default_value_t = 0.1)]
        c: f64,

        /// Robust Soliton parameter delta
        #[arg(long, default_value_t = 0.05)]
        delta: f64,

        /// Only reconstruct this epoch index (optional)
        #[arg(long)]
        epoch: Option<usize>,

        /// Symbol size in bytes for block concatenation (0 = disabled)
        #[arg(long, default_value_t = 4096)]
        symbol_size: usize,
    },

    /// Print help information
    Help,

    /// Run storage reduction experiment
    Experiment {
        /// Epoch size
        #[arg(short, long, default_value_t = 100)]
        k: usize,

        /// Robust Soliton parameter c
        #[arg(short, long, default_value_t = 0.1)]
        c: f64,

        /// Robust Soliton parameter delta
        #[arg(long, default_value_t = 0.05)]
        delta: f64,

        /// Total droplet pool size
        #[arg(long, default_value_t = 500)]
        pool_size: usize,

        /// Number of trials per configuration
        #[arg(short, long, default_value_t = 500)]
        trials: usize,
    },
}
