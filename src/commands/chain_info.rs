use std::{path::Path, time::Instant};

#[cfg(not(feature = "kernel"))]
use sef::chain::blk_file_reader::BlkFileReader;
#[cfg(feature = "kernel")]
use sef::chain::KernelBlockReader;
use sef::chain::stream::BlockSource;

pub fn run(blocks_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Reading blocks from: {}", blocks_dir.display());
    let start = Instant::now();

    #[cfg(feature = "kernel")]
    let source: Box<dyn BlockSource> = {
        let data_dir = blocks_dir.parent().unwrap_or(blocks_dir);
        Box::new(KernelBlockReader::new(
            data_dir,
            bitcoinkernel::ChainType::Signet,
        ))
    };
    #[cfg(not(feature = "kernel"))]
    let source: Box<dyn BlockSource> = Box::new(BlkFileReader::open(blocks_dir)?);

    let stats = source.chain_stats()?;

    let elapsed = start.elapsed();
    let avg_size = if stats.block_count == 0 {
        0
    } else {
        stats.total_bytes / stats.block_count as u64
    };

    println!("Chain loaded in {:.2}s", elapsed.as_secs_f64());
    println!("  Total blocks:    {}", stats.block_count);
    println!(
        "  Total data:      {:.2} MB",
        stats.total_bytes as f64 / 1e6
    );
    println!("  Block sizes:");
    println!("    min: {} bytes", stats.min_block_size);
    println!("    max: {} bytes", stats.max_block_size);
    println!("    avg: {} bytes", avg_size);
    println!(
        "  Tip: height={}, hash={}",
        stats.tip_height, stats.tip_hash
    );

    Ok(())
}
