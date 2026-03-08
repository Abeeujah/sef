use std::{ops::ControlFlow, path::Path, time::Instant};

#[cfg(not(feature = "kernel"))]
use sef::chain::blk_file_reader::BlkFileReader;
use sef::chain::stream::BlockSource;
use sef::{
    chain::{error::ChainError, stream::for_each_epoch},
    distribution::{DegreeDistribution, RobustSoliton},
    droplet::{Encoder, EpochParams},
    encode,
    epoch::{self, EpochConfig},
    symbol,
};

pub fn run(
    blocks_dir: &Path,
    output: &Path,
    cfg: &EpochConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Streaming blocks from: {}", blocks_dir.display());

    #[cfg(feature = "kernel")]
    let source: Box<dyn BlockSource> = {
        use sef::chain::KernelBlockReader;

        let data_dir = blocks_dir.parent().unwrap_or(blocks_dir);
        Box::new(KernelBlockReader::new(
            data_dir,
            bitcoinkernel::ChainType::Signet,
        ))
    };
    #[cfg(not(feature = "kernel"))]
    let source: Box<dyn BlockSource> = Box::new(BlkFileReader::open(blocks_dir)?);

    if cfg.symbol_size > 0 {
        println!(
            "  Symbol normalization: symbol_size={} bytes",
            cfg.symbol_size
        );
    }

    std::fs::create_dir_all(output)?;

    let total_start = Instant::now();
    let mut total_droplets = 0u64;
    let mut total_droplet_bytes = 0u64;
    let mut total_source_bytes = 0u64;

    for_each_epoch(&*source, cfg.k, cfg.buffer, &mut |batch| {
        let epoch_idx = batch.index;
        let epoch_k = batch.blocks.len();

        if epoch_k < 2 {
            println!("  Epoch {}: skipping (only {} block)", epoch_idx, epoch_k);
            return Ok(ControlFlow::Continue(()));
        }

        let epoch_seed = epoch::compute_epoch_seed(epoch_idx, &batch.blocks[0].hash);

        let block_data: Vec<Vec<u8>> = batch.blocks.into_iter().map(|b| b.data).collect();
        let epoch_source_bytes: usize = block_data.iter().map(|b| b.len()).sum();
        total_source_bytes += epoch_source_bytes as u64;

        let epoch_dir = output.join(format!("epoch_{}", epoch_idx));
        std::fs::create_dir_all(&epoch_dir).map_err(ChainError::from)?;

        let (source_units, manifest) = if cfg.symbol_size > 0 {
            let (syms, man) = symbol::blocks_to_symbols(&block_data, cfg.symbol_size);
            (syms, Some(man))
        } else {
            (block_data.clone(), None)
        };

        let unit_k = source_units.len();
        if unit_k < 2 {
            println!(
                "  Epoch {}: skipping (only {} source unit)",
                epoch_idx, unit_k
            );
            return Ok(ControlFlow::Continue(()));
        }

        let epoch_n = epoch::auto_scale_droplets(unit_k, cfg.n);

        let dist = RobustSoliton::new(unit_k, cfg.c, cfg.delta);

        let params = EpochParams::new(epoch_idx as u64, unit_k as u32, epoch_seed);
        let encoder = Encoder::new(&params, &dist, &source_units);

        if let Some(ref man) = manifest {
            let manifest_path = epoch_dir.join("manifest.bin");
            let manifest_bytes = symbol::serialize_manifest(man);
            std::fs::write(&manifest_path, manifest_bytes).map_err(ChainError::from)?;
        }

        let epoch_start = Instant::now();
        let mut epoch_droplet_bytes = 0u64;

        for droplet_id in 0..epoch_n {
            let droplet = encoder.generate(droplet_id);
            let filename = encode::droplet_filename(epoch_idx as u64, droplet_id);
            let filepath = epoch_dir.join(&filename);
            encode::write_droplet_file(&filepath, &droplet).map_err(ChainError::from)?;

            epoch_droplet_bytes += droplet.payload.len() as u64;
            total_droplets += 1;
        }

        total_droplet_bytes += epoch_droplet_bytes;

        println!(
            "  Epoch {:3}: {} blocks, {} symbols, {} droplets, source={:.1}KB, droplets={:.1}KB, E[deg]={:.1} ({:.2}s)",
            epoch_idx,
            epoch_k,
            unit_k,
            epoch_n,
            epoch_source_bytes as f64 / 1024.0,
            epoch_droplet_bytes as f64 / 1024.0,
            dist.expected_degree(),
            epoch_start.elapsed().as_secs_f64(),
        );

        Ok(ControlFlow::Continue(()))
    })?;

    let total_elapsed = total_start.elapsed();
    println!("\n=== Generation Summary ===");
    println!("  Total droplets:     {}", total_droplets);
    println!(
        "  Source data:        {:.2} MB",
        total_source_bytes as f64 / 1e6
    );
    println!(
        "  Droplet data:       {:.2} MB",
        total_droplet_bytes as f64 / 1e6
    );
    if total_source_bytes > 0 {
        println!(
            "  Ratio (droplet/source): {:.2}x",
            total_droplet_bytes as f64 / total_source_bytes as f64
        );
    }
    println!("  Total time:         {:.2}s", total_elapsed.as_secs_f64());
    println!(
        "  Output directory:   {}",
        output
            .canonicalize()
            .unwrap_or_else(|_| output.to_path_buf())
            .display()
    );

    Ok(())
}
