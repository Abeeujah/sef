use std::{io::BufWriter, ops::ControlFlow, path::Path, time::Instant};

#[cfg(not(feature = "kernel"))]
use sef::chain::blk_file_reader::BlkFileReader;
use sef::chain::stream::BlockSource;
use sef::{
    chain::{error::ChainError, stream::for_each_epoch},
    distribution::{DegreeDistribution, RobustSoliton},
    droplet::{Encoder, EpochParams},
    encode,
    epoch::{self, EpochConfig},
    superblock, symbol,
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

    // Reusable buffers across epochs — grown once, never shrunk
    let mut indices_buf: Vec<u32> = Vec::with_capacity(64);
    let mut payload_buf: Vec<u8> = Vec::new();

    for_each_epoch(&*source, cfg.k, cfg.buffer, &mut |batch| {
        let epoch_idx = batch.index;
        let epoch_k = batch.blocks.len();

        if epoch_k < 2 {
            println!("  Epoch {}: skipping (only {} block)", epoch_idx, epoch_k);
            return Ok(ControlFlow::Continue(()));
        }

        let epoch_seed = epoch::compute_epoch_seed(epoch_idx, &batch.blocks[0].hash);

        let block_data: Vec<Vec<u8>> = batch.blocks.into_iter().map(|b| b.data).collect();

        let trusted_headers: Vec<bitcoin::block::Header> = block_data
            .iter()
            .filter_map(|data| {
                if data.len() >= 80 {
                    bitcoin::consensus::deserialize::<bitcoin::block::Header>(&data[..80]).ok()
                } else {
                    None
                }
            })
            .collect();

        let epoch_source_bytes: usize = block_data.iter().map(|b| b.len()).sum();

        let epoch_dir = output.join(format!("epoch_{}", epoch_idx));
        std::fs::create_dir_all(&epoch_dir).map_err(ChainError::from)?;

        let (source_units, manifest, sb_manifest) = if cfg.superblock_size > 0 {
            let (supers, ranges) =
                superblock::blocks_to_superblocks(&block_data, cfg.superblock_size);
            let block_counts: Vec<usize> = ranges.iter().map(|r| r.end - r.start).collect();
            let sb_man = superblock::SuperblockManifest {
                total_blocks: block_data.len(),
                total_supers: supers.len(),
                block_counts,
            };
            (supers, None, Some(sb_man))
        } else if cfg.symbol_size > 0 {
            let (syms, man) = symbol::blocks_to_symbols(&block_data, cfg.symbol_size);
            (syms, Some(man), None)
        } else {
            (block_data.clone(), None, None)
        };

        let unit_k = source_units.len();
        if unit_k < 2 {
            println!(
                "  Epoch {}: skipping (only {} source unit)",
                epoch_idx, unit_k
            );
            return Ok(ControlFlow::Continue(()));
        }

        total_source_bytes += epoch_source_bytes as u64;

        let epoch_n = epoch::auto_scale_droplets(unit_k, cfg.n);

        let dist = RobustSoliton::new(unit_k, cfg.c, cfg.delta);

        let params = EpochParams::new(epoch_idx as u64, unit_k as u32, epoch_seed);
        let encoder = Encoder::new(&params, &dist, &source_units);

        if let Some(ref man) = manifest {
            let manifest_path = epoch_dir.join("manifest.bin");
            let manifest_bytes = symbol::serialize_manifest(man);
            std::fs::write(&manifest_path, manifest_bytes).map_err(ChainError::from)?;
        }
        if let Some(ref sb_man) = sb_manifest {
            let sb_path = epoch_dir.join("superblock.bin");
            let sb_bytes = superblock::serialize_manifest(sb_man);
            std::fs::write(&sb_path, sb_bytes).map_err(ChainError::from)?;
        }

        // Persist trusted headers for SeF-secure standalone decode.
        // All modes need headers for verification: raw and superblock modes
        // verify during peeling; symbol mode verifies after reassembly.
        let headers_path = epoch_dir.join("headers.bin");
        let headers_bytes = superblock::serialize_headers(&trusted_headers);
        std::fs::write(&headers_path, headers_bytes).map_err(ChainError::from)?;

        // Ensure payload buffer is large enough for the longest source unit
        let max_block_len = source_units.iter().map(|b| b.len()).max().unwrap_or(0);
        if payload_buf.len() < max_block_len {
            payload_buf.resize(max_block_len, 0);
        }

        let epoch_start = Instant::now();
        let mut epoch_droplet_bytes = 0u64;

        // Write all droplets into a single append-only file per epoch
        let droplets_path = epoch_dir.join("droplets.bin");
        let file = std::fs::File::create(&droplets_path).map_err(ChainError::from)?;
        let mut writer = BufWriter::with_capacity(1 << 20, file);

        for droplet_id in 0..epoch_n {
            let (_degree, padded_len) =
                encoder.generate_into(droplet_id, &mut indices_buf, &mut payload_buf);

            // Zero-alloc encode: write directly from borrowed buffers
            encode::encode_droplet_from_parts(
                &mut writer,
                epoch_idx as u64,
                droplet_id,
                &indices_buf,
                padded_len,
                &payload_buf[..padded_len as usize],
            )
            .map_err(|e| ChainError::Io(std::io::Error::other(e)))?;

            epoch_droplet_bytes += padded_len as u64;
            total_droplets += 1;
        }

        // Flush is handled by BufWriter drop, but be explicit
        use std::io::Write;
        writer.flush().map_err(ChainError::from)?;

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
        "  Throughput:         {:.1} MB/s",
        total_source_bytes as f64 / total_elapsed.as_secs_f64() / 1e6
    );
    println!(
        "  Output directory:   {}",
        output
            .canonicalize()
            .unwrap_or_else(|_| output.to_path_buf())
            .display()
    );

    Ok(())
}
