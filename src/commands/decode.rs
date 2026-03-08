use std::{io::Write, path::Path, time::Instant};

use sef::{
    decoder::{self, SymbolVerifier},
    encode, symbol,
};

/// Bitcoin signet network magic bytes.
const SIGNET_MAGIC: [u8; 4] = [0x0a, 0x03, 0xcf, 0x40];

/// Maximum size of a single blk*.dat file (~128 MiB, matching Bitcoin Core).
const MAX_BLK_FILE_SIZE: u64 = 128 * 1024 * 1024;

pub fn run(
    input: &Path,
    output: &Path,
    epoch_filter: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Fountain Code Decode ===\n");
    println!("Reading droplets from: {}", input.display());
    let t0 = Instant::now();

    let mut epoch_dirs: Vec<(usize, std::path::PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(input)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if entry.file_type()?.is_dir() {
            if let Some(idx_str) = name_str.strip_prefix("epoch_") {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    if epoch_filter.is_none() || epoch_filter == Some(idx) {
                        epoch_dirs.push((idx, entry.path()));
                    }
                }
            }
        }
    }
    epoch_dirs.sort_by_key(|(idx, _)| *idx);

    if epoch_dirs.is_empty() {
        println!("No epoch directories found.");
        return Ok(());
    }

    std::fs::create_dir_all(output)?;

    let mut total_epochs = 0usize;
    let mut total_blocks_recovered = 0usize;
    let mut total_blocks_attempted = 0usize;
    let mut total_recovered_bytes = 0u64;
    let mut total_droplets_loaded = 0usize;

    // blk file writer state
    let mut blk_file_idx = 0u32;
    let mut blk_file: Option<std::io::BufWriter<std::fs::File>> = None;
    let mut blk_file_bytes = 0u64;

    let open_next_blk = |output: &Path,
                         idx: &mut u32|
     -> Result<std::io::BufWriter<std::fs::File>, std::io::Error> {
        let path = output.join(format!("blk{:05}.dat", idx));
        *idx += 1;
        Ok(std::io::BufWriter::new(std::fs::File::create(path)?))
    };

    for (epoch_idx, epoch_dir) in &epoch_dirs {
        let manifest_path = epoch_dir.join("manifest.bin");
        if !manifest_path.exists() {
            println!("  Epoch {:3}: skipping (no manifest.bin)", epoch_idx);
            continue;
        }

        let manifest_bytes = std::fs::read(&manifest_path)?;
        let manifest = symbol::deserialize_manifest(&manifest_bytes)
            .map_err(|e| format!("epoch {}: bad manifest: {}", epoch_idx, e))?;

        let k = manifest.total_symbols;
        if k < 2 {
            println!(
                "  Epoch {:3}: skipping (only {} symbols in manifest)",
                epoch_idx, k
            );
            continue;
        }

        // Load droplets: prefer batched droplets.bin, fall back to per-file format
        let batched_path = epoch_dir.join("droplets.bin");
        let droplets = if batched_path.exists() {
            encode::read_epoch_droplets(&batched_path)?
        } else {
            let mut per_file = Vec::new();
            for entry in std::fs::read_dir(epoch_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.ends_with(".bin") && name_str.contains("droplet") {
                    match encode::read_droplet_file(&entry.path()) {
                        Ok(d) => per_file.push(d),
                        Err(e) => {
                            eprintln!(
                                "  WARNING: epoch {} failed to read {}: {}",
                                epoch_idx, name_str, e
                            );
                        }
                    }
                }
            }
            per_file
        };

        let num_droplets = droplets.len();
        total_droplets_loaded += num_droplets;

        let t_dec = Instant::now();

        let sym_verifier = SymbolVerifier {
            symbol_size: manifest.symbol_size,
            symbol_hashes: &manifest.symbol_hashes,
        };
        let result = decoder::peeling_decode(k, droplets, &sym_verifier);
        let decode_time = t_dec.elapsed();

        let num_blocks = manifest.block_entries.len();

        if result.is_success() {
            let sym_opts: Vec<Option<Vec<u8>>> = result.blocks.into_iter().collect();
            let recovered_blocks = symbol::symbols_to_blocks(&sym_opts, &manifest);

            let mut epoch_recovered = 0usize;
            let mut epoch_bytes = 0u64;

            for block_data in recovered_blocks.iter().flatten() {
                // Rotate blk file if needed
                if blk_file.is_none()
                    || blk_file_bytes + block_data.len() as u64 + 8 > MAX_BLK_FILE_SIZE
                {
                    if let Some(ref mut f) = blk_file {
                        f.flush()?;
                    }
                    blk_file = Some(open_next_blk(output, &mut blk_file_idx)?);
                    blk_file_bytes = 0;
                }

                let writer = blk_file.as_mut().unwrap();
                writer.write_all(&SIGNET_MAGIC)?;
                writer.write_all(&(block_data.len() as u32).to_le_bytes())?;
                writer.write_all(block_data)?;
                blk_file_bytes += 8 + block_data.len() as u64;

                epoch_recovered += 1;
                epoch_bytes += block_data.len() as u64;
            }

            total_blocks_recovered += epoch_recovered;
            total_blocks_attempted += num_blocks;
            total_recovered_bytes += epoch_bytes;

            println!(
                "  Epoch {:3}: ✓ OK | {}/{} blocks | {} droplets | {:.1}KB | dec {:.1}ms",
                epoch_idx,
                epoch_recovered,
                num_blocks,
                num_droplets,
                epoch_bytes as f64 / 1024.0,
                decode_time.as_secs_f64() * 1000.0,
            );
        } else {
            total_blocks_attempted += num_blocks;

            println!(
                "  Epoch {:3}: ✗ FAIL | {}/{} symbols decoded | {} droplets | dec {:.1}ms | {} verify_fail",
                epoch_idx,
                result.decoded_count,
                k,
                num_droplets,
                decode_time.as_secs_f64() * 1000.0,
                result.verify_failures,
            );
            for f in &result.failures {
                println!(
                    "           symbol {:3}: referenced by {} remaining droplets",
                    f.index, f.referenced_by
                );
            }
        }

        total_epochs += 1;
    }

    if let Some(ref mut f) = blk_file {
        f.flush()?;
    }

    println!("\n=== Decode Summary ===");
    println!("  Epochs processed:   {}", total_epochs);
    println!(
        "  Blocks recovered:   {}/{}",
        total_blocks_recovered, total_blocks_attempted
    );
    if total_blocks_attempted > 0 {
        println!(
            "  Recovery rate:      {:.1}%",
            total_blocks_recovered as f64 / total_blocks_attempted as f64 * 100.0
        );
    }
    println!(
        "  Recovered data:     {:.2} MB",
        total_recovered_bytes as f64 / 1e6
    );
    println!("  Droplets loaded:    {}", total_droplets_loaded);
    println!("  Output files:       {} blk*.dat file(s)", blk_file_idx);
    println!("  Total time:         {:.2}s", t0.elapsed().as_secs_f64());
    println!(
        "  Output directory:   {}",
        output
            .canonicalize()
            .unwrap_or_else(|_| output.to_path_buf())
            .display()
    );

    Ok(())
}
