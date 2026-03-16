use std::{io::Write, path::Path, time::Instant};

use sef::{
    decoder::{self, BitcoinBlockVerifier, BitcoinSuperblockVerifier, SymbolVerifier},
    encode, superblock, symbol,
};

/// Bitcoin signet network magic bytes.
const SIGNET_MAGIC: [u8; 4] = [0x0a, 0x03, 0xcf, 0x40];

/// Maximum size of a single blk*.dat file (~128 MiB, matching Bitcoin Core).
const MAX_BLK_FILE_SIZE: u64 = 128 * 1024 * 1024;

struct AcceptAllVerifier;
impl decoder::BlockVerifier for AcceptAllVerifier {
    fn verify_and_len(&self, _idx: u32, candidate: &[u8]) -> Result<usize, decoder::VerifyError> {
        Ok(candidate.len())
    }
}

pub fn run(
    input: &Path,
    output: &Path,
    epoch_filter: Option<usize>,
    no_verify: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Fountain Code Decode ===\n");
    println!("Reading droplets from: {}", input.display());
    let t0 = Instant::now();

    let mut epoch_dirs: Vec<(usize, std::path::PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(input)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if entry.file_type()?.is_dir()
            && let Some(idx_str) = name_str.strip_prefix("epoch_")
            && let Ok(idx) = idx_str.parse::<usize>()
            && (epoch_filter.is_none() || epoch_filter == Some(idx))
        {
            epoch_dirs.push((idx, entry.path()));
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
        let sym_manifest_path = epoch_dir.join("manifest.bin");
        let sb_manifest_path = epoch_dir.join("superblock.bin");
        let headers_path = epoch_dir.join("headers.bin");

        // Determine encoding mode from which metadata file is present
        let is_superblock = sb_manifest_path.exists();
        let is_symbol = sym_manifest_path.exists();
        let has_headers = headers_path.exists();

        if !is_superblock && !is_symbol && !has_headers {
            println!(
                "  Epoch {:3}: skipping (no manifest.bin, superblock.bin, or headers.bin)",
                epoch_idx
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

        let (
            recovered_blocks,
            num_blocks,
            k,
            result_decoded_count,
            result_verify_failures,
            result_failures,
            verify_label,
        ) = if is_superblock {
            // --- Superblock mode ---
            let sb_bytes = std::fs::read(&sb_manifest_path)?;
            let sb_manifest = superblock::deserialize_manifest(&sb_bytes)
                .map_err(|e| format!("epoch {}: bad superblock.bin: {}", epoch_idx, e))?;

            let k = sb_manifest.total_supers;
            if k < 2 {
                println!(
                    "  Epoch {:3}: skipping (only {} superblocks in manifest)",
                    epoch_idx, k
                );
                continue;
            }

            let ranges = superblock::ranges_from_manifest(&sb_manifest);
            let num_blocks = sb_manifest.total_blocks;

            if no_verify {
                let result = decoder::peeling_decode(k, droplets, &AcceptAllVerifier);
                let reassembled =
                    superblock::superblocks_to_blocks(&result.blocks, &ranges, num_blocks);
                let decoded = reassembled.iter().filter(|b| b.is_some()).count();
                let vf = result.verify_failures;
                let failures = result.failures;
                (
                    reassembled,
                    num_blocks,
                    k,
                    decoded,
                    vf,
                    failures,
                    "unverified",
                )
            } else if has_headers {
                let hdr_bytes = std::fs::read(&headers_path)?;
                let headers = superblock::deserialize_headers(&hdr_bytes)
                    .map_err(|e| format!("epoch {}: bad headers.bin: {}", epoch_idx, e))?;
                let verifier = BitcoinSuperblockVerifier {
                    trusted_headers: &headers,
                    ranges: &ranges,
                };
                let result = decoder::peeling_decode(k, droplets, &verifier);
                let reassembled =
                    superblock::superblocks_to_blocks(&result.blocks, &ranges, num_blocks);
                let decoded = reassembled.iter().filter(|b| b.is_some()).count();
                let vf = result.verify_failures;
                let failures = result.failures;
                (
                    reassembled,
                    num_blocks,
                    k,
                    decoded,
                    vf,
                    failures,
                    "verified",
                )
            } else {
                println!(
                    "  Epoch {:3}: skipping (no headers.bin, use --no-verify for insecure decode)",
                    epoch_idx
                );
                continue;
            }
        } else if is_symbol {
            // --- Symbol mode ---
            let manifest_bytes = std::fs::read(&sym_manifest_path)?;
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

            let sym_verifier = SymbolVerifier {
                symbol_size: manifest.symbol_size,
                symbol_hashes: &manifest.symbol_hashes,
            };
            let result = decoder::peeling_decode(k, droplets, &sym_verifier);
            let num_blocks = manifest.block_entries.len();

            let sym_opts: Vec<Option<Vec<u8>>> = result.blocks.into_iter().collect();
            let reassembled = symbol::symbols_to_blocks(&sym_opts, &manifest);

            let vf = result.verify_failures;
            let failures = result.failures;

            // Post-reassembly SeF verification: symbols can't be verified
            // against the header chain during peeling (they don't align to
            // block boundaries), so we verify reconstructed blocks afterwards.
            let verify_label = if no_verify {
                "unverified"
            } else {
                println!(
                    "  Epoch {:3}: skipping (no headers.bin, use --no-verify for insecure decode)",
                    epoch_idx
                );
                continue;
            };

            let decoded = reassembled.iter().filter(|b| b.is_some()).count();
            (
                reassembled,
                num_blocks,
                k,
                decoded,
                vf,
                failures,
                verify_label,
            )
        } else if has_headers {
            // --- Raw mode with headers ---
            let hdr_bytes = std::fs::read(&headers_path)?;
            let headers = superblock::deserialize_headers(&hdr_bytes)
                .map_err(|e| format!("epoch {}: bad headers.bin: {}", epoch_idx, e))?;
            let k = headers.len();
            if k < 2 {
                println!(
                    "  Epoch {:3}: skipping (only {} blocks from headers)",
                    epoch_idx, k
                );
                continue;
            }
            let verifier = BitcoinBlockVerifier {
                trusted_headers: headers,
            };
            let result = decoder::peeling_decode(k, droplets, &verifier);
            let num_blocks = k;

            let decoded = result.blocks.iter().filter(|b| b.is_some()).count();
            let vf = result.verify_failures;
            let failures = result.failures;
            let blocks = result.blocks;
            (blocks, num_blocks, k, decoded, vf, failures, "verified")
        } else {
            println!("  Epoch {:3}: skipping (no metadata files)", epoch_idx);
            continue;
        };

        let decode_time = t_dec.elapsed();

        let mut epoch_recovered = 0usize;
        let mut epoch_bytes = 0u64;

        for block_data in recovered_blocks.iter().flatten() {
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

        if epoch_recovered == num_blocks {
            if verify_label == "unverified" {
                println!(
                    "  Epoch {:3}: ✓ OK (unverified) | {}/{} blocks | {} droplets | {:.1}KB | dec {:.1}ms",
                    epoch_idx,
                    epoch_recovered,
                    num_blocks,
                    num_droplets,
                    epoch_bytes as f64 / 1024.0,
                    decode_time.as_secs_f64() * 1000.0,
                );
            } else {
                println!(
                    "  Epoch {:3}: ✓ OK | {}/{} blocks | {} droplets | {:.1}KB | dec {:.1}ms",
                    epoch_idx,
                    epoch_recovered,
                    num_blocks,
                    num_droplets,
                    epoch_bytes as f64 / 1024.0,
                    decode_time.as_secs_f64() * 1000.0,
                );
            }
        } else {
            println!(
                "  Epoch {:3}: ✗ FAIL | {}/{} blocks decoded | {} droplets (k={}) | dec {:.1}ms | {} verify_fail",
                epoch_idx,
                result_decoded_count,
                num_blocks,
                num_droplets,
                k,
                decode_time.as_secs_f64() * 1000.0,
                result_verify_failures,
            );
            for f in &result_failures {
                println!(
                    "           unit {:3}: referenced by {} remaining droplets",
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
