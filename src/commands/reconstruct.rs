use std::{ops::ControlFlow, path::Path, time::Instant};

use bitcoin::consensus::deserialize;
#[cfg(not(feature = "kernel"))]
use sef::chain::blk_file_reader::BlkFileReader;
use sef::{
    chain::{error::ChainError, stream::EpochBatch},
    decoder::{self, BitcoinBlockVerifier, SymbolVerifier},
    distribution::RobustSoliton,
    droplet::{Encoder, EpochParams},
    epoch::{self, EpochConfig},
    symbol,
};

pub fn run(
    blocks_dir: &Path,
    cfg: &EpochConfig,
    epoch_filter: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Fountain Code Reconstruction ===\n");
    let t0 = Instant::now();

    println!("Streaming blocks from: {}", blocks_dir.display());
    if cfg.symbol_size > 0 {
        println!(
            "Symbol normalization: symbol_size={} bytes",
            cfg.symbol_size
        );
    }

    let mut total_blocks_attempted = 0usize;
    let mut total_blocks_recovered = 0usize;
    let mut total_source_bytes = 0usize;
    let mut total_recovered_bytes = 0usize;
    let mut total_encode_us = 0u128;
    let mut total_decode_us = 0u128;
    let mut total_verify_failures = 0usize;
    let mut had_epochs = false;

    let mut epoch_visitor = |batch: EpochBatch| -> Result<ControlFlow<()>, ChainError> {
        if let Some(target) = epoch_filter
            && batch.index != target
        {
            return Ok(ControlFlow::Continue(()));
        }

        had_epochs = true;
        let epoch_idx = batch.index;
        let epoch_k = batch.blocks.len();
        if epoch_k < 2 {
            if epoch_filter.is_some() {
                return Ok(ControlFlow::Break(()));
            }
            return Ok(ControlFlow::Continue(()));
        }

        let first_hash = batch.blocks[0].hash.clone();
        let block_data: Vec<Vec<u8>> = batch.blocks.into_iter().map(|b| b.data).collect();
        let source_bytes: usize = block_data.iter().map(|b| b.len()).sum();

        let expected_hashes: Vec<bitcoin::block::Header> = block_data
            .iter()
            .map(|data| {
                let block: bitcoin::Block = deserialize(data)
                    .map_err(|e| ChainError::Parse(format!("block parse failed: {e}")))?;
                Ok(block.header)
            })
            .collect::<Result<Vec<_>, ChainError>>()?;

        let (source_units, manifest) = if cfg.symbol_size > 0 {
            let (syms, man) = symbol::blocks_to_symbols(&block_data, cfg.symbol_size);
            (syms, Some(man))
        } else {
            (block_data.clone(), None)
        };

        let unit_k = source_units.len();
        if unit_k < 2 {
            if epoch_filter.is_some() {
                return Ok(ControlFlow::Break(()));
            }
            return Ok(ControlFlow::Continue(()));
        }

        let epoch_n = epoch::auto_scale_droplets(unit_k, cfg.n);

        // ── Encode ──
        let dist = RobustSoliton::new(unit_k, cfg.c, cfg.delta);
        let epoch_seed = epoch::compute_epoch_seed(epoch_idx, &first_hash);

        let params = EpochParams::new(epoch_idx as u64, unit_k as u32, epoch_seed);
        let encoder = Encoder::new(&params, &dist, &source_units);

        let t_enc = Instant::now();
        let droplets: Vec<_> = (0..epoch_n).map(|id| encoder.generate(id)).collect();
        let encode_time = t_enc.elapsed();

        // ── Decode ──
        let t_dec = Instant::now();

        let (
            recovered_blocks,
            decode_result_decoded_count,
            decode_result_success,
            decode_result_verify_failures,
            decode_result_failures,
        ) = if let Some(ref man) = manifest {
            let sym_verifier = SymbolVerifier {
                symbol_size: cfg.symbol_size,
                symbol_hashes: &man.symbol_hashes,
            };
            let result = decoder::peeling_decode(unit_k, droplets, &sym_verifier);
            let sym_success = result.is_success();
            let _sym_decoded = result.decoded_count;
            let sym_verify_fail = result.verify_failures;
            let sym_failures = result.failures.clone();

            if sym_success {
                let sym_opts: Vec<Option<Vec<u8>>> = result.blocks.into_iter().collect();
                let reassembled = symbol::symbols_to_blocks(&sym_opts, man);
                let block_count = reassembled.iter().filter(|b| b.is_some()).count();
                let all_ok = block_count == epoch_k;
                (
                    reassembled,
                    block_count,
                    all_ok,
                    sym_verify_fail,
                    sym_failures,
                )
            } else {
                let sym_opts: Vec<Option<Vec<u8>>> = result.blocks.into_iter().collect();
                let reassembled = symbol::symbols_to_blocks(&sym_opts, man);
                let block_count = reassembled.iter().filter(|b| b.is_some()).count();
                (
                    reassembled,
                    block_count,
                    false,
                    sym_verify_fail,
                    sym_failures,
                )
            }
        } else {
            let verifier = BitcoinBlockVerifier {
                trusted_headers: expected_hashes.clone(),
            };
            let result = decoder::peeling_decode(epoch_k, droplets, &verifier);
            let success = result.is_success();
            let decoded = result.decoded_count;
            let vf = result.verify_failures;
            let failures = result.failures.clone();
            (result.blocks, decoded, success, vf, failures)
        };

        let decode_time = t_dec.elapsed();

        // ── Verify byte-for-byte ──
        let mut byte_match = true;
        if decode_result_success {
            for (i, recovered) in recovered_blocks.iter().enumerate() {
                if let Some(recovered) = recovered
                    && recovered != &block_data[i]
                {
                    println!(
                        "  WARNING: Epoch {} block {} recovered but bytes differ! ({} vs {} bytes)",
                        epoch_idx,
                        i,
                        recovered.len(),
                        block_data[i].len()
                    );
                    byte_match = false;
                }
            }
        }

        let recovered_bytes: usize = recovered_blocks
            .iter()
            .filter_map(|b| b.as_ref())
            .map(|b| b.len())
            .sum();

        total_blocks_attempted += epoch_k;
        total_blocks_recovered += decode_result_decoded_count;
        total_source_bytes += source_bytes;
        total_recovered_bytes += recovered_bytes;
        total_encode_us += encode_time.as_micros();
        total_decode_us += decode_time.as_micros();
        total_verify_failures += decode_result_verify_failures;

        let status = if decode_result_success && byte_match {
            "✓ OK"
        } else if decode_result_success {
            "⚠ HASH OK, BYTES DIFFER"
        } else {
            "✗ FAIL"
        };

        println!(
            "  Epoch {:3}: {} | {}/{} blocks | enc {:.1}ms | dec {:.1}ms | {} droplets (k_sym={}) | {} verify_fail",
            epoch_idx,
            status,
            decode_result_decoded_count,
            epoch_k,
            encode_time.as_secs_f64() * 1000.0,
            decode_time.as_secs_f64() * 1000.0,
            epoch_n,
            unit_k,
            decode_result_verify_failures,
        );

        if !decode_result_success {
            println!(
                "         Stall: {} undecoded symbols",
                decode_result_failures.len()
            );
            for f in &decode_result_failures {
                println!(
                    "           symbol {:3}: referenced by {} remaining droplets",
                    f.index, f.referenced_by
                );
            }
        }

        if epoch_filter.is_some() {
            Ok(ControlFlow::Break(()))
        } else {
            Ok(ControlFlow::Continue(()))
        }
    };

    #[cfg(feature = "kernel")]
    {
        use sef::chain::{KernelBlockReader, stream::for_each_epoch};

        let data_dir = blocks_dir.parent().unwrap_or(blocks_dir);
        let source = KernelBlockReader::new(data_dir, bitcoinkernel::ChainType::Signet);
        for_each_epoch(&source, cfg.k, cfg.buffer, &mut epoch_visitor)?;
    }
    #[cfg(not(feature = "kernel"))]
    {
        use sef::chain::stream::for_each_epoch;

        let source = BlkFileReader::open(blocks_dir)?;
        for_each_epoch(&source, cfg.k, cfg.buffer, &mut epoch_visitor)?;
    }

    if !had_epochs {
        println!("No epochs to process.");
        return Ok(());
    }

    // ── Summary ──
    println!("\n=== Reconstruction Summary ===");
    println!(
        "  Blocks recovered:   {}/{}",
        total_blocks_recovered, total_blocks_attempted
    );
    println!(
        "  Recovery rate:      {:.1}%",
        total_blocks_recovered as f64 / total_blocks_attempted as f64 * 100.0
    );
    println!(
        "  Source data:         {:.2} MB",
        total_source_bytes as f64 / 1e6
    );
    println!(
        "  Recovered data:     {:.2} MB",
        total_recovered_bytes as f64 / 1e6
    );
    println!(
        "  Encode throughput:  {:.1} MB/s",
        total_source_bytes as f64 / (total_encode_us as f64 / 1e6) / 1e6
    );
    println!(
        "  Decode throughput:  {:.1} MB/s",
        total_recovered_bytes as f64 / (total_decode_us as f64 / 1e6) / 1e6
    );
    println!("  Verify failures:    {}", total_verify_failures);
    println!("  Total time:         {:.2}s", t0.elapsed().as_secs_f64());

    Ok(())
}
