use std::collections::HashSet;

use rand::{SeedableRng, seq::index::sample};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use crate::{
    decoder::{PeelResult, peeling_check},
    distribution::{DegreeDistribution, RobustSoliton},
};

/// Generate the neighbor indices for a droplet (without computing XOR payloads).
///
/// Uses Sha256 to derive a deterministic seed from the epoch and droplet metadata,
/// ensuring the graph structure is reproducible across different runs and platforms.
pub fn generate_droplet_indices<D: DegreeDistribution>(
    dist: &D,
    k: usize,
    epoch_seed: &[u8; 32],
    epoch_id: u64,
    droplet_id: u64,
) -> Vec<u32> {
    let hash = Sha256::new()
        .chain_update(epoch_seed)
        .chain_update(b"droplet")
        .chain_update(epoch_id.to_le_bytes())
        .chain_update(droplet_id.to_le_bytes())
        .finalize();
    let mut rng = ChaCha8Rng::from_seed(hash.into());

    let degree = dist.sample_degree(&mut rng, k);
    let mut indices: Vec<u32> = sample(&mut rng, k, degree)
        .into_iter()
        .map(|i| i as u32)
        .collect();
    indices.sort_unstable();
    indices
}

/// Configuration for a storage reduction experiment.
#[derive(Debug, Clone)]
pub struct ExperimentConfig {
    /// Epoch size (number of source blocks).
    pub k: usize,

    /// Robust Soliton parameter c (determines the 'spike' in the distribution).
    pub c: f64,

    /// Robust Soliton parameter delta (allowable failure probability).
    pub delta: f64,

    /// Total droplet pool size (should be >= 3k).
    pub pool_size: usize,

    /// Number of trials per (s, K) configuration.
    pub trials: usize,

    /// Droplets stored per individual node.
    pub s_values: Vec<usize>,

    /// Number of nodes sampled to attempt reconstruction.
    pub k_nodes_values: Vec<usize>,
}

impl Default for ExperimentConfig {
    fn default() -> Self {
        Self {
            k: 100,
            c: 0.1,
            delta: 0.05,
            pool_size: 500,
            trials: 500,
            s_values: vec![5, 10, 20, 50],
            k_nodes_values: (1..=20).collect(),
        }
    }
}

/// Result of one experiment trial.
#[derive(Debug, Clone)]
pub struct TrialResult {
    /// Droplets per node.
    pub s: usize,

    /// Number of nodes contacted.
    pub k_nodes: usize,

    /// Number of distinct droplets obtained (after union).
    pub distinct_droplets: usize,

    /// Peeling decoder result.
    pub peel: PeelResult,
}

/// Result of a full experiment configuration (aggregated over trials).
#[derive(Debug, Clone)]
pub struct ConfigResult {
    pub s: usize,
    pub k_nodes: usize,
    pub reduction_factor: f64,
    pub trials: usize,
    pub successes: usize,
    pub success_rate: f64,
    pub mean_distinct_droplets: f64,
    pub mean_decoded: f64,
}

/// Run the full storage reduction experiment.
///
/// This simulation models a distributed network of $n=100$ nodes.
/// Each node stores a subset of $s$ droplets from a larger pre-generated pool.
///
/// The experiment evaluates the "solvability" of the graph: can we reconstruct
/// the $k$ source blocks by contacting only $K$ nodes?
///
/// ### Process:
/// 1. Generate a fixed pool of `pool_size` droplet indices.
/// 2. Assign $s$ unique droplets to each of the 100 simulated nodes.
/// 3. For each $(s, K)$ configuration, run $N$ trials.
/// 4. In each trial, pick $K$ nodes, union their unique droplets, and run the peeling decoder.
pub fn run_experiment(config: &ExperimentConfig) -> Vec<ConfigResult> {
    let dist = RobustSoliton::new(config.k, config.c, config.delta);
    let epoch_seed = [0u8; 32];
    let epoch_id = 0u64;
    let n_nodes = 100; // Simulated network size (fixed for this experiment)

    // 1. Generate the droplet pool (indices only for speed)
    let pool: Vec<Vec<u32>> = (0..config.pool_size as u64)
        .map(|did| generate_droplet_indices(&dist, config.k, &epoch_seed, epoch_id, did))
        .collect();

    let mut results = Vec::new();

    for &s in &config.s_values {
        if s > config.pool_size {
            continue;
        }

        // 2. Pre-generate node assignments (Static for all K-sweeps of this 's')
        let mut master_rng = ChaCha8Rng::seed_from_u64(42);
        let node_droplets: Vec<Vec<usize>> = (0..n_nodes)
            .map(|_| {
                let mut assigned: Vec<usize> = sample(&mut master_rng, config.pool_size, s)
                    .into_iter()
                    .collect();
                assigned.sort_unstable();
                assigned
            })
            .collect();

        for &k_nodes in &config.k_nodes_values {
            if k_nodes > n_nodes {
                continue;
            }

            let mut successes = 0usize;
            let mut total_distinct = 0usize;
            let mut total_decoded = 0usize;

            // Deterministic seed per (s, k_nodes) pair for reproducible results
            let mut trial_rng = ChaCha8Rng::seed_from_u64((s as u64) * 1_000 + (k_nodes as u64));

            // 3. Run Trials
            for _ in 0..config.trials {
                let selected_nodes: Vec<usize> = sample(&mut trial_rng, n_nodes, k_nodes)
                    .into_iter()
                    .collect();

                // Union unique droplets from selected nodes
                let mut droplet_set: HashSet<usize> = HashSet::new();
                for &node_idx in &selected_nodes {
                    for &did in &node_droplets[node_idx] {
                        droplet_set.insert(did);
                    }
                }

                let distinct_count = droplet_set.len();
                total_distinct += distinct_count;

                let selected_indices: Vec<Vec<u32>> =
                    droplet_set.iter().map(|&did| pool[did].clone()).collect();

                // 4. Peeling Decoder Simulation
                let peel = peeling_check(config.k, &selected_indices);
                if peel.success {
                    successes += 1;
                }
                total_decoded += peel.decoded;
            }

            // 5. Aggregate and Push Result (Once per configuration)
            results.push(ConfigResult {
                s,
                k_nodes,
                reduction_factor: config.k as f64 / s as f64,
                trials: config.trials,
                successes,
                success_rate: successes as f64 / config.trials as f64,
                mean_distinct_droplets: total_distinct as f64 / config.trials as f64,
                mean_decoded: total_decoded as f64 / config.trials as f64,
            });
        }
    }
    results
}

/// Run a sweep over total distinct droplets M to find the decoding threshold.
///
/// This ignores the distributed "node" aspect and treats the problem as a
/// pure Fountain Code decoding efficiency test.
pub fn sweep_total_droplets(
    k: usize,
    c: f64,
    delta: f64,
    m_values: &[usize],
    pool_size: usize,
    trials: usize,
) -> Vec<(usize, f64, f64)> {
    let dist = crate::distribution::RobustSoliton::new(k, c, delta);
    let epoch_seed = [0u8; 32];
    let epoch_id = 0u64;

    // Generate pool
    let pool: Vec<Vec<u32>> = (0..pool_size as u64)
        .map(|did| generate_droplet_indices(&dist, k, &epoch_seed, epoch_id, did))
        .collect();

    let mut results = Vec::new();

    for &m in m_values {
        if m > pool_size {
            continue;
        }

        let mut successes = 0usize;
        let mut total_decoded = 0usize;
        let mut rng = ChaCha8Rng::seed_from_u64(m as u64 * 7919);

        for _ in 0..trials {
            let selected: Vec<usize> = sample(&mut rng, pool_size, m).into_iter().collect();

            let indices: Vec<Vec<u32>> = selected.iter().map(|&did| pool[did].clone()).collect();

            let peel = peeling_check(k, &indices);
            if peel.success {
                successes += 1;
            }
            total_decoded += peel.decoded;
        }

        let success_rate = successes as f64 / trials as f64;
        let mean_decoded = total_decoded as f64 / trials as f64;
        results.push((m, success_rate, mean_decoded));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_droplet_indices_deterministic() {
        let dist = RobustSoliton::new(100, 0.1, 0.05);
        let seed = [42u8; 32];
        let i1 = generate_droplet_indices(&dist, 100, &seed, 0, 7);
        let i2 = generate_droplet_indices(&dist, 100, &seed, 0, 7);
        assert_eq!(i1, i2);
    }

    #[test]
    fn test_sweep_with_enough_droplets_succeeds() {
        // With M=200 droplets for k=50, should almost always succeed
        let results = sweep_total_droplets(50, 0.1, 0.5, &[100], 300, 50);
        assert!(!results.is_empty());
        let (_, rate, _) = results[0];
        assert!(
            rate > 0.8,
            "expected high success rate with 2x droplets, got {}",
            rate
        );
    }

    #[test]
    fn test_sweep_with_few_droplets_fails() {
        // With M=10 droplets for k=50, should almost never succeed
        let results = sweep_total_droplets(50, 0.1, 0.5, &[10], 300, 50);
        assert!(!results.is_empty());
        let (_, rate, _) = results[0];
        assert!(
            rate < 0.5,
            "expected low success rate with few droplets, got {}",
            rate
        );
    }
}
