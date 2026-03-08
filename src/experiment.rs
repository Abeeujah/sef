//! Simulation infrastructure for evaluating fountain code storage reduction in a distributed network model.
//!
//! Models a network of $n = 100$ nodes, each storing a random subset of $s$
//! droplets drawn from a pre-generated pool. The core question: given $K$
//! contacted nodes, can the union of their droplets reconstruct all $k$ source
//! blocks via the peeling decoder?
//!
//! Two experiment modes are provided:
//!
//! - [`run_experiment`] — multi-node storage reduction simulation. Sweeps over
//!   `(s, K)` configurations to measure reconstruction success rate.
//! - [`sweep_total_droplets`] — pure decoding threshold analysis. Ignores the
//!   node model and directly varies the number of distinct droplets $M$.
//!
//! **Depends on:** [`crate::distribution`], [`crate::decoder`].

use std::collections::HashSet;

use rand::{SeedableRng, seq::index::sample};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use crate::{
    decoder::{PeelResult, peeling_check},
    distribution::{DegreeDistribution, RobustSoliton},
};

/// Generates the neighbor (source block) indices for a droplet without computing XOR payloads.
///
/// Uses SHA-256 to derive a deterministic seed from the epoch and droplet
/// metadata, ensuring the graph structure is reproducible across runs and
/// platforms. This mirrors the PRNG derivation in
/// `EpochParams::droplet_rng` but avoids materializing block payloads,
/// making it suitable for graph-only simulation.
///
/// # Examples
///
/// ```
/// use sef::distribution::RobustSoliton;
/// use sef::experiment::generate_droplet_indices;
///
/// let dist = RobustSoliton::new(100, 0.1, 0.05);
/// let seed = [0u8; 32];
/// let indices = generate_droplet_indices(&dist, 100, &seed, 0, 42);
/// assert!(!indices.is_empty());
/// assert!(indices.iter().all(|&i| (i as usize) < 100));
/// ```
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

    let degree = dist.sample_degree(&mut rng);
    let mut indices: Vec<u32> = sample(&mut rng, k, degree)
        .into_iter()
        .map(|i| i as u32)
        .collect();
    indices.sort_unstable();
    indices
}

/// Configuration for a storage reduction experiment.
///
/// Controls every axis of the simulation grid: the fountain code parameters
/// ($k$, $c$, $\delta$), the droplet pool from which nodes draw, and the
/// `(s, K)` sweep ranges.
#[derive(Debug, Clone)]
pub struct ExperimentConfig {
    /// Number of source blocks (symbols) in the epoch. Determines the
    /// Robust Soliton Distribution parameterization.
    pub k: usize,

    /// Robust Soliton parameter $c$. Scales the "spike" that biases the
    /// distribution toward degree-1 droplets, aiding peeling decode startup.
    pub c: f64,

    /// Robust Soliton failure-probability bound $\delta$. Smaller values
    /// produce heavier spike mass at the cost of higher average degree.
    pub delta: f64,

    /// Size of the pre-generated droplet pool. Should be $\geq 3k$ to
    /// ensure sufficient diversity when nodes sample from it.
    pub pool_size: usize,

    /// Number of independent trials executed per `(s, K)` configuration.
    /// Higher values reduce variance in the reported success rate.
    pub trials: usize,

    /// List of "droplets per node" values ($s$) to sweep. Each node stores
    /// exactly $s$ droplets drawn uniformly without replacement from the pool.
    pub s_values: Vec<usize>,

    /// List of "nodes contacted" values ($K$) to sweep. For each $K$, the
    /// simulator unions the droplets of $K$ randomly chosen nodes and
    /// attempts peeling decode.
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

/// Outcome of a single simulation trial for one `(s, K)` pair.
#[derive(Debug, Clone)]
pub struct TrialResult {
    /// Number of droplets stored per node ($s$).
    pub s: usize,

    /// Number of nodes contacted ($K$) in this trial.
    pub k_nodes: usize,

    /// Number of distinct droplets in the union of the $K$ contacted nodes.
    pub distinct_droplets: usize,

    /// Result of running the peeling decoder on the collected droplets.
    pub peel: PeelResult,
}

/// Aggregated statistics for one `(s, K)` configuration across all trials.
#[derive(Debug, Clone)]
pub struct ConfigResult {
    /// Droplets stored per node ($s$).
    pub s: usize,
    /// Number of nodes contacted ($K$).
    pub k_nodes: usize,
    /// Theoretical storage reduction factor: $k / s$.
    pub reduction_factor: f64,
    /// Total number of trials executed.
    pub trials: usize,
    /// Number of trials where all $k$ source blocks were recovered.
    pub successes: usize,
    /// Fraction of trials that achieved full recovery (`successes / trials`).
    pub success_rate: f64,
    /// Mean number of distinct droplets across trials.
    pub mean_distinct_droplets: f64,
    /// Mean number of source blocks decoded per trial.
    pub mean_decoded: f64,
}

/// Runs the full storage reduction experiment across all `(s, K)` configurations.
///
/// Simulates a distributed network of $n = 100$ nodes. Each node stores $s$
/// droplets sampled uniformly without replacement from a pre-generated pool
/// of `pool_size` droplet indices.
///
/// For every `(s, K)` pair in the configuration, the simulator executes
/// `trials` independent rounds:
///
/// 1. Generate a fixed pool of `pool_size` droplet neighbor-index vectors.
/// 2. Assign $s$ unique droplets to each of the 100 nodes.
/// 3. Select $K$ nodes at random, union their droplets.
/// 4. Run the peeling decoder on the union and record success/failure.
///
/// Returns one [`ConfigResult`] per `(s, K)` pair, ordered by ascending $s$
/// then ascending $K$.
///
/// # Examples
///
/// ```ignore
/// use sef::experiment::{ExperimentConfig, run_experiment};
///
/// let config = ExperimentConfig {
///     k: 50,
///     trials: 10,
///     ..Default::default()
/// };
/// let results = run_experiment(&config);
/// for r in &results {
///     println!("s={} K={} success={:.1}%", r.s, r.k_nodes, r.success_rate * 100.0);
/// }
/// ```
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

/// Sweeps over total distinct droplet counts $M$ to locate the decoding threshold.
///
/// Ignores the distributed node model entirely: for each value in `m_values`,
/// the function draws $M$ droplets uniformly from a pool of `pool_size` and
/// runs the peeling decoder. This isolates the pure fountain code overhead
/// from network-topology effects.
///
/// Returns a `Vec<(M, success_rate, mean_decoded)>` where:
/// - `M` — number of distinct droplets presented to the decoder.
/// - `success_rate` — fraction of `trials` where all $k$ blocks were recovered.
/// - `mean_decoded` — average number of source blocks decoded per trial.
///
/// # Examples
///
/// ```ignore
/// use sef::experiment::sweep_total_droplets;
///
/// let results = sweep_total_droplets(50, 0.1, 0.05, &[80, 100, 150], 500, 100);
/// for (m, rate, avg) in &results {
///     println!("M={m} success={rate:.2} avg_decoded={avg:.1}");
/// }
/// ```
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
