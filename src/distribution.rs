//! Degree distribution trait and the Robust Soliton Distribution (RSD) for LT codes.
//!
//! This module defines [`DegreeDistribution`], the abstraction over how many source
//! blocks each encoded droplet combines, and provides the canonical implementation
//! [`RobustSoliton`] — the probability distribution at the heart of Luby Transform
//! codes.
//!
//! The RSD augments the Ideal Soliton Distribution with a "spike" at degree
//! $d = \lfloor K / S \rfloor$ (where $S = c \sqrt{K} \ln(K/\delta)$) to maintain
//! the decoding *ripple* — the set of degree-1 packets available to the peeling
//! decoder at each step. Without this spike, the ripple collapses to zero with
//! high probability before all source symbols are recovered.
//!
//! **Reference:** M. Luby, "LT Codes", *Proc. 43rd Annual IEEE Symposium on
//! Foundations of Computer Science (FOCS)*, 2002.
//!
//! # Examples
//!
//! ```
//! use sef::distribution::{RobustSoliton, DegreeDistribution};
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha8Rng;
//!
//! let k = 256;
//! let rsd = RobustSoliton::new(k, 0.1, 0.05);
//!
//! let mut rng = ChaCha8Rng::seed_from_u64(0);
//! let degree = rsd.sample_degree(&mut rng);
//! assert!((1..=k).contains(&degree));
//!
//! let avg = rsd.expected_degree();
//! assert!(avg > 0.0);
//! ```

use rand::Rng;

/// Trait for swappable degree distributions in fountain codes.
///
/// Implementations define how many source symbols are combined into a
/// single encoded packet (the "degree").
pub trait DegreeDistribution {
    /// Samples a degree $d$ satisfying the contract $1 \le d \le K$.
    ///
    /// Implementations **must** guarantee the returned value lies in $[1, K]$,
    /// where $K$ is the number of source blocks. Values outside this range
    /// will cause out-of-bounds index selection during encoding.
    fn sample_degree<R: Rng + ?Sized>(&self, rng: &mut R) -> usize;

    /// Computes the expected value $E[D]$ of the distribution.
    ///
    /// Used for overhead estimation and diagnostic reporting. The value
    /// reflects the average number of XOR operations per encoded packet
    /// under the current parameterization.
    fn expected_degree(&self) -> f64;
}

/// Robust Soliton Distribution (RSD) for LT (Luby Transform) codes.
///
/// The RSD is designed to ensure that a decoder can always find a degree-1
/// packet to start the ripple, while maintaining enough high-degree packets
/// to cover all source symbols. It is parameterized by a tuning constant
/// [`c`](RobustSoliton::c) and a failure bound [`delta`](RobustSoliton::delta).
pub struct RobustSoliton {
    /// Free parameter that scales the spike magnitude $S = c \sqrt{K} \ln(K/\delta)$.
    ///
    /// Smaller values reduce overhead (fewer redundant droplets needed) at
    /// the cost of a thinner ripple and higher decoding-failure probability.
    pub c: f64,

    /// Upper bound on decoding-failure probability after receiving
    /// $K \cdot (1 + \varepsilon)$ encoded symbols.
    ///
    /// Appears in $S = c \sqrt{K} \ln(K/\delta)$; tighter bounds (smaller
    /// `delta`) widen the spike and increase the expected degree.
    pub delta: f64,

    /// Pre-computed cumulative distribution function over degrees $[0, K]$.
    ///
    /// Entry `cdf[d]` equals $\Pr[D \le d]$. Built once in [`RobustSoliton::new`]
    /// (or [`rebuild`](RobustSoliton::rebuild)) and enables $O(\log K)$
    /// degree sampling via binary search.
    cdf: Vec<f64>,

    /// The number of source symbols ($K$) for which [`cdf`](RobustSoliton) was computed.
    k: usize,
}

impl RobustSoliton {
    /// Creates a new [`RobustSoliton`] distribution for epoch size `k`.
    ///
    /// Pre-computes the CDF over degrees $[1, k]$ so that subsequent calls
    /// to [`sample_degree`](DegreeDistribution::sample_degree) are $O(\log k)$.
    ///
    /// # Panics
    ///
    /// Panics if `k == 0`, `c <= 0.0`, or `delta` is not in the range $(0, 1)$.
    ///
    /// # Examples
    ///
    /// ```
    /// use sef::distribution::RobustSoliton;
    ///
    /// let rsd = RobustSoliton::new(1024, 0.1, 0.05);
    /// assert_eq!(rsd.k(), 1024);
    /// ```
    pub fn new(k: usize, c: f64, delta: f64) -> Self {
        assert!(k > 0, "epoch size k must be > 0");
        assert!(c > 0.0, "c must be > 0.0");
        assert!(delta > 0.0 && delta < 1.0, "delta must be in (0, 1");

        let cdf = Self::build_cdf(k, c, delta);
        Self { c, delta, cdf, k }
    }

    /// Rebuilds the CDF for a new epoch size `k`, retaining [`c`](RobustSoliton::c)
    /// and [`delta`](RobustSoliton::delta).
    ///
    /// This is an $O(k)$ operation. A no-op if `k` equals the current value.
    ///
    /// # Panics
    ///
    /// Panics if `k == 0`.
    pub fn rebuild(&mut self, k: usize) {
        assert!(k > 0, "epoch size k must be > 0");
        if self.k == k {
            return;
        }
        self.cdf = Self::build_cdf(k, self.c, self.delta);
        self.k = k;
    }

    /// Returns the source-block count $K$ for which the CDF is currently computed.
    ///
    /// Relevant when reusing a single [`RobustSoliton`] instance across epochs
    /// of different sizes — call [`rebuild`](RobustSoliton::rebuild) whenever
    /// `k` changes.
    pub fn k(&self) -> usize {
        self.k
    }

    fn build_cdf(k: usize, c: f64, delta: f64) -> Vec<f64> {
        let k_f = k as f64;
        let s = c * (k_f / delta).ln() * k_f.sqrt(); // The "spike" parameter S
        let r_boundary = (k_f / s).round() as usize; // Location of the spike

        let mut cdf = vec![0.0f64; k + 1];
        let mut sum_rho_plus_tau = 0.0;

        // Calculate unnormalized values and total sum (beta)
        let mut pmf = vec![0.0f64; k + 1];
        for (d, pf) in pmf.iter_mut().enumerate().take(k + 1).skip(1) {
            let rho = if d == 1 {
                1.0 / k_f
            } else {
                1.0 / (d as f64 * (d as f64 - 1.0))
            };
            let tau = if r_boundary == 0 {
                0.0
            } else if d < r_boundary {
                s / (d as f64 * k_f)
            } else if d == r_boundary {
                (s / k_f) * (s / delta).ln()
            } else {
                0.0
            };

            *pf = rho + tau;
            sum_rho_plus_tau += *pf;
        }

        // Normalize and build CDF
        let mut running_sum = 0.0;
        for d in 1..=k {
            running_sum += pmf[d] / sum_rho_plus_tau;
            cdf[d] = running_sum;
        }

        cdf[k] = 1.0; // Ensures perfect closure
        cdf
    }
}

impl DegreeDistribution for RobustSoliton {
    /// Draws a uniform variate $u \in [0, 1)$ and performs a binary search
    /// over the pre-computed CDF to return the corresponding degree in $[1, K]$.
    fn sample_degree<R: Rng + ?Sized>(&self, rng: &mut R) -> usize {
        let u: f64 = rng.r#gen();

        // binary_search_by returns the index of an exact match (Ok)
        // or the insertion point (Err). Both lead us to the correct degree.
        let idx = self.cdf[1..] // skips 0th element as it is `0.0`
            .binary_search_by(|v| v.partial_cmp(&u).expect("NaN in CDF"))
            .unwrap_or_else(|e| e);

        // Adjust back for 1-based indexing and clamp to [1, k]
        (idx + 1).clamp(1, self.k)
    }

    /// Computes $E[D] = \sum_{d=1}^{K} d \cdot p(d)$ by differencing consecutive
    /// CDF entries to recover each probability mass $p(d)$.
    fn expected_degree(&self) -> f64 {
        self.cdf[..=self.k]
            .windows(2)
            .enumerate()
            .map(|(i, window)| {
                let d = (i + 1) as f64;
                let p = window[1] - window[0];
                d * p
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_distribution_consistency() {
        let k = 1000;
        let dist = RobustSoliton::new(k, 0.1, 0.05);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let expected = dist.expected_degree();
        let iterations = 100_000;

        let actual_avg: f64 = (0..iterations)
            .map(|_| dist.sample_degree(&mut rng) as f64)
            .sum::<f64>()
            / iterations as f64;
        let diff = (actual_avg - expected).abs();

        assert!(
            diff < 0.1,
            "Sampled average {} deviated too far from expected {}",
            actual_avg,
            expected
        );
    }

    #[test]
    fn test_cdf_is_valid() {
        let k = 1000;
        let dist = RobustSoliton::new(k, 0.1, 0.05);
        assert!(dist.cdf[0] == 0.0 && dist.cdf[k] == 1.0);

        for d in 1..=k {
            assert!(
                dist.cdf[d] >= dist.cdf[d - 1],
                "CDF not monotone at d={}",
                d
            );
        }
    }

    #[test]
    fn test_pmf_sums_to_one() {
        let k = 500;
        let dist = RobustSoliton::new(k, 0.1, 0.05);
        let total: f64 = (1..=k).map(|d| dist.cdf[d] - dist.cdf[d - 1]).sum();
        assert!(
            (total - 1.0).abs() < 1e-10,
            "PMF does not sum to 1: {}",
            total
        );
    }

    #[test]
    fn test_sampling_produces_valid_degrees() {
        let k = 100;
        let dist = RobustSoliton::new(k, 0.1, 0.05);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        for _ in 0..10_000 {
            let d = dist.sample_degree(&mut rng);
            assert!((1..=100).contains(&d), "degree {} out of range", d);
        }
    }

    #[test]
    fn test_expected_degree() {
        let k = 1000;
        let delta = 0.05;
        let dist = RobustSoliton::new(k, 0.1, delta);

        let e = dist.expected_degree();
        let (expected_degree, _) = (1..=k).fold((0.0, 0.0), |(sum, prev), d| {
            let current_cdf = dist.cdf[d];
            let prob = current_cdf - prev;
            (sum + (d as f64 * prob), current_cdf)
        });

        assert!(
            (e - expected_degree).abs() < 1e-10,
            "Expected degree {} deviated from target {}",
            e,
            expected_degree
        );
    }
}
