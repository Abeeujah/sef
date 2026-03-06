use rand::Rng;

/// Trait for swappable degree distributions in fountain codes.
///
/// Implementations define how many source symbols are combined into a
/// single encoded packet (the "degree").
pub trait DegreeDistribution {
    /// Samples a degree $d$ such that $1 \le d \le k$ for a given block size `k`.
    ///
    /// This represents the number of source symbols to be XORed together.
    fn sample_degree<R: Rng + ?Sized>(&self, rng: &mut R, k: usize) -> usize;

    /// Computes the expected value $E[D]$ of the distribution for a block size `k`.
    ///
    /// This is typically used to estimate the average number of XOR operations
    /// per packet or to calculate theoretical overhead.
    fn expected_degree(&self, k: usize) -> f64;
}

/// Robust Soliton Distribution (RSD) for LT (Luby Transform) codes.
///
/// The RSD is designed to ensure that a decoder can always find a degree-1
/// packet to start the ripple, while maintaining enough high-degree packets
/// to cover all source symbols.
pub struct RobustSoliton {
    /// Tuning constant that determines the number of degree-1 packets.
    /// Lower values increase efficiency but risk decoder stalls.
    pub c: f64,

    /// The probability that the decoding fails after receiving $K \cdot (1 + \epsilon)$ symbols.
    pub delta: f64,

    /// Cached cumulative distribution function (CDF).
    /// Used for $O(\log d)$ degree sampling via binary search.
    cdf: Vec<f64>,

    /// The number of source symbols (block size) for which `cdf` was generated.
    k: usize,
}

impl RobustSoliton {
    /// Create a new Robust Soliton Distribution for epoch size `k`.
    ///
    /// # Panics
    /// Panics if `k == 0`, `c <= 0.0`, or `delta` is not in the range (0, 1).
    pub fn new(k: usize, c: f64, delta: f64) -> Self {
        assert!(k > 0, "epoch size k must be > 0");
        assert!(c > 0.0, "c must be > 0.0");
        assert!(delta > 0.0 && delta < 1.0, "delta must be in (0, 1");

        let cdf = Self::build_cdf(k, c, delta);
        Self { c, delta, cdf, k }
    }

    /// Rebuilds the CDF for a new epoch size `k`.
    ///
    /// This is an $O(k)$ operation. Use this when the source block size
    /// changes while keeping the same tuning parameters.
    pub fn rebuild(&mut self, k: usize) {
        if self.k == k {
            return;
        }
        self.cdf = Self::build_cdf(k, self.c, self.delta);
        self.k = k;
    }

    /// Returns the block size (k) for which this distribution was built.
    pub fn k(&self) -> usize {
        self.k
    }

    fn build_cdf(k: usize, c: f64, delta: f64) -> Vec<f64> {
        let k_f = k as f64;
        let s = c * (k_f / delta).ln() * k_f.sqrt(); // The "spike" parameter S
        let r_boundary = (k_f / s).round() as usize; // Location of the spike

        let mut cdf = vec![0.0f64; k + 1];
        let mut sum_rho_plus_theta = 0.0;

        // Calculate unnormalized values and total sum (beta)
        let mut pmf = vec![0.0f64; k + 1];
        for (d, pf) in pmf.iter_mut().enumerate().take(k + 1).skip(1) {
            let rho = if d == 1 {
                1.0 / k_f
            } else {
                1.0 / (d as f64 * (d as f64 - 1.0))
            };
            let theta = if r_boundary == 0 {
                0.0
            } else if d < r_boundary {
                s / (d as f64 * k_f)
            } else if d == r_boundary {
                (s / k_f) * (s / delta).ln()
            } else {
                0.0
            };

            *pf = rho + theta;
            sum_rho_plus_theta += *pf;
        }

        // Normalize and build CDF
        let mut running_sum = 0.0;
        for d in 1..=k {
            running_sum += pmf[d] / sum_rho_plus_theta;
            cdf[d] = running_sum;
        }

        cdf[k] = 1.0; // Ensures perfect closure
        cdf
    }
}

impl DegreeDistribution for RobustSoliton {
    fn sample_degree<R: Rng + ?Sized>(&self, rng: &mut R, k: usize) -> usize {
        assert_eq!(
            k, self.k,
            "k mismatch: distribution built for {}, got {}",
            self.k, k
        );
        let u: f64 = rng.r#gen();

        // binary_search_by returns the index of an exact match (Ok)
        // or the insertion point (Err). Both lead us to the correct degree.
        let idx = self.cdf[1..] // skips 0th element as it is `0.0`
            .binary_search_by(|v| v.partial_cmp(&u).expect("NaN in CDF"))
            .unwrap_or_else(|e| e);

        // Adjust back for 1-based indexing and clamp to [1, k]
        (idx + 1).clamp(1, k)
    }

    fn expected_degree(&self, k: usize) -> f64 {
        assert_eq!(k, self.k, "k mismatch");

        self.cdf[..=k]
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

        let expected = dist.expected_degree(k);
        let iterations = 100_000;

        let actual_avg: f64 = (0..iterations)
            .map(|_| dist.sample_degree(&mut rng, k) as f64)
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
            let d = dist.sample_degree(&mut rng, k);
            assert!((1..=100).contains(&d), "degree {} out of range", d);
        }
    }

    #[test]
    fn test_expected_degree() {
        let k = 1000;
        let delta = 0.05;
        let dist = RobustSoliton::new(k, 0.1, delta);

        let e = dist.expected_degree(k);
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
