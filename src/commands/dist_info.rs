use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sef::distribution::{DegreeDistribution, RobustSoliton};

pub fn run(k: usize, c: f64, delta: f64) {
    let dist = RobustSoliton::new(k, c, delta);
    let expected = dist.expected_degree();

    println!("Robust Soliton Distribution");
    println!("  k (epoch size): {}", k);
    println!("  c:              {}", c);
    println!("  delta:          {}", delta);
    println!("  E[degree]:      {:.2}", expected);

    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let n_samples = 10_000;
    let mut counts = vec![0u32; k + 1];
    for _ in 0..n_samples {
        let d = dist.sample_degree(&mut rng);
        counts[d] += 1;
    }

    println!("\n  Degree distribution (top 10 most frequent):");
    let mut ranked: Vec<(usize, u32)> = counts
        .iter()
        .enumerate()
        .filter(|(_, c)| **c > 0)
        .map(|(d, &c)| (d, c))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    for (d, count) in ranked.iter().take(10) {
        println!(
            "    d={:4}: {:5} ({:.1}%)",
            d,
            count,
            *count as f64 / n_samples as f64 * 100.0
        );
    }
}
