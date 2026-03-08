use std::time::Instant;

use sef::experiment;

pub fn run(
    k: usize,
    c: f64,
    delta: f64,
    pool_size: usize,
    trials: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    // ── Part 1: Decoding threshold sweep ──
    println!("=== Decoding Threshold Sweep ===");
    println!(
        "  k={}, c={}, delta={}, pool={}, trials={}\n",
        k, c, delta, pool_size, trials
    );

    let m_values: Vec<usize> = {
        let mut v: Vec<usize> = (k..=k + 20).collect();
        v.extend(
            [k + 30, k + 40, k + 50, k + 75, k * 2]
                .iter()
                .filter(|&&m| m <= pool_size),
        );
        v.sort_unstable();
        v.dedup();
        v
    };

    let sweep = experiment::sweep_total_droplets(k, c, delta, &m_values, pool_size, trials);

    println!(
        "  {:>5}  {:>10}  {:>12}  {:>10}",
        "M", "M/k", "success%", "avg_decoded"
    );
    println!("  {}", "-".repeat(45));
    for (m, rate, mean_dec) in &sweep {
        println!(
            "  {:>5}  {:>10.2}  {:>11.1}%  {:>10.1}",
            m,
            *m as f64 / k as f64,
            rate * 100.0,
            mean_dec
        );
    }

    let m_star_95 = sweep
        .iter()
        .find(|(_, r, _)| *r >= 0.95)
        .map(|(m, _, _)| *m);
    let m_star_99 = sweep
        .iter()
        .find(|(_, r, _)| *r >= 0.99)
        .map(|(m, _, _)| *m);
    println!();
    if let Some(m) = m_star_95 {
        println!(
            "  M* for 95% success: {} ({:.2}x overhead)",
            m,
            m as f64 / k as f64
        );
    } else {
        println!("  M* for 95% success: not reached in sweep range");
    }
    if let Some(m) = m_star_99 {
        println!(
            "  M* for 99% success: {} ({:.2}x overhead)",
            m,
            m as f64 / k as f64
        );
    } else {
        println!("  M* for 99% success: not reached in sweep range");
    }

    // ── Part 2: Multi-node storage reduction ──
    println!("\n=== Multi-Node Storage Reduction ===\n");

    let config = experiment::ExperimentConfig {
        k,
        c,
        delta,
        pool_size,
        trials,
        s_values: vec![5, 10, 20, 50],
        k_nodes_values: (1..=20).collect(),
    };

    let results = experiment::run_experiment(&config);

    for &s in &config.s_values {
        let gamma = k as f64 / s as f64;
        println!(
            "  Storage reduction γ = {:.0}x  (s={} droplets/node)",
            gamma, s
        );
        println!(
            "    {:>3}  {:>10}  {:>10}  {:>12}",
            "K", "avg_M", "success%", "avg_decoded"
        );
        println!("    {}", "-".repeat(42));

        let s_results: Vec<&experiment::ConfigResult> =
            results.iter().filter(|r| r.s == s).collect();

        for r in &s_results {
            println!(
                "    {:>3}  {:>10.1}  {:>11.1}%  {:>10.1}",
                r.k_nodes,
                r.mean_distinct_droplets,
                r.success_rate * 100.0,
                r.mean_decoded,
            );
        }

        let k95 = s_results.iter().find(|r| r.success_rate >= 0.95);
        let k99 = s_results.iter().find(|r| r.success_rate >= 0.99);
        if let Some(r) = k95 {
            println!(
                "    → K for 95%: {} nodes (avg {} distinct droplets)",
                r.k_nodes, r.mean_distinct_droplets as usize
            );
        }
        if let Some(r) = k99 {
            println!(
                "    → K for 99%: {} nodes (avg {} distinct droplets)",
                r.k_nodes, r.mean_distinct_droplets as usize
            );
        }
        println!();
    }

    println!(
        "Total experiment time: {:.2}s",
        start.elapsed().as_secs_f64()
    );
    Ok(())
}
