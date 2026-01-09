// Native Rust signing benchmark
// Run with: cargo run --release --bin sign_benchmark -- <data_dir>
//
// This benchmarks the signing operation in native Rust (no WASM overhead)
// to compare with WASM performance.

use anyhow::{Context, Result};
use dwallet_mpc_centralized_party::advance_centralized_sign_party;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <data_dir>", args[0]);
        eprintln!();
        eprintln!("The data_dir should contain:");
        eprintln!("  - protocol_pp.bin");
        eprintln!("  - dkg_output.bin");
        eprintln!("  - secret_share.bin");
        eprintln!("  - presign.bin");
        eprintln!("  - message.bin");
        eprintln!("  - params.json (curve, signature_algorithm, hash_scheme)");
        eprintln!();
        eprintln!("Run your backend with SAVE_SIGN_DATA=1 to generate test data.");
        std::process::exit(1);
    }

    let data_dir = PathBuf::from(&args[1]);

    println!("=== Native Rust Signing Benchmark ===\n");

    // Load test data
    println!("Loading test data from {:?}...", data_dir);

    let protocol_pp = fs::read(data_dir.join("protocol_pp.bin"))
        .context("Failed to read protocol_pp.bin")?;
    println!("  protocol_pp: {} bytes ({:.1} MB)", protocol_pp.len(), protocol_pp.len() as f64 / 1_000_000.0);

    let dkg_output = fs::read(data_dir.join("dkg_output.bin"))
        .context("Failed to read dkg_output.bin")?;
    println!("  dkg_output: {} bytes", dkg_output.len());

    let secret_share = fs::read(data_dir.join("secret_share.bin"))
        .context("Failed to read secret_share.bin")?;
    println!("  secret_share: {} bytes", secret_share.len());

    let presign = fs::read(data_dir.join("presign.bin"))
        .context("Failed to read presign.bin")?;
    println!("  presign: {} bytes", presign.len());

    let message = fs::read(data_dir.join("message.bin"))
        .context("Failed to read message.bin")?;
    println!("  message: {} bytes", message.len());

    let params: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(data_dir.join("params.json"))
            .context("Failed to read params.json")?
    )?;

    let curve = params["curve"].as_u64().unwrap() as u32;
    let signature_algorithm = params["signature_algorithm"].as_u64().unwrap() as u32;
    let hash_scheme = params["hash_scheme"].as_u64().unwrap() as u32;

    println!("  curve: {}, sig_algo: {}, hash: {}", curve, signature_algorithm, hash_scheme);
    println!();

    // Warm-up run
    println!("Warm-up run...");
    let _ = advance_centralized_sign_party(
        protocol_pp.clone(),
        dkg_output.clone(),
        secret_share.clone(),
        presign.clone(),
        message.clone(),
        curve,
        signature_algorithm,
        hash_scheme,
    );
    println!("Warm-up complete.\n");

    // Benchmark runs
    const NUM_RUNS: usize = 3;
    let mut times = Vec::with_capacity(NUM_RUNS);

    println!("Running {} benchmark iterations...\n", NUM_RUNS);

    for i in 0..NUM_RUNS {
        let start = Instant::now();

        let result = advance_centralized_sign_party(
            protocol_pp.clone(),
            dkg_output.clone(),
            secret_share.clone(),
            presign.clone(),
            message.clone(),
            curve,
            signature_algorithm,
            hash_scheme,
        );

        let elapsed = start.elapsed();
        times.push(elapsed.as_millis());

        match result {
            Ok(sig) => println!("  Run {}: {}ms (signature: {} bytes)", i + 1, elapsed.as_millis(), sig.len()),
            Err(e) => println!("  Run {}: {}ms (ERROR: {})", i + 1, elapsed.as_millis(), e),
        }
    }

    println!();
    println!("=== Results ===");
    let avg: u128 = times.iter().sum::<u128>() / times.len() as u128;
    let min = times.iter().min().unwrap();
    let max = times.iter().max().unwrap();

    println!("  Average: {}ms", avg);
    println!("  Min:     {}ms", min);
    println!("  Max:     {}ms", max);
    println!();
    println!("Compare with WASM time (~8000ms) to see speedup.");
    println!("Expected native speedup: 1.5-2x faster than WASM.");

    Ok(())
}
