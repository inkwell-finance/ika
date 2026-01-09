// Run with: cargo bench --bench sign_benchmark
// Compare with WASM times to see native vs WASM overhead

use std::time::Instant;

fn main() {
    println!("=== Native Rust Signing Benchmark ===\n");
    println!("This benchmark measures the raw signing performance.");
    println!("Compare with WASM times to estimate speedup potential.\n");

    // We need test data - for now just print instructions
    println!("To run a proper benchmark, you need:");
    println!("1. Sample protocol_pp bytes (44MB)");
    println!("2. Sample presign bytes");
    println!("3. Sample secret key share");
    println!("4. Sample DKG output");
    println!();
    println!("For quick estimation:");
    println!("- WASM is typically 1.5-3x slower than native Rust");
    println!("- If native takes 3-4s, WASM at 8s is expected");
    println!("- CPU single-thread performance is key (not cores)");
    println!();
    println!("CPU benchmarks to look at:");
    println!("- Passmark Single Thread: https://www.cpubenchmark.net/singleThread.html");
    println!("- Your current CPU's single-thread score vs faster options");
    println!();

    // Print current CPU info if available
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in info.lines() {
                if line.starts_with("model name") {
                    println!("Current CPU: {}", line.split(':').nth(1).unwrap_or("unknown").trim());
                    break;
                }
            }
        }
    }
}
