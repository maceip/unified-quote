//! Integration test: Value X computation against a real GitHub Actions runner.
//!
//! Downloads or uses a pre-existing runner installation to verify that
//! compute_value_x produces a deterministic hash over the runner image.

use uq_runner::quote::value_x::compute_value_x;
use std::path::Path;

const RUNNER_DIR: &str = "/tmp/actions-runner";

#[test]
fn test_value_x_on_real_runner() {
    let runner_path = Path::new(RUNNER_DIR);
    if !runner_path.exists() {
        eprintln!("Skipping: {} not found. Download a runner first.", RUNNER_DIR);
        return;
    }

    let start = std::time::Instant::now();
    let x1 = compute_value_x(runner_path).expect("compute_value_x failed");
    let elapsed = start.elapsed();

    println!("Value X = {}", hex::encode(x1));
    println!("Computed in {:?} over {}", elapsed, RUNNER_DIR);

    // Must be deterministic
    let x2 = compute_value_x(runner_path).expect("second compute failed");
    assert_eq!(x1, x2, "Value X must be deterministic across calls");
    println!("Determinism: verified");

    // Must be non-zero (not an empty hash)
    assert_ne!(x1, [0u8; 48], "Value X should not be all zeros");

    // Print size of runner for context
    let file_count = walkdir(runner_path);
    println!("Runner files hashed: {file_count}");
}

fn walkdir(path: &Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                count += walkdir(&p);
            } else if p.is_file() {
                count += 1;
            }
        }
    }
    count
}
