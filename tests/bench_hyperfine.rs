//! Hyperfine performance benchmarks — require `CCTX_BENCH=1` and `hyperfine` in PATH.
//!
//! Run with:
//!   CCTX_BENCH=1 cargo test --test bench_hyperfine -- --ignored --test-threads=1

fn skip_unless_bench() -> bool {
    std::env::var("CCTX_BENCH").ok().as_deref() != Some("1")
}

fn hyperfine_available() -> bool {
    std::process::Command::new("hyperfine").arg("--version").output().is_ok()
}

fn run_hyperfine(args: &[&str], export_path: &str) -> serde_json::Value {
    std::fs::create_dir_all("target/bench").unwrap();
    let status = std::process::Command::new("hyperfine")
        .args(["--warmup", "3", "--runs", "50",
               "--export-json", export_path])
        .args(args)
        .status().unwrap();
    assert!(status.success(), "hyperfine failed");
    let bytes = std::fs::read(export_path).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[ignore = "requires CCTX_BENCH=1 and hyperfine in PATH"]
#[test]
fn list_mean_under_100ms() {
    if skip_unless_bench() { return; }
    if !hyperfine_available() { return; }
    let bin = env!("CARGO_BIN_EXE_cctx");
    let json = run_hyperfine(&[bin], "target/bench/list.json");
    let mean_s = json["results"][0]["mean"].as_f64().unwrap();
    assert!(mean_s < 0.1, "cctx list mean = {:.1}ms > 100ms", mean_s * 1000.0);
}

#[ignore = "requires CCTX_BENCH=1 and hyperfine in PATH"]
#[test]
fn current_mean_under_100ms() {
    if skip_unless_bench() { return; }
    if !hyperfine_available() { return; }
    let bin = env!("CARGO_BIN_EXE_cctx");
    let json = run_hyperfine(&[&format!("{bin} -c")], "target/bench/current.json");
    let mean_s = json["results"][0]["mean"].as_f64().unwrap();
    assert!(mean_s < 0.1, "cctx -c mean = {:.1}ms > 100ms", mean_s * 1000.0);
}

#[ignore = "requires CCTX_BENCH=1 and hyperfine in PATH"]
#[test]
fn switch_mean_under_100ms() {
    if skip_unless_bench() { return; }
    if !hyperfine_available() { return; }
    let bin = env!("CARGO_BIN_EXE_cctx");
    let json = run_hyperfine(&[&format!("{bin} personal")], "target/bench/switch.json");
    let mean_s = json["results"][0]["mean"].as_f64().unwrap();
    assert!(mean_s < 0.1, "cctx personal mean = {:.1}ms > 100ms", mean_s * 1000.0);
}
