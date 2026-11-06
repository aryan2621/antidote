//! Known-bad / known-good sample sets. A rule change that brings the noise back, or silences a real
//! detection, fails here. Add a sample by dropping a file in `tests/data/{bad,good}`.

use std::path::Path;

use antidote_core::{corpus, scan::scan_tree};

fn scan(dir: &str) -> Vec<antidote_core::Finding> {
    let mut out = vec![];
    scan_tree(&corpus::load().unwrap(), &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(dir), &mut out);
    out
}

#[test]
fn known_bad_samples_still_fire() {
    let out = scan("bad");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/bad");
    for f in std::fs::read_dir(dir).unwrap() {
        let name = f.unwrap().file_name().to_string_lossy().to_string();
        let (id, sample) = (name.split('.').next().unwrap(), &name);
        assert!(out.iter().any(|x| x.id == id && x.path.ends_with(sample.as_str())), "{id} no longer fires on {sample}");
    }
}

#[test]
fn known_good_samples_have_no_high_findings() {
    let high: Vec<_> = scan("good").into_iter().filter(|f| matches!(f.severity, "high" | "critical")).map(|f| format!("{} {}", f.id, f.path)).collect();
    assert!(high.is_empty(), "false positives: {high:?}");
}
