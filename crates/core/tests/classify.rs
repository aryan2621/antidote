//! Rust inference must reproduce ml/train.py's scores (golden.json is written by the trainer).
use std::fs;
use std::path::Path;

use antidote_core::classify::Model;

#[test]
fn matches_python() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let model = Model::from_json(&fs::read_to_string(repo.join("corpus/models/injection-v1.json")).unwrap()).unwrap();
    let golden: Vec<serde_json::Value> = serde_json::from_str(&fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden.json")).unwrap()).unwrap();
    assert!(golden.len() >= 100);
    for g in &golden {
        let text = g["text"].as_str().unwrap();
        let want = g["score"].as_f64().unwrap() as f32;
        let got = model.score(text);
        assert!((got - want).abs() < 1e-4, "score mismatch {got} vs {want} for {text:?}");
    }
}
