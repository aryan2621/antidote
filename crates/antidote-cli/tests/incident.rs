use std::process::{Command, Stdio};

fn incident(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_antidote")).args(["incident", "new"]).args(args).stdin(Stdio::null()).output().unwrap()
}

#[test]
fn write_uses_next_id_and_validates_enums() {
    let dir = std::env::temp_dir().join(format!("antidote-incident-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("entries")).unwrap();
    let base = ["--summary", "s", "--date", "2026-09", "--impact", "data loss", "--ref", "https://e.com/x"];
    let out = incident(&[&base[..], &["--trigger", "model error", "--write", dir.to_str().unwrap()]].concat());
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let year = std::fs::read_dir(dir.join("entries")).unwrap().next().unwrap().unwrap().file_name();
    let year = year.to_str().unwrap();
    assert!(year.starts_with("AGT-INC-") && year.ends_with("-0001.json"), "{year}");
    let e: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("entries").join(year)).unwrap()).unwrap();
    assert_eq!(e["trigger"], "model error");
    assert_eq!(format!("{}.json", e["id"].as_str().unwrap()), year);

    assert_eq!(incident(&[&base[..], &["--trigger", "aliens"]].concat()).status.code(), Some(2));
    assert_eq!(incident(&["--summary", "s"]).status.code(), Some(2), "missing fields without a terminal is an error");
}
