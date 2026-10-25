use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn antidote(args: &[&str]) -> (i32, Vec<Value>) {
    let out = Command::new(env!("CARGO_BIN_EXE_antidote")).args(args).arg("--format=json").output().unwrap();
    let findings = serde_json::from_slice::<Vec<Value>>(&out.stdout)
        .unwrap_or_else(|_| panic!("bad output: {}", String::from_utf8_lossy(&out.stderr)));
    (out.status.code().unwrap(), findings)
}

#[test]
fn entries_match_schema() {
    let schema: Value = serde_json::from_str(&fs::read_to_string(repo().join("schema/entry.schema.json")).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut ids = std::collections::HashSet::new();
    for f in fs::read_dir(repo().join("corpus/entries")).unwrap() {
        let path = f.unwrap().path();
        let entry: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let errors: Vec<String> = validator.iter_errors(&entry).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "{}: {errors:?}", path.display());
        let id = entry["id"].as_str().unwrap();
        assert_eq!(path.file_stem().unwrap(), id, "file name must equal id");
        assert!(ids.insert(id.to_string()), "duplicate id {id}");
    }
}

#[test]
fn every_rule_fires_on_its_sample() {
    // (rule id, fixture file name or None for "any extension")
    let mut rules: Vec<(String, Option<String>)> = Vec::new();
    for f in fs::read_dir(repo().join("corpus/rules")).unwrap() {
        let p = f.unwrap().path();
        let src = fs::read_to_string(&p).unwrap();
        if p.extension().unwrap() == "scm" {
            // AGT-T-0001.js.scm → fixture bad/AGT-T-0001.js
            rules.push((p.file_stem().unwrap().to_str().unwrap().split('.').next().unwrap().into(), Some(p.file_stem().unwrap().to_str().unwrap().into())));
        } else {
            rules.extend(src.lines().filter_map(|l| l.trim().strip_prefix("id = \"")?.strip_suffix('"').map(|id| (id.to_string(), None))));
        }
    }
    assert!(rules.iter().any(|r| r.1.is_some()) && rules.iter().any(|r| r.1.is_none()));
    for (id, file) in rules {
        let sample = fs::read_dir(fixtures().join("bad"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| match &file {
                Some(f) => p.file_name().unwrap() == f.as_str(),
                None => p.file_stem().unwrap() == id.as_str(),
            })
            .unwrap_or_else(|| panic!("no fixture for rule {id} {file:?}"));
        let (_, findings) = antidote(&["scan", sample.to_str().unwrap()]);
        assert!(findings.iter().any(|f| f["id"] == id.as_str()), "{id} did not fire on {}: {findings:?}", sample.display());
    }
}

#[test]
fn known_good_is_clean() {
    let (code, findings) = antidote(&["scan", fixtures().join("good").to_str().unwrap()]);
    assert!(findings.is_empty(), "false positives: {findings:#?}");
    assert_eq!(code, 0);
}

#[test]
fn bad_exits_nonzero() {
    let (code, _) = antidote(&["scan", fixtures().join("bad").to_str().unwrap()]);
    assert_eq!(code, 1);
}

#[test]
fn check_matches_versions_and_ranges() {
    let hit = |r: &str| !antidote(&["check", r]).1.is_empty();
    assert!(hit("npm:postmark-mcp@1.0.16"));
    assert!(hit("npm:mcp-remote@0.1.15"));
    assert!(!hit("npm:mcp-remote@0.1.16"));
    assert!(!hit("npm:mcp-remote"), "unpinned resolves to a fixed latest");
}

fn run(args: &[&str]) -> (i32, Vec<u8>) {
    let out = Command::new(env!("CARGO_BIN_EXE_antidote")).args(args).output().unwrap();
    (out.status.code().unwrap(), out.stdout)
}

#[test]
fn codequality_has_gitlab_fields() {
    let (_, stdout) = run(&["scan", fixtures().join("bad").to_str().unwrap(), "--format=codequality"]);
    let v: Value = serde_json::from_slice(&stdout).unwrap();
    let issues = v.as_array().unwrap();
    assert!(!issues.is_empty());
    let mut fps = std::collections::HashSet::new();
    for i in issues {
        assert!(i["description"].is_string() && i["check_name"].as_str().unwrap().starts_with("AGT-"), "{i}");
        assert!(["info", "minor", "major", "critical", "blocker"].contains(&i["severity"].as_str().unwrap()), "{i}");
        assert!(i["location"]["path"].is_string() && i["location"]["lines"]["begin"].as_u64().unwrap() >= 1, "{i}");
        assert!(fps.insert(i["fingerprint"].as_str().unwrap().to_string()), "duplicate fingerprint {i}");
    }
}

#[test]
fn sarif_is_valid() {
    let (_, stdout) = run(&["scan", fixtures().join("bad").to_str().unwrap(), "--format=sarif"]);
    let sarif: Value = serde_json::from_slice(&stdout).unwrap();
    let schema: Value = serde_json::from_str(include_str!("sarif-2.1.0.schema.json")).unwrap();
    let errors: Vec<String> = jsonschema::validator_for(&schema).unwrap().iter_errors(&sarif).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:#?}");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let (_, findings) = antidote(&["scan", fixtures().join("bad").to_str().unwrap()]);
    assert_eq!(results.len(), findings.len());
    assert!(results.iter().all(|r| r["locations"][0]["physicalLocation"]["region"]["startLine"].is_u64()));
}

#[test]
fn fail_on_threshold() {
    let medium_only = fixtures().join("bad/AGT-R-0102.md");
    let p = medium_only.to_str().unwrap();
    assert_eq!(run(&["scan", p]).0, 0);
    assert_eq!(run(&["scan", p, "--fail-on=medium"]).0, 1);
    assert_eq!(run(&["scan", fixtures().join("bad").to_str().unwrap(), "--fail-on=never"]).0, 0);
}

#[test]
fn feed_build_bundles_corpus() {
    let out = std::env::temp_dir().join(format!("antidote-feed-{}.json", std::process::id()));
    let (code, _) = run(&["feed", "build", repo().join("corpus").to_str().unwrap(), "-o", out.to_str().unwrap(), "--version", "5"]);
    assert_eq!(code, 0);
    let feed: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    fs::remove_file(out).ok();
    assert_eq!(feed["version"], 5);
    assert_eq!(feed["entries"].as_array().unwrap().len(), fs::read_dir(repo().join("corpus/entries")).unwrap().count());
    assert!(feed["rules"]["tool_poisoning"].as_str().unwrap().contains("AGT-R-0001"));
}

#[test]
fn classifier_flags_injection_fixtures() {
    for f in ["AGT-R-0003.md", "AGT-R-0004.json", "AGT-R-0005.json"] {
        let p = fixtures().join("bad").join(f);
        // put the fixture where the scanner treats it as agent-facing text
        let dir = tempfile_dir();
        let target = dir.join("skills").join(if f.ends_with(".md") { "SKILL.md" } else { f });
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(&p, &target).unwrap();
        let (_, findings) = antidote(&["scan", dir.to_str().unwrap()]);
        fs::remove_dir_all(&dir).ok();
        assert!(findings.iter().any(|x| x["id"] == "AGT-C-0001"), "classifier missed {f}: {findings:?}");
    }
    let (_, off) = antidote(&["scan", fixtures().join("bad/AGT-R-0004.json").to_str().unwrap(), "--no-classifier"]);
    assert!(off.iter().all(|x| x["id"] != "AGT-C-0001"));
}

fn tempfile_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("antidote-cls-{}-{:?}", std::process::id(), std::thread::current().id()));
    fs::create_dir_all(&d).unwrap();
    d
}
