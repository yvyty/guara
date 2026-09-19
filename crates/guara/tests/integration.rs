//! CLI integration tests over the same fixture tree the library tests use
//! so walk, search, and index agree end to end.

#[path = "../../../tests/fixture_tree.rs"]
mod fixture_tree;

use assert_cmd::Command;
use predicates::prelude::*;

use fixture_tree::{build, NEEDLE};

#[test]
fn cli_search_finds_the_needle_and_skips_ignored_files() {
    let fixture = build();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args([NEEDLE, fixture.root.to_str().unwrap(), "-q"])
        .assert()
        .success()
        .stdout(predicate::str::contains("top.txt"))
        .stdout(predicate::str::contains("docs/readme.md"))
        .stdout(predicate::str::contains("main.rs"))
        .stdout(predicate::str::contains("ignored/skip.txt").not())
        .stdout(predicate::str::contains("lib.rs").not());
}

#[test]
fn cli_index_then_search_uses_the_shared_fixture_tree() {
    let fixture = build();
    let db = fixture.tempdir().join("cli-index.db");
    let db_arg = db.to_str().unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", fixture.root.to_str().unwrap(), "--db", db_arg])
        .assert()
        .success()
        .stderr(predicate::str::contains("8 added"));

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", "status", "--db", db_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("path count: 8"))
        .stdout(predicate::str::contains("root:"));

    // Index-backed search prints the same relative paths a live walk would.
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args([NEEDLE, fixture.root.to_str().unwrap(), "--db", db_arg, "-q"])
        .assert()
        .success()
        .stdout(predicate::str::contains("top.txt"))
        .stdout(predicate::str::contains("docs/readme.md"))
        .stderr(predicate::str::contains("ignored/skip.txt").not());
}

#[test]
fn cli_tui_fallbacks_to_the_same_results() {
    let fixture = build();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["tui", NEEDLE, fixture.root.to_str().unwrap(), "-q"])
        .assert()
        .success()
        .stdout(predicate::str::contains("top.txt"))
        .stderr(predicate::str::contains("ignored/skip.txt").not());
}

#[test]
fn cli_json_output_is_clean_for_the_fixture_tree() {
    let fixture = build();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    let output = cmd
        .args([NEEDLE, fixture.root.to_str().unwrap(), "--json", "-q"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).unwrap();
    let mut hits = 0;
    for line in text.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("ndjson line");
        assert!(value.get("path").is_some(), "missing path in {line}");
        hits += 1;
    }
    assert_eq!(hits, 3, "expected three needle hits, got {hits}: {text}");
}
