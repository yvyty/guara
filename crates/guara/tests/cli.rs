use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_succeeds() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("search"));
}

#[test]
fn version_succeeds() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("guara"))
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn search_help_succeeds() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Search for files"));
}

#[test]
fn unknown_flag_fails() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["--badflag"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn default_command_searches_current_dir() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    // No subcommand: defaults to `search` in the current directory.
    cmd.assert().success();
}

#[test]
fn default_command_accepts_pattern_without_subcommand() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("needle.txt"), "haystack needle here\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["needle", dir.path().to_str().unwrap(), "-q"])
        .assert()
        .success()
        .stdout(predicate::str::contains("needle.txt"));
}

#[test]
fn explicit_search_subcommand_matches_default() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("needle.txt"), "haystack needle here\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "needle", dir.path().to_str().unwrap(), "-q"])
        .assert()
        .success()
        .stdout(predicate::str::contains("needle.txt"));
}

#[test]
fn library_version_matches() {
    assert_eq!(guara_core::version(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn json_output_is_valid_ndjson() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "--json", "-q", "src"])
        .assert()
        .success()
        .stdout(predicate::str::contains("path"));

    // Each line of stdout should be valid JSON
    let output = cmd.assert().get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    for line in text.lines() {
        if !line.is_empty() {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("each output line should be valid JSON");
        }
    }
}

#[test]
fn quiet_hides_stats_on_stderr() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    let output = cmd
        .args(["search", "-q", "src"])
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("scanned"),
        "stats should not appear on stderr with --quiet"
    );
}

#[test]
fn stats_appear_on_stderr_without_quiet() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    let output = cmd
        .args(["search", "src"])
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("scanned"),
        "stats should appear on stderr without --quiet"
    );
}

#[test]
fn exit_code_1_when_no_hits() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello world\n").unwrap();
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args([
        "search",
        "ZZZNoSuchPatternXYZ123",
        dir.path().to_str().unwrap(),
    ])
    .assert()
    .failure()
    .code(predicate::eq(1));
}

#[test]
fn exit_code_0_when_hits_found() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "src"])
        .assert()
        .success()
        .code(predicate::eq(0));
}

#[test]
fn exit_code_2_on_config_error() {
    // --max-count with non-numeric value triggers a usage error
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "--max-count", "abc", "src"])
        .assert()
        .failure()
        .code(predicate::eq(2));
}

#[test]
fn exit_code_2_on_invalid_regex() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "-e", "[unterminated", "src"])
        .assert()
        .failure()
        .code(predicate::eq(2))
        .stderr(predicate::str::contains("invalid pattern"));
}

#[test]
fn filtered_binary_does_not_trigger_exit_3() {
    // A directory containing a binary file plus a matching text file. The
    // binary is skipped by policy, which must NOT be treated as an error.
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("hit.txt"), "needle\n").unwrap();
    std::fs::write(dir.path().join("blob.bin"), [0x00u8, 0x01, 0x00, 0xFF]).unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "needle", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .code(predicate::eq(0));
}

#[test]
fn security_summary_counts_suspicious_hit() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("note.txt"), "needle here\n").unwrap();
    std::fs::write(dir.path().join("invoice.pdf.exe"), "needle here\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    let output = cmd
        .args(["search", "needle", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("1 suspicious"),
        "expected one suspicious verdict on stderr, got: {stderr}"
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("security: Suspicious"),
        "expected a human security suffix, got: {stdout}"
    );
}

#[test]
fn security_summary_hidden_with_quiet() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("invoice.pdf.exe"), "needle here\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    let output = cmd
        .args(["search", "needle", dir.path().to_str().unwrap(), "-q"])
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("security:"),
        "security summary should not appear with --quiet, got: {stderr}"
    );
}

#[test]
fn json_output_includes_verdict_and_reasons() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("invoice.pdf.exe"), "needle here\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    let output = cmd
        .args([
            "search",
            "--json",
            "-q",
            "needle",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .clone();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout.lines().next().expect("one JSON line");
    let value: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
    assert_eq!(
        value.get("verdict").and_then(|v| v.as_str()),
        Some("suspicious")
    );
    assert!(value
        .get("reasons")
        .and_then(|v| v.as_array())
        .is_some_and(|r| !r.is_empty()));
}

#[test]
fn deep_scan_without_a_backend_exits_2() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("note.txt"), "needle here\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args([
        "search",
        "needle",
        dir.path().to_str().unwrap(),
        "--deep-scan",
    ])
    .assert()
    .failure()
    .code(predicate::eq(2))
    .stderr(predicate::str::contains("no scanner backend"));
}

#[test]
fn quarantine_without_destination_is_a_usage_error() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "needle", "--quarantine"])
        .assert()
        .failure()
        .code(predicate::eq(2));
}

#[test]
fn default_search_leaves_files_in_place() {
    let dir = tempfile::TempDir::new().unwrap();
    let flagged = dir.path().join("invoice.pdf.exe");
    std::fs::write(&flagged, "needle here\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "needle", dir.path().to_str().unwrap()])
        .assert()
        .success();

    assert!(flagged.exists(), "default search must not move files");
}

#[test]
fn quarantine_moves_flagged_file_and_writes_manifest() {
    let dir = tempfile::TempDir::new().unwrap();
    let flagged = dir.path().join("invoice.pdf.exe");
    std::fs::write(&flagged, "needle here\n").unwrap();
    let vault = dir.path().join("vault");

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args([
        "search",
        "needle",
        dir.path().to_str().unwrap(),
        "--quarantine",
        "--quarantine-dir",
        vault.to_str().unwrap(),
    ])
    .assert()
    .success();

    assert!(!flagged.exists(), "flagged file should have been moved");
    let manifest = vault.join("quarantine-manifest.tsv");
    assert!(manifest.exists(), "manifest should exist");
    let contents = std::fs::read_to_string(manifest).unwrap();
    assert!(contents.contains("invoice.pdf.exe"));
    assert!(vault.read_dir().unwrap().count() >= 2);
}

/// Index commands run against a temporary database, never the user's own
fn tree_with_two_files() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("needle.txt"), "haystack needle here\n").unwrap();
    std::fs::write(dir.path().join("other.txt"), "nothing to see\n").unwrap();
    let db = dir.path().join("index.db");
    (dir, db)
}

#[test]
fn help_lists_index_watch_commands() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("index"))
        .stdout(predicate::str::contains("reindex"))
        .stdout(predicate::str::contains("history"))
        .stdout(predicate::str::contains("serve"));
}

#[test]
fn serve_help_documents_watch_terms() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--watch-term"))
        .stdout(predicate::str::contains("--debounce"));
}

#[test]
fn index_builds_skips_unchanged_and_reports_status() {
    let (dir, db) = tree_with_two_files();
    let root = dir.path().to_str().unwrap();
    let db_arg = db.to_str().unwrap();

    // First pass writes both files. The database lives inside the tree and must
    // not index itself.
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", root, "--db", db_arg])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 added"))
        .stderr(predicate::str::contains("2 file(s) scanned"));

    // Second pass of an unchanged tree writes nothing.
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", root, "--db", db_arg])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 added"))
        .stderr(predicate::str::contains("2 unchanged (skipped)"));

    // Status prints path count, DB path, and last updated.
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", "status", "--db", db_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("path count: 2"))
        .stdout(predicate::str::contains(format!("db: {}", db.display())))
        .stdout(predicate::str::contains("last updated: 20"));
}

#[test]
fn reindex_rebuilds_from_scratch() {
    let (dir, db) = tree_with_two_files();
    let root = dir.path().to_str().unwrap();
    let db_arg = db.to_str().unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["reindex", root, "--db", db_arg])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 added"));

    // Unlike `index`, a second `reindex` still writes every row.
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["reindex", root, "--db", db_arg])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 added"))
        .stderr(predicate::str::contains("0 unchanged"));
}

#[test]
fn index_status_without_a_database_does_not_create_one() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = dir.path().join("absent.db");

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", "status", "--db", db.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("path count: 0"))
        .stdout(predicate::str::contains("last updated: never"));

    assert!(!db.exists(), "status must not create a database");
}

#[test]
fn search_uses_the_index_and_skips_untracked_files() {
    let (dir, db) = tree_with_two_files();
    let root = dir.path().to_str().unwrap();
    let db_arg = db.to_str().unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", root, "--db", db_arg, "-q"])
        .assert()
        .success();

    // Written after indexing: a walk would find it, the index cannot.
    std::fs::write(dir.path().join("later-needle.txt"), "needle later\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    let output = cmd
        .args(["search", "needle", root, "--db", db_arg])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("needle.txt"), "stdout: {stdout}");
    assert!(
        !stdout.contains("later-needle.txt"),
        "indexed search must not walk: {stdout}"
    );
    assert!(stderr.contains("(index:"), "stderr: {stderr}");
}

#[test]
fn search_without_an_index_walks_live_with_the_same_hits() {
    let (dir, db) = tree_with_two_files();
    let root = dir.path().to_str().unwrap();
    let db_arg = db.to_str().unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", root, "--db", db_arg, "-q"])
        .assert()
        .success();
    std::fs::write(dir.path().join("later-needle.txt"), "needle later\n").unwrap();

    // --no-index forces a walk, which sees the file created after indexing.
    let mut cmd = Command::cargo_bin("guara").unwrap();
    let output = cmd
        .args(["search", "needle", root, "--no-index", "--db", db_arg, "-q"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("needle.txt"), "stdout: {stdout}");
    assert!(stdout.contains("later-needle.txt"), "stdout: {stdout}");

    // An index whose roots do not cover the request is ignored too.
    let other = tempfile::TempDir::new().unwrap();
    std::fs::write(other.path().join("needle.txt"), "needle\n").unwrap();
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args([
        "search",
        "needle",
        other.path().to_str().unwrap(),
        "--db",
        db_arg,
        "-q",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("needle.txt"));
}

#[test]
fn history_records_indexed_searches_only() {
    let (dir, db) = tree_with_two_files();
    let root = dir.path().to_str().unwrap();
    let db_arg = db.to_str().unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["index", root, "--db", db_arg, "-q"])
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "needle", root, "--db", db_arg, "-q"])
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["history", "--db", db_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("needle"));

    // A walk-only search is not recorded.
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["search", "other", root, "--no-index", "--db", db_arg, "-q"])
        .assert()
        .success();
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["history", "--db", db_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("other").not());
}

#[test]
fn history_without_a_database_reports_nothing_to_show() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = dir.path().join("absent.db");

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["history", "--db", db.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("no index yet"));

    assert!(!db.exists(), "history must not create a database");
}

#[test]
fn tui_help_succeeds() {
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["tui", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Browse results"));
}

#[test]
fn tui_without_a_terminal_prints_results() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("needle.txt"), "haystack needle here\n").unwrap();

    // The test harness pipes stdout, so the browser falls back to plain output.
    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["tui", "needle", dir.path().to_str().unwrap(), "-q"])
        .assert()
        .success()
        .stdout(predicate::str::contains("needle.txt"));

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["tui", "needle", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("not a terminal"));
}

#[test]
fn tui_with_no_hits_exits_one() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("plain.txt"), "nothing to see\n").unwrap();

    let mut cmd = Command::cargo_bin("guara").unwrap();
    cmd.args(["tui", "zzz-not-present", dir.path().to_str().unwrap(), "-q"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no hits to browse"));
}

#[cfg(unix)]
#[test]
fn serve_exposes_the_ipc_protocol_on_a_socket() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("guara.sock");
    let db = dir.path().join("index.db");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("needle.txt"), "a needle lives here\n").unwrap();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_guara"))
        .args([
            "serve",
            "--no-initial-index",
            &format!("--socket={}", socket.display()),
            "--db",
            db.to_str().unwrap(),
            root.to_str().unwrap(),
            "-q",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let mut ready = false;
    for _ in 0..300 {
        if socket.exists() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let outcome = if !ready {
        Err("the daemon never created the IPC socket".to_string())
    } else {
        probe_socket(&socket)
    };

    let _ = child.kill();
    let _ = child.wait();
    outcome.unwrap();
}

#[cfg(unix)]
fn probe_socket(socket: &std::path::Path) -> Result<(), String> {
    use guara_core::ipc::{request, Request, Response, PROTOCOL_VERSION};

    match request(socket, &Request::Hello { version: 1 }).map_err(|e| e.to_string())? {
        Response::Hello { version, .. } => assert_eq!(version, PROTOCOL_VERSION),
        other => return Err(format!("unexpected hello response: {other:?}")),
    }

    let search = Request::Search {
        query: "needle".to_string(),
        root: None,
        limit: None,
    };
    match request(socket, &search).map_err(|e| e.to_string())? {
        Response::Hits { hits, .. } => {
            assert!(
                hits.iter().any(|hit| hit.path.ends_with("needle.txt")),
                "unexpected hits: {hits:?}"
            );
        }
        other => return Err(format!("unexpected search response: {other:?}")),
    }

    match request(socket, &Request::Status).map_err(|e| e.to_string())? {
        Response::Status(report) => {
            assert!(report.watching, "the daemon should report watching");
            assert!(report.index_path.is_some(), "status should name the index");
        }
        other => return Err(format!("unexpected status response: {other:?}")),
    }

    Ok(())
}
