//! Opt-in deep scanners.
//!
//! Deep scanning is never on by default. Each backend is gated behind a Cargo
//! feature so the default build stays free of ClamAV/YARA/hash dependencies:
//!
//! | Backend | Feature | Input |
//! | ------- | ------- | ----- |
//! | clamd   | `security-clamav` | `--clamd-socket <PATH>` |
//! | YARA    | `security-yara`   | `--rules-dir <DIR>` |
//! | hashes  | `security-hash`   | `--hash-db <FILE>` |
//!
//! When `--deep-scan` is requested with no usable backend, [`DeepScanner::build`]
//! returns [`DeepScanError::NoBackend`] and the CLI explains how to enable one
//! and exits with a documented code. Backends never mutate files; quarantining
//! is a separate, explicit step (see [`crate::quarantine`]).

use std::path::{Path, PathBuf};

use crate::search::FileResult;
use crate::security::Assessment;

/// Exit code used by the CLI when `--deep-scan` has no usable backend.
pub const NO_BACKEND_EXIT_CODE: i32 = 2;

#[cfg(feature = "security-hash")]
use std::collections::HashSet;

/// Inputs that select deep-scan backends.
#[derive(Debug, Clone, Default)]
pub struct DeepScanOptions {
    /// Whether deep scanning was requested at all.
    pub enabled: bool,
    /// Path to a clamd Unix socket.
    pub clamd_socket: Option<PathBuf>,
    /// Directory of YARA rules (`.yar` / `.yara`).
    pub rules_dir: Option<PathBuf>,
    /// File of known-bad SHA-256 hashes, one hex digest per line.
    pub hash_db: Option<PathBuf>,
}

/// Why a deep scanner could not be built.
#[derive(Debug)]
pub enum DeepScanError {
    /// Scanning was requested but no backend is usable.
    NoBackend,
    /// A backend was configured but could not be initialised.
    Backend {
        backend: &'static str,
        message: String,
    },
}

impl std::fmt::Display for DeepScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeepScanError::NoBackend => write!(
                f,
                "deep scan requested but no scanner backend is available; \
                 rebuild with `--features security-clamav`, `--features security-yara`, or \
                 `--features security-hash`, then pass `--clamd-socket`, `--rules-dir`, or `--hash-db`"
            ),
            DeepScanError::Backend { backend, message } => {
                write!(f, "{backend} deep scan unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for DeepScanError {}

/// The outcome of deep-scanning one file.
#[derive(Debug, Clone, Default)]
pub struct DeepScanReport {
    /// Findings, if any.
    pub assessment: Assessment,
    /// Per-file backend errors (I/O, protocol). Never fatal on their own.
    pub errors: Vec<String>,
}

/// An assembled set of deep scanners.
#[derive(Debug, Default)]
pub struct DeepScanner {
    #[cfg(feature = "security-clamav")]
    clamd_socket: Option<PathBuf>,
    #[cfg(feature = "security-yara")]
    yara_rules: Option<yara_x::Rules>,
    #[cfg(feature = "security-hash")]
    known_hashes: Option<HashSet<String>>,
    warnings: Vec<String>,
}

impl DeepScanner {
    /// Assemble the scanners requested by `opts`.
    ///
    /// Disabled options return an empty scanner. Enabled options that cannot be
    /// initialised either warn (non-fatal, e.g. a missing hash DB) or fail
    /// (invalid YARA rules). If nothing usable remains, `NoBackend` is returned.
    pub fn build(opts: &DeepScanOptions) -> Result<Self, DeepScanError> {
        #[cfg_attr(
            not(any(
                feature = "security-clamav",
                feature = "security-yara",
                feature = "security-hash"
            )),
            allow(unused_mut)
        )]
        let mut scanner = DeepScanner {
            #[cfg(feature = "security-clamav")]
            clamd_socket: None,
            #[cfg(feature = "security-yara")]
            yara_rules: None,
            #[cfg(feature = "security-hash")]
            known_hashes: None,
            warnings: Vec::new(),
        };

        if !opts.enabled {
            return Ok(scanner);
        }

        #[cfg(feature = "security-clamav")]
        if let Some(socket) = &opts.clamd_socket {
            if socket.exists() {
                scanner.clamd_socket = Some(socket.clone());
            } else {
                scanner.warnings.push(format!(
                    "clamd socket {} does not exist; clamav backend disabled",
                    socket.display()
                ));
            }
        }

        #[cfg(feature = "security-yara")]
        if let Some(dir) = &opts.rules_dir {
            match load_yara_rules(dir) {
                Ok(rules) => scanner.yara_rules = Some(rules),
                Err(message) => {
                    return Err(DeepScanError::Backend {
                        backend: "yara",
                        message,
                    })
                }
            }
        }

        #[cfg(feature = "security-hash")]
        if let Some(db) = &opts.hash_db {
            match load_hashes(db) {
                Ok(hashes) => scanner.known_hashes = Some(hashes),
                Err(e) => scanner.warnings.push(format!(
                    "cannot read hash db {}: {e}; hash backend disabled",
                    db.display()
                )),
            }
        }

        if !scanner.has_backend() {
            return Err(DeepScanError::NoBackend);
        }
        Ok(scanner)
    }

    /// Whether any backend is active.
    pub fn has_backend(&self) -> bool {
        #[cfg(feature = "security-clamav")]
        if self.clamd_socket.is_some() {
            return true;
        }
        #[cfg(feature = "security-yara")]
        if self.yara_rules.is_some() {
            return true;
        }
        #[cfg(feature = "security-hash")]
        if self.known_hashes.is_some() {
            return true;
        }
        false
    }

    /// Names of the compiled-in backends, for diagnostics.
    pub fn backend_names(&self) -> Vec<&'static str> {
        #[cfg_attr(
            not(any(
                feature = "security-clamav",
                feature = "security-yara",
                feature = "security-hash"
            )),
            allow(unused_mut)
        )]
        let mut names = Vec::new();
        #[cfg(feature = "security-clamav")]
        if self.clamd_socket.is_some() {
            names.push("clamav");
        }
        #[cfg(feature = "security-yara")]
        if self.yara_rules.is_some() {
            names.push("yara");
        }
        #[cfg(feature = "security-hash")]
        if self.known_hashes.is_some() {
            names.push("hash");
        }
        names
    }

    /// Non-fatal problems encountered while assembling the scanners.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Scan a single file with every active backend.
    pub fn scan(&self, path: &Path) -> DeepScanReport {
        let mut report = DeepScanReport::default();
        self.scan_into(path, &mut report);
        report
    }

    #[cfg_attr(
        not(any(
            feature = "security-clamav",
            feature = "security-yara",
            feature = "security-hash"
        )),
        allow(unused_variables)
    )]
    fn scan_into(&self, path: &Path, report: &mut DeepScanReport) {
        #[cfg(feature = "security-clamav")]
        if let Some(socket) = &self.clamd_socket {
            match clamd_scan(socket, path) {
                Ok(ClamdOutcome::Clean) => {}
                Ok(ClamdOutcome::Found(signature)) => report.assessment.raise(
                    crate::security::Verdict::HighRisk,
                    "clamav",
                    format!("clamd detected '{signature}'"),
                ),
                Err(e) => report.errors.push(format!("clamav: {e}")),
            }
        }

        #[cfg(feature = "security-yara")]
        if let Some(rules) = &self.yara_rules {
            match yara_scan(rules, path, crate::security::DEFAULT_SAMPLE_LIMIT) {
                Ok(matches) if !matches.is_empty() => report.assessment.raise(
                    crate::security::Verdict::HighRisk,
                    "yara",
                    format!("YARA rules matched: {}", matches.join(", ")),
                ),
                Ok(_) => {}
                Err(e) => report.errors.push(format!("yara: {e}")),
            }
        }

        #[cfg(feature = "security-hash")]
        if let Some(hashes) = &self.known_hashes {
            match sha256_file(path) {
                Ok(digest) if hashes.contains(&digest) => report.assessment.raise(
                    crate::security::Verdict::HighRisk,
                    "known-bad-hash",
                    format!("SHA-256 {digest} is in the known-bad hash db"),
                ),
                Ok(_) => {}
                Err(e) => report.errors.push(format!("hash: {e}")),
            }
        }
    }
}

/// Run every active deep scanner over `results`, merging findings in place.
///
/// Returns any per-file backend errors collected along the way.
pub fn apply(results: &mut [FileResult], scanner: &DeepScanner) -> Vec<String> {
    let mut errors = Vec::new();
    for result in results.iter_mut() {
        let report = scanner.scan(&result.path);
        result.security.merge(report.assessment);
        errors.extend(report.errors);
    }
    errors
}

// --- ClamAV (clamd socket) -------------------------------------------------

#[cfg(feature = "security-clamav")]
enum ClamdOutcome {
    Clean,
    Found(String),
}

#[cfg(all(feature = "security-clamav", unix))]
fn clamd_scan(socket: &Path, path: &Path) -> Result<ClamdOutcome, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket)
        .map_err(|e| format!("cannot connect to clamd socket {}: {e}", socket.display()))?;
    stream
        .write_all(b"zINSTREAM\0")
        .map_err(|e| e.to_string())?;

    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        stream
            .write_all(&(read as u32).to_be_bytes())
            .map_err(|e| e.to_string())?;
        stream.write_all(&buf[..read]).map_err(|e| e.to_string())?;
    }
    stream
        .write_all(&0u32.to_be_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().ok();

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    parse_clamd_response(&response)
}

#[cfg(all(feature = "security-clamav", not(unix)))]
fn clamd_scan(_socket: &Path, _path: &Path) -> Result<ClamdOutcome, String> {
    Err("clamd socket scanning is Unix-only".to_string())
}

#[cfg(all(feature = "security-clamav", unix))]
fn parse_clamd_response(bytes: &[u8]) -> Result<ClamdOutcome, String> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_end_matches('\0').trim();
    if text.is_empty() {
        return Err("empty response from clamd".to_string());
    }
    if let Some(idx) = text.find("FOUND") {
        let signature = text[..idx]
            .trim()
            .trim_start_matches("stream:")
            .trim()
            .trim_end_matches(':')
            .trim();
        return Ok(ClamdOutcome::Found(signature.to_string()));
    }
    if text.ends_with("OK") {
        return Ok(ClamdOutcome::Clean);
    }
    Err(format!("unexpected clamd response: {text}"))
}

// --- YARA ------------------------------------------------------------------

#[cfg(feature = "security-yara")]
fn load_yara_rules(dir: &Path) -> Result<yara_x::Rules, String> {
    let mut compiler = yara_x::Compiler::new();
    let mut count = 0usize;

    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read rules dir {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_rule = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yar") | Some("yara")
        );
        if !is_rule {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read rule {}: {e}", path.display()))?;
        compiler
            .add_source(source.as_str())
            .map_err(|e| format!("invalid YARA rule {}: {e}", path.display()))?;
        count += 1;
    }

    if count == 0 {
        return Err(format!("no .yar/.yara rules found in {}", dir.display()));
    }
    Ok(compiler.build())
}

#[cfg(feature = "security-yara")]
fn yara_scan(rules: &yara_x::Rules, path: &Path, limit: usize) -> Result<Vec<String>, String> {
    let data = read_bounded(path, limit).map_err(|e| e.to_string())?;
    let mut scanner = yara_x::Scanner::new(rules);
    let results = scanner.scan(&data).map_err(|e| e.to_string())?;
    Ok(results
        .matching_rules()
        .map(|rule| rule.identifier().to_string())
        .collect())
}

#[cfg(feature = "security-yara")]
fn read_bounded(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; limit.max(1)];
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

// --- Known-bad hashes ------------------------------------------------------

#[cfg(feature = "security-hash")]
fn load_hashes(path: &Path) -> Result<HashSet<String>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let mut hashes = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        hashes.insert(line.to_ascii_lowercase());
    }
    Ok(hashes)
}

#[cfg(feature = "security-hash")]
fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_options_build_empty_scanner() {
        let opts = DeepScanOptions::default();
        let scanner = DeepScanner::build(&opts).expect("disabled scan should not error");
        assert!(!scanner.has_backend());
        assert!(scanner.backend_names().is_empty());
    }

    #[test]
    fn enabled_without_backend_is_no_backend_error() {
        let opts = DeepScanOptions {
            enabled: true,
            ..Default::default()
        };
        let err = DeepScanner::build(&opts).unwrap_err();
        assert!(matches!(err, DeepScanError::NoBackend));
        let message = err.to_string();
        assert!(message.contains("security-clamav"));
        assert!(message.contains("--rules-dir"));
    }

    #[test]
    fn no_backend_message_matches_documented_exit_code() {
        // The CLI returns NO_BACKEND_EXIT_CODE for this error; keep them in sync.
        assert_eq!(NO_BACKEND_EXIT_CODE, 2);
    }

    #[cfg(feature = "security-hash")]
    #[test]
    fn missing_hash_db_warns_and_has_no_backend() {
        let opts = DeepScanOptions {
            enabled: true,
            hash_db: Some(PathBuf::from("/nonexistent/hashes.txt")),
            ..Default::default()
        };
        let err = DeepScanner::build(&opts).unwrap_err();
        assert!(matches!(err, DeepScanError::NoBackend));
    }

    #[cfg(feature = "security-hash")]
    #[test]
    fn hash_present_in_db_is_high_risk() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let sample = dir.path().join("sample.bin");
        std::fs::write(&sample, b"known bad payload").unwrap();

        let digest = sha256_file(&sample).unwrap();
        let db = dir.path().join("hashes.txt");
        std::fs::write(&db, format!("# comment\n{digest}\n\n")).unwrap();

        let scanner = DeepScanner::build(&DeepScanOptions {
            enabled: true,
            hash_db: Some(db),
            ..Default::default()
        })
        .expect("hash backend should build");

        let report = scanner.scan(&sample);
        assert_eq!(
            report.assessment.verdict,
            crate::security::Verdict::HighRisk
        );
        assert!(report
            .assessment
            .reasons
            .iter()
            .any(|r| r.code == "known-bad-hash"));
    }

    #[cfg(feature = "security-hash")]
    #[test]
    fn hash_absent_leaves_file_clean() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let sample = dir.path().join("innocent.bin");
        std::fs::write(&sample, b"nothing to see").unwrap();

        let db = dir.path().join("hashes.txt");
        std::fs::write(&db, "deadbeef\n").unwrap();

        let scanner = DeepScanner::build(&DeepScanOptions {
            enabled: true,
            hash_db: Some(db),
            ..Default::default()
        })
        .unwrap();

        assert!(scanner.scan(&sample).assessment.is_clean());
    }

    #[cfg(feature = "security-yara")]
    #[test]
    fn yara_rule_matches_fixture_string() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        std::fs::write(
            rules.join("needle.yar"),
            "rule needle_rule {\n  strings:\n    $a = \"guara-yara-needle\"\n  condition:\n    $a\n}\n",
        )
        .unwrap();

        let sample = dir.path().join("sample.txt");
        std::fs::write(&sample, b"text with guara-yara-needle inside").unwrap();

        let scanner = DeepScanner::build(&DeepScanOptions {
            enabled: true,
            rules_dir: Some(rules),
            ..Default::default()
        })
        .expect("yara backend should build");

        let report = scanner.scan(&sample);
        assert_eq!(
            report.assessment.verdict,
            crate::security::Verdict::HighRisk
        );
        assert!(report
            .assessment
            .reasons
            .iter()
            .any(|r| r.code == "yara" && r.message.contains("needle_rule")));
    }

    #[cfg(feature = "security-yara")]
    #[test]
    fn invalid_yara_rule_errors_clearly() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        std::fs::write(
            rules.join("broken.yar"),
            "rule broken { this is not yara }\n",
        )
        .unwrap();

        let err = DeepScanner::build(&DeepScanOptions {
            enabled: true,
            rules_dir: Some(rules),
            ..Default::default()
        })
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("broken.yar"), "message: {message}");
    }

    #[cfg(feature = "security-yara")]
    #[test]
    fn empty_rules_dir_errors() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir(&rules).unwrap();

        let err = DeepScanner::build(&DeepScanOptions {
            enabled: true,
            rules_dir: Some(rules),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("no .yar/.yara"));
    }

    #[cfg(all(feature = "security-clamav", unix))]
    mod clamd {
        use super::*;
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        /// Serve exactly one clamd `INSTREAM` request and reply with `response`.
        fn mock_clamd(response: &'static str) -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::TempDir::new().unwrap();
            let socket = dir.path().join("clamd.ctl");
            let listener = UnixListener::bind(&socket).unwrap();

            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    consume_instream(&mut stream);
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });

            (dir, socket)
        }

        /// Read a `zINSTREAM\0` command line followed by length-prefixed chunks
        /// terminated by a zero-length chunk, mirroring the clamd protocol.
        fn consume_instream(stream: &mut std::os::unix::net::UnixStream) {
            let mut byte = [0u8; 1];
            loop {
                if stream.read_exact(&mut byte).is_err() || byte[0] == 0 {
                    break;
                }
            }
            loop {
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let size = u32::from_be_bytes(len) as usize;
                if size == 0 {
                    return;
                }
                let mut chunk = vec![0u8; size];
                if stream.read_exact(&mut chunk).is_err() {
                    return;
                }
            }
        }

        #[test]
        fn clamd_clean_response_is_clean() {
            let dir = tempfile::TempDir::new().unwrap();
            let sample = dir.path().join("sample.txt");
            std::fs::write(&sample, b"harmless").unwrap();

            let (_sock_dir, socket) = mock_clamd("stream: OK\0");
            let scanner = DeepScanner::build(&DeepScanOptions {
                enabled: true,
                clamd_socket: Some(socket),
                ..Default::default()
            })
            .expect("clamav backend should build");

            let report = scanner.scan(&sample);
            assert!(report.assessment.is_clean(), "{:?}", report.assessment);
        }

        #[test]
        fn clamd_found_response_is_high_risk() {
            let dir = tempfile::TempDir::new().unwrap();
            let sample = dir.path().join("sample.bin");
            std::fs::write(&sample, b"pretend malware").unwrap();

            let (_sock_dir, socket) = mock_clamd("stream: Mock-Test-Signature FOUND\0");
            let scanner = DeepScanner::build(&DeepScanOptions {
                enabled: true,
                clamd_socket: Some(socket),
                ..Default::default()
            })
            .expect("clamav backend should build");

            let report = scanner.scan(&sample);
            assert_eq!(
                report.assessment.verdict,
                crate::security::Verdict::HighRisk
            );
            assert!(report
                .assessment
                .reasons
                .iter()
                .any(|r| r.code == "clamav" && r.message.contains("Mock-Test-Signature")));
        }

        #[test]
        fn missing_clamd_socket_warns_and_has_no_backend() {
            let opts = DeepScanOptions {
                enabled: true,
                clamd_socket: Some(PathBuf::from("/nonexistent/clamd.ctl")),
                ..Default::default()
            };
            let err = DeepScanner::build(&opts).unwrap_err();
            assert!(matches!(err, DeepScanError::NoBackend));
        }
    }
}
