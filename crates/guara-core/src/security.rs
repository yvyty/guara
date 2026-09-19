//! Always-on, lightweight security heuristics.
//!
//! These checks are *signals*, not antivirus. They look at cheap, local
//! properties of a file and produce a [`Verdict`] plus a list of [`Reason`]s:
//!
//! - Shannon entropy of a bounded sample (packed/compressed/encrypted-like)
//! - Unix permission oddities (setuid/setgid, world-writable executables)
//! - Suspicious file names (double extensions such as `invoice.pdf.exe`,
//!   plus a user-configurable pattern list)
//! - PE/ELF magic and header sanity (truncated or corrupt headers)
//!
//! Every check is report-only: nothing here opens for write, moves, or deletes
//! a file. See `README.md` for the false-positive expectations.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::search::FileMetadata;

/// Maximum number of bytes read into memory for entropy and header checks.
///
/// Multi-gigabyte files are sampled, never read whole, by default.
pub const DEFAULT_SAMPLE_LIMIT: usize = 1024 * 1024;

/// Shannon entropy (bits per byte) at or above which a sample is considered
/// packed, compressed, or encrypted-like. Documented false positives include
/// archives, installers, and media containers.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 7.2;

/// Samples smaller than this are ignored for the entropy rule: a handful of
/// bytes can show high entropy without meaning anything.
pub const MIN_ENTROPY_SAMPLE: usize = 256;

/// File extensions that normally launch code. Used by the double-extension
/// rule and overridable through config.
pub const DEFAULT_EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "ps1", "psm1", "jar",
    "msi", "hta", "lnk", "dll", "wsf", "reg",
];

/// Severity of a finding.
///
/// Ordering is meaningful: `Clean < Suspicious < HighRisk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// No rule fired.
    #[default]
    Clean,
    /// At least one heuristic rule fired; worth a second look.
    Suspicious,
    /// A high-confidence signal (reserved, e.g. known-bad hash lists).
    HighRisk,
}

impl Verdict {
    /// Human-readable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "Clean",
            Verdict::Suspicious => "Suspicious",
            Verdict::HighRisk => "High Risk",
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single reason a verdict was raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    /// Stable machine-readable rule id (e.g. `double-extension`).
    pub code: String,
    /// Short human-readable explanation.
    pub message: String,
}

/// The result of running the heuristics against one file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    /// Highest severity any rule produced.
    pub verdict: Verdict,
    /// All explanations, in the order the rules ran.
    pub reasons: Vec<Reason>,
}

impl Assessment {
    /// A clean assessment with no reasons.
    pub fn clean() -> Self {
        Self::default()
    }

    /// The file produced no suspicious signal.
    pub fn is_clean(&self) -> bool {
        self.verdict == Verdict::Clean
    }

    /// Record a finding, keeping the highest severity seen so far.
    pub fn raise(&mut self, severity: Verdict, code: &str, message: impl Into<String>) {
        if severity > self.verdict {
            self.verdict = severity;
        }
        self.reasons.push(Reason {
            code: code.to_string(),
            message: message.into(),
        });
    }

    /// Merge another assessment into this one: take the higher verdict and
    /// append its reasons.
    pub fn merge(&mut self, other: Assessment) {
        if other.verdict > self.verdict {
            self.verdict = other.verdict;
        }
        self.reasons.extend(other.reasons);
    }
}

/// Tunable heuristics, loadable from the `[security]` config section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HeuristicConfig {
    /// Run the heuristics at all. Default: `true`.
    pub enabled: bool,
    /// Entropy threshold in bits per byte.
    pub entropy_threshold: f64,
    /// Bytes read into memory per file for entropy and header checks.
    pub sample_limit: usize,
    /// Extensions treated as executable for the double-extension rule.
    pub executable_extensions: Vec<String>,
    /// Extra case-insensitive substrings matched against the full path.
    /// Empty by default; this is the documented, user-editable blocklist.
    pub suspicious_patterns: Vec<String>,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            sample_limit: DEFAULT_SAMPLE_LIMIT,
            executable_extensions: DEFAULT_EXECUTABLE_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            suspicious_patterns: Vec::new(),
        }
    }
}

/// Shannon entropy of `data` in bits per byte. Empty input returns `0.0`.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Assess a file, gathering size and permissions itself.
pub fn assess_file(path: &Path, cfg: &HeuristicConfig) -> Assessment {
    let metadata = FileMetadata {
        size: std::fs::metadata(path).ok().map(|m| m.len()),
        modified: None,
        permissions: permissions_of(path),
    };
    assess(path, &metadata, cfg)
}

/// Assess a file given already-collected metadata.
pub fn assess(path: &Path, metadata: &FileMetadata, cfg: &HeuristicConfig) -> Assessment {
    let mut assessment = Assessment::clean();
    if !cfg.enabled {
        return assessment;
    }

    check_patterns(path, cfg, &mut assessment);
    check_permissions(metadata, cfg, &mut assessment);

    if let Some((sample, complete)) = read_sample(path, cfg.sample_limit) {
        check_header(&sample, complete, &mut assessment);
        check_entropy(&sample, cfg, &mut assessment);
    }

    assessment
}

fn read_sample(path: &Path, limit: usize) -> Option<(Vec<u8>, bool)> {
    use std::io::Read;

    let size = std::fs::metadata(path).ok().map(|m| m.len());
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; limit.max(1)];
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    buf.truncate(filled);
    let complete = size.is_some_and(|s| filled as u64 >= s);
    Some((buf, complete))
}

fn check_entropy(sample: &[u8], cfg: &HeuristicConfig, assessment: &mut Assessment) {
    if sample.len() < MIN_ENTROPY_SAMPLE {
        return;
    }
    let entropy = shannon_entropy(sample);
    if entropy >= cfg.entropy_threshold {
        assessment.raise(
            Verdict::Suspicious,
            "high-entropy",
            format!(
                "entropy {:.2} bits/byte meets or exceeds the {:.2} threshold",
                entropy, cfg.entropy_threshold
            ),
        );
    }
}

fn check_patterns(path: &Path, cfg: &HeuristicConfig, assessment: &mut Assessment) {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Double extension: `invoice.pdf.exe`. At least two dots, and the final
    // extension is executable-like.
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() >= 3 {
        let last = parts[parts.len() - 1];
        if cfg.executable_extensions.iter().any(|e| e == last) {
            assessment.raise(
                Verdict::Suspicious,
                "double-extension",
                format!("executable extension '.{last}' follows another extension"),
            );
        }
    }

    let full_path = path.to_string_lossy().to_lowercase();
    for pattern in &cfg.suspicious_patterns {
        if pattern.is_empty() {
            continue;
        }
        if full_path.contains(&pattern.to_lowercase()) {
            assessment.raise(
                Verdict::Suspicious,
                "suspicious-pattern",
                format!("path matches configured pattern '{pattern}'"),
            );
        }
    }
}

#[cfg(unix)]
fn check_permissions(metadata: &FileMetadata, cfg: &HeuristicConfig, assessment: &mut Assessment) {
    let Some(mode) = metadata.permissions else {
        return;
    };
    let executable = mode & 0o111 != 0;

    if mode & 0o4000 != 0 {
        assessment.raise(
            Verdict::Suspicious,
            "setuid",
            "setuid bit is set".to_string(),
        );
    }
    if mode & 0o2000 != 0 {
        assessment.raise(
            Verdict::Suspicious,
            "setgid",
            "setgid bit is set".to_string(),
        );
    }
    if executable && mode & 0o002 != 0 && cfg.enabled {
        assessment.raise(
            Verdict::Suspicious,
            "world-writable-executable",
            "executable is world-writable".to_string(),
        );
    }
}

/// Permission checks are a documented no-op on non-Unix platforms: Windows has
/// no setuid/world-writable mode bits, so no verdict is raised.
#[cfg(not(unix))]
fn check_permissions(
    _metadata: &FileMetadata,
    _cfg: &HeuristicConfig,
    _assessment: &mut Assessment,
) {
}

#[cfg(unix)]
fn permissions_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.mode())
}

#[cfg(not(unix))]
fn permissions_of(_path: &Path) -> Option<u32> {
    None
}

/// Minimum ELF header length that can be validated: `e_ident` (16 bytes) plus
/// enough of the fixed header to be meaningful.
const ELF_MIN_VALIDATED: usize = 16;

/// Offset of `e_lfanew` in a PE/MZ header.
const PE_LFANEW_OFFSET: usize = 0x3c;
/// Length of the DOS header that must be present to read `e_lfanew`.
const PE_DOS_HEADER: usize = 0x40;

fn check_header(sample: &[u8], complete: bool, assessment: &mut Assessment) {
    if sample.starts_with(b"\x7fELF") {
        check_elf(sample, complete, assessment);
    } else if sample.starts_with(b"MZ") {
        check_pe(sample, complete, assessment);
    }
}

fn check_elf(sample: &[u8], complete: bool, assessment: &mut Assessment) {
    if sample.len() < ELF_MIN_VALIDATED {
        if complete {
            assessment.raise(
                Verdict::Suspicious,
                "elf-truncated",
                format!(
                    "ELF header is {} bytes; at least {} required",
                    sample.len(),
                    ELF_MIN_VALIDATED
                ),
            );
        }
        return;
    }

    let min_header = match sample[4] {
        1 => 52,
        2 => 64,
        other => {
            assessment.raise(
                Verdict::Suspicious,
                "elf-class",
                format!("unknown ELF class byte {other}"),
            );
            return;
        }
    };

    if sample.len() < min_header && complete {
        assessment.raise(
            Verdict::Suspicious,
            "elf-truncated",
            format!(
                "ELF header is {} bytes; {} required for this class",
                sample.len(),
                min_header
            ),
        );
    }
}

fn check_pe(sample: &[u8], complete: bool, assessment: &mut Assessment) {
    if sample.len() < PE_DOS_HEADER {
        if complete {
            assessment.raise(
                Verdict::Suspicious,
                "pe-truncated",
                format!(
                    "PE DOS header is {} bytes; {} required",
                    sample.len(),
                    PE_DOS_HEADER
                ),
            );
        }
        return;
    }

    let e_lfanew = u32::from_le_bytes([
        sample[PE_LFANEW_OFFSET],
        sample[PE_LFANEW_OFFSET + 1],
        sample[PE_LFANEW_OFFSET + 2],
        sample[PE_LFANEW_OFFSET + 3],
    ]) as usize;

    let Some(sig_end) = e_lfanew.checked_add(4) else {
        assessment.raise(
            Verdict::Suspicious,
            "pe-corrupt",
            "PE header offset overflows".to_string(),
        );
        return;
    };

    if e_lfanew < PE_DOS_HEADER {
        assessment.raise(
            Verdict::Suspicious,
            "pe-corrupt",
            format!("PE header offset {e_lfanew} points into the DOS header"),
        );
        return;
    }

    if sig_end > sample.len() {
        if complete {
            assessment.raise(
                Verdict::Suspicious,
                "pe-truncated",
                format!("PE header offset {e_lfanew} is past the end of the file"),
            );
        }
        return;
    }

    if &sample[e_lfanew..sig_end] != b"PE\0\0" {
        assessment.raise(
            Verdict::Suspicious,
            "pe-corrupt",
            "missing PE\\0\\0 signature".to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    /// Uniform bytes across the whole 0..=255 range approach 8 bits/byte.
    fn high_entropy_sample(len: usize) -> Vec<u8> {
        (0..=255u8).cycle().take(len).collect()
    }

    fn elf64_header() -> Vec<u8> {
        let mut header = vec![0u8; 64];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2; // 64-bit
        header[5] = 1; // little-endian
        header[6] = 1; // version
        header
    }

    fn pe_header() -> Vec<u8> {
        let mut header = vec![0u8; 64];
        header[..2].copy_from_slice(b"MZ");
        header[PE_LFANEW_OFFSET..PE_LFANEW_OFFSET + 4]
            .copy_from_slice(&(PE_DOS_HEADER as u32).to_le_bytes());
        header.extend_from_slice(b"PE\0\0");
        header
    }

    #[test]
    fn entropy_of_random_like_bytes_is_high() {
        let entropy = shannon_entropy(&high_entropy_sample(4096));
        assert!(
            entropy >= DEFAULT_ENTROPY_THRESHOLD,
            "expected high entropy, got {entropy}"
        );
    }

    #[test]
    fn entropy_of_text_is_low() {
        let text = b"the quick brown fox jumps over the lazy dog ".repeat(64);
        let entropy = shannon_entropy(&text);
        assert!(entropy < DEFAULT_ENTROPY_THRESHOLD, "got {entropy}");
    }

    #[test]
    fn empty_and_tiny_files_do_not_panic() {
        let dir = TempDir::new().unwrap();
        let empty = write(&dir, "empty", b"");
        let tiny = write(&dir, "tiny.txt", b"hi");

        let cfg = HeuristicConfig::default();
        assert!(assess_file(&empty, &cfg).is_clean());
        assert!(assess_file(&tiny, &cfg).is_clean());
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn packed_like_file_is_suspicious() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "packed.bin", &high_entropy_sample(4096));

        let assessment = assess_file(&path, &HeuristicConfig::default());
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert!(assessment.reasons.iter().any(|r| r.code == "high-entropy"));
    }

    #[test]
    fn duplicate_extension_is_suspicious() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "invoice.pdf.exe", b"plain text\n");

        let assessment = assess_file(&path, &HeuristicConfig::default());
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert!(assessment
            .reasons
            .iter()
            .any(|r| r.code == "double-extension"));
    }

    #[test]
    fn plain_single_extension_is_clean() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "invoice.pdf", b"plain text\n");
        assert!(assess_file(&path, &HeuristicConfig::default()).is_clean());
    }

    #[test]
    fn configured_pattern_raises_verdict() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "badname.txt", b"plain text\n");

        let cfg = HeuristicConfig {
            suspicious_patterns: vec!["badname".to_string()],
            ..Default::default()
        };
        let assessment = assess_file(&path, &cfg);
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert!(assessment
            .reasons
            .iter()
            .any(|r| r.code == "suspicious-pattern"));
    }

    #[test]
    fn valid_tiny_elf_is_clean() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "tiny.elf", &elf64_header());
        assert!(assess_file(&path, &HeuristicConfig::default()).is_clean());
    }

    #[test]
    fn truncated_elf_is_suspicious_with_explanation() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "cut.elf", b"\x7fELF\x02");

        let assessment = assess_file(&path, &HeuristicConfig::default());
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        let reason = assessment
            .reasons
            .iter()
            .find(|r| r.code == "elf-truncated")
            .expect("elf-truncated reason");
        assert!(reason.message.contains("ELF"));
    }

    #[test]
    fn valid_tiny_pe_is_clean() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "tiny.exe", &pe_header());
        assert!(assess_file(&path, &HeuristicConfig::default()).is_clean());
    }

    #[test]
    fn truncated_pe_is_suspicious() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "cut.exe", b"MZ\x00\x00");

        let assessment = assess_file(&path, &HeuristicConfig::default());
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert!(assessment.reasons.iter().any(|r| r.code == "pe-truncated"));
    }

    #[test]
    fn corrupt_pe_signature_is_suspicious() {
        let dir = TempDir::new().unwrap();
        let mut header = vec![0u8; 64];
        header[..2].copy_from_slice(b"MZ");
        header[PE_LFANEW_OFFSET..PE_LFANEW_OFFSET + 4]
            .copy_from_slice(&(PE_DOS_HEADER as u32).to_le_bytes());
        header.extend_from_slice(b"XX\0\0");
        let path = write(&dir, "corrupt.exe", &header);

        let assessment = assess_file(&path, &HeuristicConfig::default());
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert!(assessment.reasons.iter().any(|r| r.code == "pe-corrupt"));
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_executable_is_suspicious() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = write(&dir, "script.sh", b"echo hi\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();

        let assessment = assess_file(&path, &HeuristicConfig::default());
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert!(assessment
            .reasons
            .iter()
            .any(|r| r.code == "world-writable-executable"));
    }

    #[cfg(unix)]
    #[test]
    fn setuid_binary_is_suspicious() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = write(&dir, "suid.bin", b"plain text content\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();

        let assessment = assess_file(&path, &HeuristicConfig::default());
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert!(assessment.reasons.iter().any(|r| r.code == "setuid"));
    }

    #[test]
    fn disabled_config_yields_clean() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "packed.bin", &high_entropy_sample(4096));

        let cfg = HeuristicConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(assess_file(&path, &cfg).is_clean());
    }
}
