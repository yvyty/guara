//! Report-only quarantine.
//!
//! Guará never mutates files during a search. Quarantine happens only when the
//! user passes `--quarantine` **and** a destination directory, and even then it
//! is a **move/rename** into that directory plus a manifest entry. Files are
//! never unlinked in place. If a rename cannot be performed (for example across
//! filesystems), the file is left exactly where it was and an error is reported.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::search::FileResult;
use crate::security::Verdict;

/// Manifest file name written inside the quarantine directory.
pub const MANIFEST_NAME: &str = "quarantine-manifest.tsv";

/// A user-requested quarantine destination.
#[derive(Debug, Clone)]
pub struct QuarantinePolicy {
    dir: PathBuf,
}

impl QuarantinePolicy {
    /// Create a policy that moves flagged files into `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The destination directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The manifest path inside the destination directory.
    pub fn manifest_path(&self) -> PathBuf {
        self.dir.join(MANIFEST_NAME)
    }

    /// Move every non-clean file in `results` into the quarantine directory.
    ///
    /// Clean files are ignored. Files that cannot be moved are reported in
    /// [`QuarantineOutcome::errors`] and left in place.
    pub fn apply(&self, results: &[FileResult]) -> QuarantineOutcome {
        let mut outcome = QuarantineOutcome::default();

        if let Err(e) = fs::create_dir_all(&self.dir) {
            outcome.errors.push((
                self.dir.clone(),
                format!("cannot create quarantine dir: {e}"),
            ));
            return outcome;
        }

        for result in results {
            if result.security.verdict == Verdict::Clean {
                continue;
            }
            let original = &result.path;
            let destination = match unique_destination(&self.dir, original) {
                Ok(dest) => dest,
                Err(e) => {
                    outcome.errors.push((original.clone(), e));
                    continue;
                }
            };

            match fs::rename(original, &destination) {
                Ok(()) => {
                    let entry = QuarantineEntry {
                        original: original.clone(),
                        quarantined: destination,
                        verdict: result.security.verdict,
                        reasons: result
                            .security
                            .reasons
                            .iter()
                            .map(|r| r.code.clone())
                            .collect(),
                    };
                    if let Err(e) = self.append_manifest(&entry) {
                        // The move succeeded; a failed manifest write is an
                        // error worth surfacing but must not undo the move.
                        outcome.errors.push((original.clone(), e));
                    }
                    outcome.moved.push(entry);
                }
                Err(e) => outcome.errors.push((
                    original.clone(),
                    format!("cannot move to {}: {e}", destination.display()),
                )),
            }
        }

        outcome
    }

    fn append_manifest(&self, entry: &QuarantineEntry) -> Result<(), String> {
        let manifest = self.manifest_path();
        let is_new = !manifest.exists();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&manifest)
            .map_err(|e| format!("cannot open manifest {}: {e}", manifest.display()))?;

        if is_new {
            writeln!(
                file,
                "timestamp\toriginal_path\tquarantined_path\tverdict\treasons"
            )
            .map_err(|e| e.to_string())?;
        }

        writeln!(
            file,
            "{}\t{}\t{}\t{}\t{}",
            timestamp(),
            sanitize(&entry.original.to_string_lossy()),
            sanitize(&entry.quarantined.to_string_lossy()),
            entry.verdict.as_str(),
            entry.reasons.join(",")
        )
        .map_err(|e| e.to_string())
    }
}

/// A file that was moved into quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEntry {
    /// Where the file was.
    pub original: PathBuf,
    /// Where the file now lives.
    pub quarantined: PathBuf,
    /// Its verdict at quarantine time.
    pub verdict: Verdict,
    /// Rule codes that contributed to the verdict.
    pub reasons: Vec<String>,
}

/// Outcome of a quarantine pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantineOutcome {
    /// Files successfully moved (and listed in the manifest).
    pub moved: Vec<QuarantineEntry>,
    /// Files that could not be moved, with the reason.
    pub errors: Vec<(PathBuf, String)>,
}

fn unique_destination(dir: &Path, original: &Path) -> Result<PathBuf, String> {
    let name = original
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| "source has no file name".to_string())?;
    let stamp = timestamp();

    let mut candidate = dir.join(format!("{stamp}-{name}"));
    let mut counter = 1u32;
    while candidate.exists() {
        candidate = dir.join(format!("{stamp}-{counter}-{name}"));
        counter += 1;
    }
    Ok(candidate)
}

fn timestamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Keep manifest columns intact even if a path contains tabs or newlines.
fn sanitize(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::FileMetadata;
    use crate::security::Assessment;
    use tempfile::TempDir;

    fn suspicious_result(path: PathBuf) -> FileResult {
        let mut security = Assessment::clean();
        security.raise(Verdict::Suspicious, "double-extension", "double extension");
        FileResult {
            path,
            filename_matched: true,
            content_matches: vec![],
            metadata: FileMetadata::default(),
            security,
        }
    }

    fn clean_result(path: PathBuf) -> FileResult {
        FileResult {
            path,
            filename_matched: true,
            content_matches: vec![],
            metadata: FileMetadata::default(),
            security: Assessment::clean(),
        }
    }

    #[test]
    fn default_search_does_not_move_files() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("invoice.pdf.exe");
        fs::write(&source, b"pretend").unwrap();

        // Merely assessing a file must not move it.
        let results = [suspicious_result(source.clone())];
        assert!(source.exists(), "file must stay in place by default");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn quarantine_moves_file_and_writes_manifest() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("invoice.pdf.exe");
        fs::write(&source, b"pretend").unwrap();

        let dest = dir.path().join("vault");
        let policy = QuarantinePolicy::new(&dest);
        let outcome = policy.apply(&[suspicious_result(source.clone())]);

        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert_eq!(outcome.moved.len(), 1);
        assert!(!source.exists(), "source should have been moved");
        assert!(outcome.moved[0].quarantined.exists());
        assert!(outcome.moved[0].quarantined.starts_with(&dest));

        let manifest = fs::read_to_string(policy.manifest_path()).unwrap();
        assert!(manifest.contains("original_path"));
        assert!(manifest.contains("invoice.pdf.exe"));
        assert!(manifest.contains("Suspicious"));
    }

    #[test]
    fn clean_files_are_not_quarantined() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("note.txt");
        fs::write(&source, b"plain").unwrap();

        let dest = dir.path().join("vault");
        let outcome = QuarantinePolicy::new(&dest).apply(&[clean_result(source.clone())]);

        assert!(outcome.moved.is_empty());
        assert!(source.exists());
        assert!(!policy_manifest_exists(&dest));
    }

    fn policy_manifest_exists(dest: &Path) -> bool {
        dest.join(MANIFEST_NAME).exists()
    }

    #[test]
    fn manifest_appends_across_runs() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("one.pdf.exe");
        let second = dir.path().join("two.pdf.exe");
        fs::write(&first, b"a").unwrap();
        fs::write(&second, b"b").unwrap();

        let policy = QuarantinePolicy::new(dir.path().join("vault"));
        policy.apply(&[suspicious_result(first)]);
        policy.apply(&[suspicious_result(second)]);

        let manifest = fs::read_to_string(policy.manifest_path()).unwrap();
        // Header appears once, plus two data rows.
        assert_eq!(manifest.matches("original_path").count(), 1);
        assert_eq!(manifest.lines().count(), 3);
    }
}
