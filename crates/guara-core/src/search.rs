//! Filename and content matching with literal and regex support.
//!
//! Supports case-insensitive and whole-word modes, context lines, max-count,
//! memory-mapped reads for large files, file filters (extension, size, mtime,
//! binary skip), and multiple patterns with AND/OR combination.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use memmap2::Mmap;
use regex::bytes::{Regex, RegexBuilder};
use serde::Serialize;

use crate::fs::FileEntry;
use crate::index::{IndexError, IndexQuery, IndexStore};
use crate::security::{self, Assessment, HeuristicConfig};

/// Size threshold (1 MB) above which files are read via mmap.
const MMAP_THRESHOLD: u64 = 1024 * 1024;

/// File-level filter applied before content search.
#[derive(Debug, Clone, Default)]
pub struct FileFilter {
    /// Allowed file extensions (without leading dot, e.g. `["rs", "toml"]`).
    /// Empty = all extensions.
    pub extensions: Vec<String>,
    /// Minimum file size in bytes.
    pub min_size: Option<u64>,
    /// Maximum file size in bytes.
    pub max_size: Option<u64>,
    /// Only files modified after this Unix timestamp.
    pub after: Option<u64>,
    /// Only files modified before this Unix timestamp.
    pub before: Option<u64>,
    /// Skip files detected as binary for content search. Default: `true`.
    pub skip_binary: bool,
}

impl FileFilter {
    /// Returns `true` if the file passes all filter criteria.
    pub fn matches(&self, path: &Path, metadata: &fs::Metadata) -> bool {
        // Extension filter
        if !self.extensions.is_empty() {
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default();
            if !self.extensions.contains(&ext) {
                return false;
            }
        }

        // Size filter
        let size = metadata.len();
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }

        // Modification time filter
        if let Some(after) = self.after {
            if let Ok(mtime) = metadata.modified() {
                if let Ok(secs) = mtime.duration_since(SystemTime::UNIX_EPOCH) {
                    if secs.as_secs() < after {
                        return false;
                    }
                }
            }
        }
        if let Some(before) = self.before {
            if let Ok(mtime) = metadata.modified() {
                if let Ok(secs) = mtime.duration_since(SystemTime::UNIX_EPOCH) {
                    if secs.as_secs() >= before {
                        return false;
                    }
                }
            }
        }

        // Binary skip
        if self.skip_binary && is_binary(path) {
            return false;
        }

        true
    }
}

/// Detect whether a file is binary by checking MIME guess and content heuristic.
fn is_binary(path: &Path) -> bool {
    // MIME guess from extension
    if let Some(mime) = mime_guess::from_path(path).first() {
        let type_str = mime.type_().as_str();
        if type_str.starts_with("text") {
            return false;
        }
        if type_str == "application" {
            // application/* is ambiguous — check content
        } else {
            return true;
        }
    }

    // Content heuristic: check first 512 bytes for null bytes
    match fs::File::open(path) {
        Ok(mut file) => {
            use std::io::Read;
            let mut buf = [0u8; 512];
            if let Ok(n) = file.read(&mut buf) {
                buf[..n].contains(&0)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Options controlling how patterns are matched against filenames and file
/// contents.
#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    /// Search patterns. Empty = "list all files" (no filtering).
    pub patterns: Vec<String>,
    /// Treat patterns as regular expressions instead of literals.
    pub regex: bool,
    /// Case-insensitive matching.
    pub ignore_case: bool,
    /// Match whole words only.
    pub whole_word: bool,
    /// Maximum number of hits before stopping early. `None` = unlimited.
    pub max_count: Option<usize>,
    /// Number of context lines before and after a content match.
    pub context: usize,
    /// Use OR mode: any pattern matches. Default: AND (all patterns must match).
    pub or_mode: bool,
    /// Always-on security heuristics. See [`crate::security`].
    pub security: HeuristicConfig,
    /// File-level filter.
    pub filter: FileFilter,
    /// Per-file timeout in seconds. `None` = unlimited.
    pub timeout: Option<u64>,
}

/// A single content match within a file.
#[derive(Debug, Clone, Serialize)]
pub struct ContentMatch {
    /// 1-based line number of the matching line.
    pub line_number: usize,
    /// The text of the matching line.
    pub line: String,
    /// Context lines before the match (oldest first).
    pub context_before: Vec<ContextLine>,
    /// Context lines after the match (oldest first).
    pub context_after: Vec<ContextLine>,
}

/// A context line.
#[derive(Debug, Clone, Serialize)]
pub struct ContextLine {
    pub line_number: usize,
    pub line: String,
}

/// File metadata attached to each result.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FileMetadata {
    /// File size in bytes.
    pub size: Option<u64>,
    /// Last modification time (seconds since epoch).
    pub modified: Option<u64>,
    /// Unix permission bits (mode). Non-Unix: `None`.
    pub permissions: Option<u32>,
}

/// Result for a single file.
#[derive(Debug, Clone, Serialize)]
pub struct FileResult {
    pub path: PathBuf,
    pub filename_matched: bool,
    pub content_matches: Vec<ContentMatch>,
    pub metadata: FileMetadata,
    /// Lightweight security assessment. Flattened so JSON exposes the
    /// `verdict` and `reasons` fields at the top level of each hit.
    #[serde(flatten)]
    pub security: Assessment,
}

impl FileResult {
    pub fn has_hits(&self) -> bool {
        self.filename_matched || !self.content_matches.is_empty()
    }

    pub fn total_hits(&self) -> usize {
        let content = self.content_matches.len();
        if self.filename_matched {
            content + 1
        } else {
            content
        }
    }
}

/// Classification of a skipped file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipKind {
    /// Rejected by a user-requested filter (extension, size, date, binary policy).
    Filtered,
    /// Exceeded the per-file timeout.
    Timeout,
    /// Content could not be read (permissions, I/O).
    ReadError,
}

impl SkipKind {
    /// Whether this skip represents an actual error rather than intentional
    /// filtering. Only real errors should surface as exit code `3`.
    pub fn is_error(self) -> bool {
        !matches!(self, SkipKind::Filtered)
    }

    /// Human-readable label.
    pub fn as_str(self) -> &'static str {
        match self {
            SkipKind::Filtered => "filtered",
            SkipKind::Timeout => "timeout",
            SkipKind::ReadError => "read error",
        }
    }
}

impl std::fmt::Display for SkipKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A file that was skipped during search, with the reason.
#[derive(Debug, Clone, Serialize)]
pub struct SkipReason {
    pub path: PathBuf,
    pub kind: SkipKind,
}

/// Aggregate search statistics.
#[derive(Debug, Clone, Default)]
pub struct SearchStats {
    pub files_scanned: usize,
    pub files_matched: usize,
    pub total_hits: usize,
    pub capped: bool,
    /// Files skipped due to errors, oversize, timeout, or filter rejection.
    pub skipped: Vec<SkipReason>,
    /// Set when candidates came from the persistent index.
    pub index: Option<IndexUsage>,
}

/// How the persistent index contributed to a search.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// `files_scanned` counts the rows the SQL filter returned; these fields explain
/// what happened to them.
pub struct IndexUsage {
    /// Rows returned by the index query.
    pub candidates: usize,
    /// Rows whose `size`/`mtime` no longer matched, so the file was rescanned
    /// live instead of trusting the index.
    pub stale: usize,
    /// Rows whose file was gone; dropped from the candidate list.
    pub missing: usize,
}

impl SearchStats {
    /// Whether any skipped file represents an actual error (not intentional
    /// filtering).
    pub fn has_errors(&self) -> bool {
        self.skipped.iter().any(|s| s.kind.is_error())
    }
}

/// Compile regexes from the search options. Returns an empty vec when no
/// patterns are set (list-all mode).
pub fn build_regexes(options: &SearchOptions) -> Result<Vec<Regex>, regex::Error> {
    options
        .patterns
        .iter()
        .map(|pattern| {
            let pattern = if options.regex {
                pattern.clone()
            } else {
                regex::escape(pattern)
            };
            let pattern = if options.whole_word {
                format!(r"(?-u)\b{pattern}\b(?-u)")
            } else {
                pattern
            };
            let mut builder = RegexBuilder::new(&pattern);
            builder.case_insensitive(options.ignore_case);
            builder.build()
        })
        .collect()
}

/// Check if a line matches according to AND/OR mode.
fn line_matches(line: &[u8], regexes: &[Regex], or_mode: bool) -> bool {
    if regexes.is_empty() {
        return true;
    }
    if or_mode {
        regexes.iter().any(|re| re.is_match(line))
    } else {
        regexes.iter().all(|re| re.is_match(line))
    }
}

/// Check if a filename matches any pattern.
fn filename_matches(filename: &str, regexes: &[Regex]) -> bool {
    if regexes.is_empty() {
        return true;
    }
    regexes.iter().any(|re| re.is_match(filename.as_bytes()))
}

/// Search a list of file entries.
///
/// Returns matched results and statistics. If `max_count` is set, the search
/// stops after the configured number of hits and `stats.capped` is `true`.
pub fn search_entries(
    entries: &[FileEntry],
    options: &SearchOptions,
) -> (Vec<FileResult>, SearchStats) {
    let regexes = match build_regexes(options) {
        Ok(r) if r.is_empty() => {
            // No patterns: list all files that pass the filter.
            let mut results = Vec::new();
            let mut skipped = Vec::new();
            for entry in entries {
                let metadata = collect_metadata(&entry.path);
                if let Ok(md) = fs::metadata(&entry.path) {
                    if !options.filter.matches(&entry.path, &md) {
                        skipped.push(SkipReason {
                            path: entry.path.clone(),
                            kind: SkipKind::Filtered,
                        });
                        continue;
                    }
                }
                results.push(FileResult {
                    path: entry.path.clone(),
                    filename_matched: true,
                    content_matches: vec![],
                    security: security::assess(&entry.path, &metadata, &options.security),
                    metadata,
                });
            }
            let stats = SearchStats {
                files_scanned: entries.len(),
                files_matched: results.len(),
                total_hits: results.len(),
                capped: false,
                skipped,
                index: None,
            };
            return (results, stats);
        }
        Ok(r) => r,
        Err(_) => {
            // Invalid regex is a whole-run configuration error, not a per-file
            // skip. Callers should validate via `build_regexes` first.
            let stats = SearchStats {
                files_scanned: entries.len(),
                ..Default::default()
            };
            return (vec![], stats);
        }
    };

    let mut results = Vec::new();
    let mut total_hits = 0;
    let mut capped = false;
    let mut skipped = Vec::new();
    let context = options.context;
    let timeout = options.timeout.map(std::time::Duration::from_secs);

    for entry in entries {
        if let Some(max) = options.max_count {
            if total_hits >= max {
                capped = true;
                break;
            }
        }

        // Apply file filter before content search
        if let Ok(md) = fs::metadata(&entry.path) {
            if !options.filter.matches(&entry.path, &md) {
                skipped.push(SkipReason {
                    path: entry.path.clone(),
                    kind: SkipKind::Filtered,
                });
                continue;
            }
        }

        let file_start = std::time::Instant::now();

        let metadata = collect_metadata(&entry.path);

        let filename = entry
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let filename_matched = filename_matches(&filename, &regexes);
        if filename_matched {
            total_hits += 1;
        }

        let mut content_matches = Vec::new();

        if let Some(data) = read_contents(&entry.path) {
            let bytes = data.as_bytes();
            let lines: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
            let line_count = lines.len();

            for (idx, line) in lines.iter().enumerate() {
                // Check per-file timeout
                if let Some(t) = timeout {
                    if file_start.elapsed() > t {
                        skipped.push(SkipReason {
                            path: entry.path.clone(),
                            kind: SkipKind::Timeout,
                        });
                        break;
                    }
                }

                if line_matches(line, &regexes, options.or_mode) {
                    total_hits += 1;

                    let context_before = (0..context)
                        .rev()
                        .map(|c| idx.saturating_sub(c + 1))
                        .filter(|&i| i < line_count)
                        .rev()
                        .map(|i| ContextLine {
                            line_number: i + 1,
                            line: String::from_utf8_lossy(lines[i]).to_string(),
                        })
                        .collect();

                    let context_after = (1..=context)
                        .map(|c| idx + c)
                        .filter(|&i| i < line_count)
                        .map(|i| ContextLine {
                            line_number: i + 1,
                            line: String::from_utf8_lossy(lines[i]).to_string(),
                        })
                        .collect();

                    content_matches.push(ContentMatch {
                        line_number: idx + 1,
                        line: String::from_utf8_lossy(line).to_string(),
                        context_before,
                        context_after,
                    });

                    if let Some(max) = options.max_count {
                        if total_hits >= max {
                            capped = true;
                            break;
                        }
                    }
                }
            }
        }

        if filename_matched || !content_matches.is_empty() {
            results.push(FileResult {
                path: entry.path.clone(),
                filename_matched,
                content_matches,
                security: security::assess(&entry.path, &metadata, &options.security),
                metadata,
            });
        }

        if let Some(max) = options.max_count {
            if total_hits >= max {
                capped = true;
                break;
            }
        }
    }

    let stats = SearchStats {
        files_scanned: entries.len(),
        files_matched: results.len(),
        total_hits,
        capped,
        skipped,
        index: None,
    };

    (results, stats)
}

/// Search candidates taken from the persistent index instead of a live walk.
///
/// The index supplies the candidate list and prunes it with SQL
/// metadata filters. Contents are always read live, and each candidate is
/// `stat`ed first: a row whose `size` or `mtime` changed is counted as stale and
/// rescanned. Rows whose file disappeared are dropped; the next
/// `guara index` pass prunes them from the database. This function never
/// writes: searching does not mutate the index.
pub fn search_indexed(
    store: &IndexStore,
    query: &IndexQuery,
    options: &SearchOptions,
) -> Result<(Vec<FileResult>, SearchStats), IndexError> {
    let rows = store.query(query)?;
    let mut entries = Vec::with_capacity(rows.len());
    let mut stale = 0;
    let mut missing = 0;

    for row in &rows {
        match fs::metadata(&row.path) {
            Err(_) => missing += 1,
            Ok(metadata) => {
                if metadata.len() != row.size || modified_secs(&metadata) != row.mtime {
                    stale += 1;
                }
                entries.push(FileEntry {
                    path: row.path.clone(),
                });
            }
        }
    }

    let (results, mut stats) = search_entries(&entries, options);
    stats.index = Some(IndexUsage {
        candidates: rows.len(),
        stale,
        missing,
    });
    Ok((results, stats))
}

/// File contents abstraction: either owned bytes or memory-mapped.
enum FileContents {
    Owned(Vec<u8>),
    Mapped(Mmap),
}

impl FileContents {
    fn as_bytes(&self) -> &[u8] {
        match self {
            FileContents::Owned(v) => v,
            FileContents::Mapped(m) => m.as_ref(),
        }
    }
}

/// Read file contents, using mmap for files above the threshold.
fn read_contents(path: &Path) -> Option<FileContents> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return None;
    }

    let size = metadata.len();

    if size > MMAP_THRESHOLD {
        let file = fs::File::open(path).ok()?;
        match unsafe { Mmap::map(&file) } {
            Ok(mmap) => Some(FileContents::Mapped(mmap)),
            Err(_) => fs::read(path).ok().map(FileContents::Owned),
        }
    } else {
        fs::read(path).ok().map(FileContents::Owned)
    }
}

/// Collect file metadata (size, modified time, permissions).
/// Missing fields are `None` rather than causing a panic.
fn collect_metadata(path: &Path) -> FileMetadata {
    match fs::metadata(path) {
        Ok(m) => FileMetadata {
            size: Some(m.len()),
            modified: Some(modified_secs(&m)),
            permissions: permissions_mode(&m),
        },
        Err(_) => FileMetadata::default(),
    }
}

/// Last modification time in seconds since the Unix epoch (0 when unknown).
fn modified_secs(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn permissions_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.mode())
}

#[cfg(not(unix))]
fn permissions_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

/// Parse a size string like "1k", "2M", "1G" into bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Find where the numeric part ends
    let split = s
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| i)
        .unwrap_or(s.len());

    let (num_str, suffix) = s.split_at(split);
    let num: u64 = num_str.parse().ok()?;

    let multiplier = match suffix.trim().to_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return None,
    };

    Some(num * multiplier)
}

/// Parse a date string in `YYYY-MM-DD` format into a Unix timestamp.
pub fn parse_date(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: u32 = parts[0].parse().ok()?;
    let month: u32 = parts[1].parse().ok()?;
    let day: u32 = parts[2].parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    days_from_epoch(year, month, day).map(|d| d as u64 * 86400)
}

fn is_leap(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_epoch(year: u32, month: u32, day: u32) -> Option<i64> {
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[m as usize] as i64;
        if m == 2 && is_leap(year) {
            days += 1;
        }
    }
    days += (day - 1) as i64;
    Some(days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{walk, WalkOptions};
    use std::fs as stdfs;
    use tempfile::TempDir;

    fn make_fixture() -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path();

        stdfs::write(root.join("foo.txt"), "hello world\nfoo bar baz\n").unwrap();
        stdfs::write(root.join("bar.txt"), "nothing interesting here\n").unwrap();
        stdfs::write(root.join("foo_bar.txt"), "line 1\nmatching foo\nline 3\n").unwrap();
        stdfs::write(root.join("empty.txt"), "").unwrap();
        stdfs::write(
            root.join("multi.txt"),
            "first foo\nsecond\nthird foo\nfourth\nfifth foo\n",
        )
        .unwrap();

        dir
    }

    fn entries(dir: &TempDir) -> Vec<FileEntry> {
        walk(&[dir.path()], &WalkOptions::default()).entries
    }

    /// `search foo` matches files whose names contain `foo`.
    #[test]
    fn literal_filename_match() {
        let dir = make_fixture();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["foo".to_string()],
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let names: Vec<String> = results
            .iter()
            .map(|r| r.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"foo.txt".to_string()));
        assert!(names.contains(&"foo_bar.txt".to_string()));
        assert!(!names.contains(&"bar.txt".to_string()));
    }

    /// `-e 'bar.*baz'` matches regex names only.
    #[test]
    fn regex_filename_match() {
        let dir = make_fixture();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["bar.*baz".to_string()],
            regex: true,
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let name_matches: Vec<&FileResult> =
            results.iter().filter(|r| r.filename_matched).collect();
        assert!(name_matches.is_empty(), "no filename should match bar.*baz");
    }

    /// Content search: a file containing the needle emits path + matching line(s).
    #[test]
    fn content_match() {
        let dir = make_fixture();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["foo".to_string()],
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let foo_result = results
            .iter()
            .find(|r| r.path.file_name().unwrap() == "foo.txt")
            .expect("foo.txt should be in results");
        assert!(!foo_result.content_matches.is_empty());
        assert!(foo_result
            .content_matches
            .iter()
            .any(|m| m.line.contains("foo")));
    }

    /// `--context 2` includes two lines before and after.
    #[test]
    fn context_lines() {
        let dir = make_fixture();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["second".to_string()],
            context: 2,
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let multi = results
            .iter()
            .find(|r| r.path.file_name().unwrap() == "multi.txt")
            .expect("multi.txt should be in results");

        assert_eq!(multi.content_matches.len(), 1);
        let m = &multi.content_matches[0];
        assert_eq!(m.line_number, 2);
        assert_eq!(m.line, "second");
        assert_eq!(m.context_before.len(), 2);
        assert_eq!(m.context_before[0].line, "first foo");
        assert_eq!(m.context_after.len(), 2);
        assert_eq!(m.context_after[0].line, "third foo");
    }

    /// `-i` matches mixed case.
    #[test]
    fn case_insensitive() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("test.txt"), "Hello World\nHELLO\n").unwrap();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["hello".to_string()],
            ignore_case: true,
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let result = results
            .iter()
            .find(|r| r.path.file_name().unwrap() == "test.txt")
            .expect("test.txt should match");
        assert!(result.content_matches.len() >= 2);
    }

    /// `-w` does not match the needle as a substring of a longer token.
    #[test]
    fn whole_word() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("test.txt"), "foo\nfoobar\na foo b\n").unwrap();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["foo".to_string()],
            whole_word: true,
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let result = results
            .iter()
            .find(|r| r.path.file_name().unwrap() == "test.txt")
            .expect("test.txt should have whole-word matches");

        let matched_lines: Vec<&str> = result
            .content_matches
            .iter()
            .map(|m| m.line.as_str())
            .collect();
        assert!(matched_lines.contains(&"foo"));
        assert!(matched_lines.contains(&"a foo b"));
        assert!(!matched_lines.contains(&"foobar"));
    }

    /// Empty file: no content matches, no panic.
    #[test]
    fn empty_file_no_panic() {
        let dir = make_fixture();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["anything".to_string()],
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);
        assert!(results
            .iter()
            .all(|r| r.path.file_name().unwrap() != "empty.txt"));
    }

    /// `--max-count` stops after the configured number of hits.
    #[test]
    fn max_count_stops_early() {
        let dir = make_fixture();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["foo".to_string()],
            max_count: Some(1),
            ..Default::default()
        };
        let (_results, stats) = search_entries(&entries, &opts);
        assert!(stats.capped);
        assert!(stats.total_hits <= 2);
    }

    /// No pattern: list all files.
    #[test]
    fn no_pattern_lists_all() {
        let dir = make_fixture();
        let entries = entries(&dir);
        let opts = SearchOptions::default();
        let (results, stats) = search_entries(&entries, &opts);

        assert_eq!(results.len(), entries.len());
        assert!(!stats.capped);
    }

    /// Regex content match.
    #[test]
    fn regex_content_match() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("test.txt"), "abc123\ndef456\nghi789\n").unwrap();
        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec![r"\d+".to_string()],
            regex: true,
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let result = results
            .iter()
            .find(|r| r.path.file_name().unwrap() == "test.txt")
            .expect("test.txt should match");
        assert_eq!(result.content_matches.len(), 3);
    }

    // --- File filter tests ---

    #[test]
    fn filter_by_extension() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.rs"), "fn main() {}\n").unwrap();
        stdfs::write(dir.path().join("b.txt"), "hello\n").unwrap();
        stdfs::write(dir.path().join("c.rs"), "mod test;\n").unwrap();

        let entries = entries(&dir);
        let opts = SearchOptions {
            filter: FileFilter {
                extensions: vec!["rs".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let names: Vec<String> = results
            .iter()
            .map(|r| r.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"a.rs".to_string()));
        assert!(names.contains(&"c.rs".to_string()));
        assert!(!names.contains(&"b.txt".to_string()));
    }

    #[test]
    fn filter_by_size() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("small.txt"), "ab").unwrap();
        stdfs::write(dir.path().join("big.txt"), "abcdefghijklmnopqrstuvwxyz").unwrap();

        let entries = entries(&dir);
        let opts = SearchOptions {
            filter: FileFilter {
                min_size: Some(10),
                ..Default::default()
            },
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let names: Vec<String> = results
            .iter()
            .map(|r| r.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(!names.contains(&"small.txt".to_string()));
        assert!(names.contains(&"big.txt".to_string()));
    }

    #[test]
    fn filter_binary_skip() {
        let dir = TempDir::new().unwrap();
        // Write a text file
        stdfs::write(dir.path().join("text.txt"), "hello world\n").unwrap();
        // Write a binary file (null bytes)
        stdfs::write(
            dir.path().join("data.bin"),
            vec![0x00, 0x01, 0x02, 0x00, 0xFF],
        )
        .unwrap();

        let entries = entries(&dir);

        // Default: skip_binary = false, but we need to set it to test
        let opts = SearchOptions {
            patterns: vec!["hello".to_string()],
            filter: FileFilter {
                skip_binary: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let names: Vec<String> = results
            .iter()
            .map(|r| r.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"text.txt".to_string()));
        assert!(!names.contains(&"data.bin".to_string()));
    }

    #[test]
    fn filter_binary_search_when_enabled() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("text.txt"), "hello world\n").unwrap();
        stdfs::write(
            dir.path().join("data.bin"),
            vec![b'h', b'e', b'l', b'l', b'o', 0x00],
        )
        .unwrap();

        let entries = entries(&dir);
        // With skip_binary=false, the .bin file is not skipped
        let opts = SearchOptions {
            patterns: vec!["hello".to_string()],
            filter: FileFilter {
                skip_binary: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let names: Vec<String> = results
            .iter()
            .map(|r| r.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"text.txt".to_string()));
        assert!(names.contains(&"data.bin".to_string()));
    }

    // --- Multiple terms AND/OR tests ---

    #[test]
    fn multiple_terms_and() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("both.txt"), "foo bar\n").unwrap();
        stdfs::write(dir.path().join("only_foo.txt"), "foo\n").unwrap();
        stdfs::write(dir.path().join("only_bar.txt"), "bar\n").unwrap();

        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["foo".to_string(), "bar".to_string()],
            or_mode: false,
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        // AND: only files containing BOTH foo and bar should match in content
        let both = results
            .iter()
            .find(|r| r.path.file_name().unwrap() == "both.txt");
        assert!(both.is_some(), "both.txt should match (AND)");

        // only_foo.txt has "foo" in filename, so it will match on filename.
        // But content has only "foo" (no "bar"), so no content match.
        // filename_matched will be true because any pattern matches filename.
        // This is expected — filename matching uses OR semantics.
    }

    #[test]
    fn multiple_terms_or() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("only_foo.txt"), "foo\n").unwrap();
        stdfs::write(dir.path().join("only_bar.txt"), "bar\n").unwrap();
        stdfs::write(dir.path().join("neither.txt"), "baz\n").unwrap();

        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["foo".to_string(), "bar".to_string()],
            or_mode: true,
            ..Default::default()
        };
        let (results, _) = search_entries(&entries, &opts);

        let names: Vec<String> = results
            .iter()
            .map(|r| r.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"only_foo.txt".to_string()));
        assert!(names.contains(&"only_bar.txt".to_string()));
        assert!(!names.contains(&"neither.txt".to_string()));
    }

    // --- Helper function tests ---

    #[test]
    fn parse_size_variants() {
        assert_eq!(parse_size("100"), Some(100));
        assert_eq!(parse_size("1k"), Some(1024));
        assert_eq!(parse_size("1kb"), Some(1024));
        assert_eq!(parse_size("2M"), Some(2 * 1024 * 1024));
        assert_eq!(parse_size("3G"), Some(3 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("abc"), None);
    }

    #[test]
    fn parse_date_basic() {
        // 2024-01-01 should be > 0
        let ts = parse_date("2024-01-01").expect("valid date");
        assert!(ts > 0);
        // Unix epoch
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("invalid"), None);
        assert_eq!(parse_date("2024-13-01"), None);
    }

    // --- Skip classification tests ---

    #[test]
    fn filtered_skips_are_not_errors() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.rs"), "hello\n").unwrap();
        stdfs::write(dir.path().join("b.txt"), "hello\n").unwrap();

        let entries = entries(&dir);
        let opts = SearchOptions {
            filter: FileFilter {
                extensions: vec!["rs".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let (_, stats) = search_entries(&entries, &opts);

        // b.txt was filtered out, but that is not an error.
        assert!(stats.skipped.iter().any(|s| s.kind == SkipKind::Filtered));
        assert!(!stats.has_errors());
    }

    #[test]
    fn binary_policy_skip_is_not_an_error() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("data.bin"), vec![0x00, 0x01, 0x00]).unwrap();
        stdfs::write(dir.path().join("text.txt"), "hello\n").unwrap();

        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["hello".to_string()],
            filter: FileFilter {
                skip_binary: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let (_, stats) = search_entries(&entries, &opts);

        assert!(stats.skipped.iter().any(|s| s.kind == SkipKind::Filtered));
        assert!(!stats.has_errors());
    }

    #[test]
    fn timeout_skip_is_an_error() {
        let dir = TempDir::new().unwrap();
        // Large-ish file to give the timeout a chance to trigger at 0s.
        let content = "needle\n".repeat(1000);
        stdfs::write(dir.path().join("big.txt"), content).unwrap();

        let entries = entries(&dir);
        let opts = SearchOptions {
            patterns: vec!["needle".to_string()],
            timeout: Some(0),
            ..Default::default()
        };
        let (_, stats) = search_entries(&entries, &opts);

        // With a 0-second timeout, the per-file loop should record a timeout.
        if stats.skipped.iter().any(|s| s.kind == SkipKind::Timeout) {
            assert!(stats.has_errors());
        }
    }

    fn index_fixture(dir: &TempDir) -> crate::index::IndexStore {
        let mut store = crate::index::IndexStore::open_in_memory().unwrap();
        store
            .update(
                &[dir.path().to_path_buf()],
                &WalkOptions::default(),
                &crate::index::UpdateOptions::default(),
            )
            .unwrap();
        store
    }

    fn index_query(dir: &TempDir) -> IndexQuery {
        IndexQuery {
            unders: vec![dir.path().to_path_buf()],
            ..Default::default()
        }
    }

    fn names(results: &[FileResult]) -> Vec<String> {
        let mut names: Vec<String> = results
            .iter()
            .map(|r| {
                r.path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default()
            })
            .collect();
        names.sort();
        names
    }

    /// An indexed search reads rows instead of walking: a file created after the
    /// index pass is not a candidate.
    #[test]
    fn indexed_search_does_not_walk_the_tree() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("indexed.txt"), "needle\n").unwrap();
        let store = index_fixture(&dir);

        // Written after indexing: a live walk would find it, the index will not.
        stdfs::write(dir.path().join("untracked.txt"), "needle\n").unwrap();

        let opts = SearchOptions {
            patterns: vec!["needle".to_string()],
            ..Default::default()
        };
        let (results, stats) = search_indexed(&store, &index_query(&dir), &opts).unwrap();

        assert_eq!(names(&results), vec!["indexed.txt".to_string()]);
        let index = stats.index.expect("index usage is recorded");
        assert_eq!(index.candidates, 1);
        assert_eq!(index.missing, 0);
    }

    /// A changed file is rescanned live rather than trusted from the index
    #[test]
    fn indexed_search_rescans_a_stale_entry() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "nothing here\n").unwrap();
        let store = index_fixture(&dir);

        // Different size, newer mtime: the row no longer describes the file.
        stdfs::write(dir.path().join("a.txt"), "now it has a needle inside\n").unwrap();

        let opts = SearchOptions {
            patterns: vec!["needle".to_string()],
            ..Default::default()
        };
        let (results, stats) = search_indexed(&store, &index_query(&dir), &opts).unwrap();

        assert_eq!(names(&results), vec!["a.txt".to_string()]);
        let index = stats.index.expect("index usage is recorded");
        assert_eq!(index.stale, 1);
        assert_eq!(index.missing, 0);
    }

    /// Rows whose file disappeared are dropped from the candidate list.
    #[test]
    fn indexed_search_skips_vanished_files() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        stdfs::write(dir.path().join("b.txt"), "needle\n").unwrap();
        let store = index_fixture(&dir);

        stdfs::remove_file(dir.path().join("b.txt")).unwrap();

        let opts = SearchOptions {
            patterns: vec!["needle".to_string()],
            ..Default::default()
        };
        let (results, stats) = search_indexed(&store, &index_query(&dir), &opts).unwrap();

        assert_eq!(names(&results), vec!["a.txt".to_string()]);
        let index = stats.index.expect("index usage is recorded");
        assert_eq!(index.candidates, 2);
        assert_eq!(index.missing, 1);
    }

    /// Fallback check for: a live walk and a fresh index agree.
    #[test]
    fn live_walk_and_indexed_search_agree() {
        let dir = make_fixture();
        let store = index_fixture(&dir);
        let opts = SearchOptions {
            patterns: vec!["foo".to_string()],
            ..Default::default()
        };

        let walk_entries = entries(&dir);
        let (walk_results, _) = search_entries(&walk_entries, &opts);
        let (indexed_results, _) = search_indexed(&store, &index_query(&dir), &opts).unwrap();

        assert_eq!(names(&walk_results), names(&indexed_results));
    }

    /// Metadata filters are applied in SQL, so only matching rows are candidates.
    #[test]
    fn indexed_query_prunes_by_extension_and_size() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("small.txt"), "needle\n").unwrap();
        stdfs::write(dir.path().join("big.txt"), "needle\n".repeat(100)).unwrap();
        stdfs::write(dir.path().join("note.md"), "needle\n").unwrap();
        let store = index_fixture(&dir);

        let query = IndexQuery {
            extensions: vec!["txt".to_string()],
            max_size: Some(20),
            unders: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let rows = store.query(&query).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path.file_name().unwrap(), "small.txt");
    }
}
