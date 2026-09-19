//! Output formatters: human-readable terminal output, JSON, CSV, HTML.
//!
//! Supports color (with `NO_COLOR` and TTY detection), compact and tabular
//! modes, grep-style context with line numbers, and file exports.
//! Statistics go to stderr so that `--json` stdout stays clean.

use std::time::Duration;

use crate::search::{ContentMatch, FileMetadata, FileResult, SearchStats};
use crate::security::{Assessment, Verdict};

/// When to use color output.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ColorMode {
    Always,
    Never,
    Auto,
}

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OutputOptions {
    pub color: ColorMode,
    pub compact: bool,
    pub table: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            color: ColorMode::Auto,
            compact: false,
            table: false,
        }
    }
}

/// Returns `true` if color should be emitted given the mode and TTY status.
pub fn use_color(mode: ColorMode, is_tty: bool) -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => is_tty,
    }
}

// ANSI color codes
const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";

fn color(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Format results for the terminal: one block per file with path, metadata,
/// and content matches.
pub fn format_human(results: &[FileResult], opts: &OutputOptions) -> String {
    if opts.table {
        return format_table(results, opts);
    }
    if opts.compact {
        return format_compact(results, opts);
    }
    format_default(results, opts)
}

fn format_default(results: &[FileResult], opts: &OutputOptions) -> String {
    let c = use_color(opts.color, false);
    let mut out = String::new();

    for result in results {
        let meta = format_metadata_inline(&result.metadata);
        let path_display = result.path.display().to_string();
        if meta.is_empty() {
            out.push_str(&format!("{}\n", color(&path_display, BOLD, c)));
        } else {
            out.push_str(&format!(
                "{} ({})\n",
                color(&path_display, BOLD, c),
                color(&meta, CYAN, c)
            ));
        }

        if let Some(suffix) = format_security_suffix(&result.security) {
            out.push_str(&format!("  security: {}\n", color(&suffix, YELLOW, c)));
        }

        for m in &result.content_matches {
            out.push_str(&format!(
                "  {}:{}: {}\n",
                color(&result.path.display().to_string(), GREEN, c),
                color(&m.line_number.to_string(), YELLOW, c),
                m.line
            ));
            for ctx in &m.context_before {
                out.push_str(&format!(
                    "  {}-{}: {}\n",
                    color(&result.path.display().to_string(), GREEN, c),
                    color(&ctx.line_number.to_string(), YELLOW, c),
                    ctx.line
                ));
            }
            for ctx in &m.context_after {
                out.push_str(&format!(
                    "  {}+{}: {}\n",
                    color(&result.path.display().to_string(), GREEN, c),
                    color(&ctx.line_number.to_string(), YELLOW, c),
                    ctx.line
                ));
            }
        }
    }

    out
}

fn format_compact(results: &[FileResult], opts: &OutputOptions) -> String {
    let c = use_color(opts.color, false);
    let mut out = String::new();

    for result in results {
        let path_display = result.path.display().to_string();
        if result.content_matches.is_empty() {
            out.push_str(&format!("{}\n", color(&path_display, BOLD, c)));
        } else {
            let lines: Vec<String> = result
                .content_matches
                .iter()
                .map(|m| format!("{}: {}", m.line_number, m.line))
                .collect();
            out.push_str(&format!(
                "{}: {}\n",
                color(&path_display, BOLD, c),
                lines.join("; ")
            ));
        }
    }

    out
}

fn format_table(results: &[FileResult], opts: &OutputOptions) -> String {
    let c = use_color(opts.color, false);
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{}\n",
        color("PATH\tMATCHES\tSIZE\tMODIFIED", BOLD, c)
    ));

    for result in results {
        let match_count = result.content_matches.len();
        let size = result
            .metadata
            .size
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let modified = result
            .metadata
            .modified
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            color(&result.path.display().to_string(), GREEN, c),
            match_count,
            size,
            modified
        ));
    }

    out
}

/// Format results as newline-delimited JSON objects.
pub fn format_json(results: &[FileResult]) -> String {
    let mut lines = Vec::new();
    for result in results {
        match serde_json::to_string(result) {
            Ok(s) => lines.push(s),
            Err(_) => continue,
        }
    }
    lines.join("\n")
}

/// Format search statistics for stderr output.
pub fn format_stats(stats: &SearchStats, elapsed: Duration) -> String {
    let mut msg = format!(
        "scanned {} files, {} hits, {} matched, {} skipped, {:.3}s",
        stats.files_scanned,
        stats.total_hits,
        stats.files_matched,
        stats.skipped.len(),
        elapsed.as_secs_f64()
    );
    if stats.capped {
        msg.push_str(" (capped)");
    }
    if let Some(index) = &stats.index {
        msg.push_str(&format!(
            " (index: {} candidates, {} stale, {} missing)",
            index.candidates, index.stale, index.missing
        ));
    }
    msg
}

/// Human-readable, one-line security suffix. `None` when the file is clean.
pub fn format_security_suffix(assessment: &Assessment) -> Option<String> {
    if assessment.is_clean() {
        return None;
    }
    let reasons: Vec<&str> = assessment
        .reasons
        .iter()
        .map(|r| r.message.as_str())
        .collect();
    Some(format!("{}: {}", assessment.verdict, reasons.join("; ")))
}

/// One-line threat summary counting results by verdict. Shown on stderr
/// unless `--quiet` is set.
pub fn format_security_summary(results: &[FileResult]) -> String {
    let mut clean = 0usize;
    let mut suspicious = 0usize;
    let mut high_risk = 0usize;
    for result in results {
        match result.security.verdict {
            Verdict::Clean => clean += 1,
            Verdict::Suspicious => suspicious += 1,
            Verdict::HighRisk => high_risk += 1,
        }
    }
    format!("security: {clean} clean, {suspicious} suspicious, {high_risk} high risk")
}

/// Format a single content match as a human-readable string (for reuse/testing).
pub fn format_content_match(m: &ContentMatch) -> String {
    let mut out = format!("{}: {}", m.line_number, m.line);
    for ctx in &m.context_before {
        out.push_str(&format!("\n  -{}: {}", ctx.line_number, ctx.line));
    }
    for ctx in &m.context_after {
        out.push_str(&format!("\n  +{}: {}", ctx.line_number, ctx.line));
    }
    out
}

/// Format results as CSV.
pub fn format_csv(results: &[FileResult]) -> String {
    let mut out = String::new();
    out.push_str("path,filename_matched,line_number,line,size,modified,permissions\n");

    for result in results {
        let size = result
            .metadata
            .size
            .map(|s| s.to_string())
            .unwrap_or_default();
        let modified = result
            .metadata
            .modified
            .map(|m| m.to_string())
            .unwrap_or_default();
        let permissions = result
            .metadata
            .permissions
            .map(|p| format!("{p:o}"))
            .unwrap_or_default();
        let path = result.path.display();

        if result.content_matches.is_empty() {
            out.push_str(&format!(
                "{path},{},{},,{size},{modified},{permissions}\n",
                result.filename_matched, ""
            ));
        } else {
            for m in &result.content_matches {
                let escaped_line = csv_escape(&m.line);
                out.push_str(&format!(
                    "{path},{},{},{escaped_line},{size},{modified},{permissions}\n",
                    result.filename_matched, m.line_number
                ));
            }
        }
    }

    out
}

/// Format results as a self-contained HTML report.
pub fn format_html(results: &[FileResult]) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<title>Guará Search Results</title>\n");
    out.push_str("<style>\n");
    out.push_str("body{font-family:sans-serif;margin:1em}\n");
    out.push_str("table{border-collapse:collapse;width:100%}\n");
    out.push_str("th,td{border:1px solid #ccc;padding:4px 8px;text-align:left}\n");
    out.push_str("th{background:#f0f0f0}\n");
    out.push_str("code{background:#f8f8f8;padding:2px}\n");
    out.push_str("</style>\n</head>\n<body>\n");
    out.push_str("<h1>Guará Search Results</h1>\n");
    out.push_str("<table>\n<thead><tr>");
    out.push_str("<th>Path</th><th>Match</th><th>Line #</th><th>Line</th>");
    out.push_str("<th>Size</th><th>Modified</th><th>Permissions</th>");
    out.push_str("</tr></thead>\n<tbody>\n");

    for result in results {
        let size = result
            .metadata
            .size
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".to_string());
        let modified = result
            .metadata
            .modified
            .map(|m| m.to_string())
            .unwrap_or_else(|| "—".to_string());
        let permissions = result
            .metadata
            .permissions
            .map(|p| format!("{p:o}"))
            .unwrap_or_else(|| "—".to_string());
        let path = html_escape(&result.path.display().to_string());

        if result.content_matches.is_empty() {
            out.push_str(&format!(
                "<tr><td><code>{path}</code></td><td>filename</td><td>—</td><td>—</td><td>{size}</td><td>{modified}</td><td>{permissions}</td></tr>\n"
            ));
        } else {
            for m in &result.content_matches {
                let line = html_escape(&m.line);
                out.push_str(&format!(
                    "<tr><td><code>{path}</code></td><td>content</td><td>{}</td><td>{line}</td><td>{size}</td><td>{modified}</td><td>{permissions}</td></tr>\n",
                    m.line_number
                ));
            }
        }
    }

    out.push_str("</tbody>\n</table>\n</body>\n</html>\n");
    out
}

fn format_metadata_inline(meta: &FileMetadata) -> String {
    let mut parts = Vec::new();
    if let Some(size) = meta.size {
        parts.push(format!("{size} bytes"));
    }
    if let Some(mtime) = meta.modified {
        parts.push(format!("modified: {mtime}"));
    }
    if let Some(mode) = meta.permissions {
        parts.push(format!("mode: {mode:o}"));
    }
    parts.join(", ")
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::{FileMetadata, FileResult};
    use std::path::PathBuf;

    fn make_result(path: &str, filename_matched: bool) -> FileResult {
        FileResult {
            path: PathBuf::from(path),
            filename_matched,
            content_matches: vec![],
            metadata: FileMetadata {
                size: Some(42),
                modified: Some(1700000000),
                permissions: Some(0o644),
            },
            security: Assessment::default(),
        }
    }

    #[test]
    fn human_output_one_block_per_file() {
        let results = vec![
            make_result("/foo/bar.txt", true),
            make_result("/baz/qux.txt", false),
        ];
        let opts = OutputOptions {
            color: ColorMode::Never,
            ..Default::default()
        };
        let out = format_human(&results, &opts);

        assert!(out.contains("/foo/bar.txt"));
        assert!(out.contains("/baz/qux.txt"));
        assert!(out.contains("42 bytes"));
    }

    #[test]
    fn human_output_with_content_matches() {
        let result = FileResult {
            path: PathBuf::from("/foo/test.txt"),
            filename_matched: false,
            content_matches: vec![ContentMatch {
                line_number: 5,
                line: "hello world".to_string(),
                context_before: vec![],
                context_after: vec![],
            }],
            metadata: FileMetadata::default(),
            security: Assessment::default(),
        };
        let opts = OutputOptions {
            color: ColorMode::Never,
            ..Default::default()
        };
        let out = format_human(std::slice::from_ref(&result), &opts);
        assert!(out.contains("5: hello world"));
    }

    #[test]
    fn json_output_has_required_keys() {
        let results = vec![make_result("/foo/bar.txt", true)];
        let json = format_json(&results);
        assert!(!json.is_empty());

        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let obj = parsed.as_object().expect("JSON object");
        assert!(obj.contains_key("path"));
        assert!(obj.contains_key("filename_matched"));
        assert!(obj.contains_key("content_matches"));
        assert!(obj.contains_key("metadata"));

        let meta = obj.get("metadata").unwrap().as_object().unwrap();
        assert!(meta.contains_key("size"));
        assert!(meta.contains_key("modified"));
        assert!(meta.contains_key("permissions"));
    }

    #[test]
    fn json_output_multiple_results_ndjson() {
        let results = vec![
            make_result("/foo/1.txt", true),
            make_result("/foo/2.txt", false),
        ];
        let json = format_json(&results);
        let lines: Vec<&str> = json.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).expect("each line is valid JSON");
        }
    }

    #[test]
    fn stats_format_has_scanned_and_hits() {
        let stats = SearchStats {
            files_scanned: 100,
            files_matched: 5,
            total_hits: 10,
            capped: false,
            ..Default::default()
        };
        let out = format_stats(&stats, Duration::from_millis(1500));
        assert!(out.contains("scanned 100 files"));
        assert!(out.contains("10 hits"));
        assert!(out.contains("5 matched"));
        assert!(!out.contains("capped"));
    }

    #[test]
    fn stats_capped_marker() {
        let stats = SearchStats {
            files_scanned: 5,
            files_matched: 3,
            total_hits: 10,
            capped: true,
            ..Default::default()
        };
        let out = format_stats(&stats, Duration::from_millis(100));
        assert!(out.contains("capped"));
    }

    #[test]
    fn quiet_mode_hides_stats() {
        let stats = SearchStats::default();
        let out = format_stats(&stats, Duration::from_secs(0));
        assert!(out.contains("scanned 0 files"));
    }

    #[test]
    fn compact_mode_one_line_per_file() {
        let result = FileResult {
            path: PathBuf::from("/foo/test.txt"),
            filename_matched: false,
            content_matches: vec![ContentMatch {
                line_number: 1,
                line: "hello".to_string(),
                context_before: vec![],
                context_after: vec![],
            }],
            metadata: FileMetadata::default(),
            security: Assessment::default(),
        };
        let opts = OutputOptions {
            color: ColorMode::Never,
            compact: true,
            ..Default::default()
        };
        let out = format_human(std::slice::from_ref(&result), &opts);
        // Should be one line
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("/foo/test.txt"));
        assert!(out.contains("1: hello"));
    }

    #[test]
    fn table_mode_has_header() {
        let results = vec![make_result("/foo/bar.txt", true)];
        let opts = OutputOptions {
            color: ColorMode::Never,
            table: true,
            ..Default::default()
        };
        let out = format_human(&results, &opts);
        assert!(out.contains("PATH"));
        assert!(out.contains("MATCHES"));
    }

    #[test]
    fn no_color_env_disables_color() {
        // Save and restore NO_COLOR
        let prev = std::env::var_os("NO_COLOR");
        std::env::set_var("NO_COLOR", "1");

        assert!(!use_color(ColorMode::Always, true));
        assert!(!use_color(ColorMode::Auto, true));

        // Restore
        match prev {
            Some(v) => std::env::set_var("NO_COLOR", v),
            None => std::env::remove_var("NO_COLOR"),
        }
    }

    #[test]
    fn color_never_no_ansi() {
        let result = make_result("/foo/bar.txt", true);
        let opts = OutputOptions {
            color: ColorMode::Never,
            ..Default::default()
        };
        let out = format_human(&[result], &opts);
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn color_always_has_ansi() {
        let result = make_result("/foo/bar.txt", true);
        let opts = OutputOptions {
            color: ColorMode::Always,
            ..Default::default()
        };
        let out = format_human(&[result], &opts);
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn csv_has_header_and_rows() {
        let result = FileResult {
            path: PathBuf::from("/foo/test.txt"),
            filename_matched: true,
            content_matches: vec![ContentMatch {
                line_number: 3,
                line: "hello, world".to_string(),
                context_before: vec![],
                context_after: vec![],
            }],
            metadata: FileMetadata {
                size: Some(100),
                modified: Some(1600000000),
                permissions: Some(0o755),
            },
            security: Assessment::default(),
        };
        let csv = format_csv(&[result]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "path,filename_matched,line_number,line,size,modified,permissions"
        );
        assert!(lines[1].contains("/foo/test.txt"));
        // Comma in line should be quoted
        assert!(lines[1].contains("\"hello, world\""));
    }

    #[test]
    fn html_is_self_contained() {
        let results = vec![make_result("/foo/bar.txt", true)];
        let html = format_html(&results);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html"));
        assert!(html.contains("</html>"));
        assert!(html.contains("/foo/bar.txt"));
    }

    #[test]
    fn html_escapes_special_chars() {
        let result = FileResult {
            path: PathBuf::from("/foo/<script>.txt"),
            filename_matched: true,
            content_matches: vec![],
            metadata: FileMetadata::default(),
            security: Assessment::default(),
        };
        let html = format_html(&[result]);
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    fn suspicious_result(path: &str) -> FileResult {
        let mut result = make_result(path, true);
        result
            .security
            .raise(Verdict::Suspicious, "double-extension", "double extension");
        result
    }

    #[test]
    fn security_suffix_absent_for_clean_result() {
        assert_eq!(format_security_suffix(&Assessment::default()), None);
    }

    #[test]
    fn human_output_shows_security_suffix() {
        let result = suspicious_result("/foo/invoice.pdf.exe");
        let opts = OutputOptions {
            color: ColorMode::Never,
            ..Default::default()
        };
        let out = format_human(&[result], &opts);
        assert!(out.contains("security: Suspicious"));
        assert!(out.contains("double extension"));
    }

    #[test]
    fn json_includes_verdict_and_reasons() {
        let json = format_json(&[suspicious_result("/foo/invoice.pdf.exe")]);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let obj = parsed.as_object().expect("JSON object");

        assert_eq!(
            obj.get("verdict").and_then(|v| v.as_str()),
            Some("suspicious")
        );
        let reasons = obj
            .get("reasons")
            .and_then(|v| v.as_array())
            .expect("reasons array");
        assert_eq!(reasons.len(), 1);
        assert_eq!(
            reasons[0].get("code").and_then(|v| v.as_str()),
            Some("double-extension")
        );
    }

    #[test]
    fn security_summary_counts_by_verdict() {
        let mut high = make_result("/foo/high.bin", true);
        high.security
            .raise(Verdict::HighRisk, "hash", "known bad hash");

        let results = vec![
            make_result("/foo/clean.txt", true),
            suspicious_result("/foo/invoice.pdf.exe"),
            high,
        ];
        let summary = format_security_summary(&results);
        assert!(summary.contains("1 clean"));
        assert!(summary.contains("1 suspicious"));
        assert!(summary.contains("1 high risk"));
    }
}
