//! Pure terminal-UI state for the `guara tui` result browser.
//!
//! Everything here is terminal-agnostic: filtering, selection, scrolling, and
//! the preview text are plain data, so the behaviour can be unit-tested without
//! a real terminal. The binary crate owns input events and ratatui rendering.

use std::path::{Path, PathBuf};

use crate::search::FileResult;
use crate::security::{self, Assessment, HeuristicConfig};

/// Which pane owns the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Navigation keys move the selection.
    #[default]
    List,
    /// Printable keys extend the filter query.
    Filter,
}

/// What a preview line represents, so the renderer can style it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewKind {
    /// The path of the selected result.
    Path,
    /// Size / modified / permissions summary.
    Meta,
    /// A content match line.
    Match,
    /// A context line around a match.
    Context,
    /// Security verdict and reasons.
    Security,
    /// Result of an on-demand heuristic scan.
    Scan,
    /// Explanatory text (nothing to preview, filter note).
    Note,
}

/// One line of the preview pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewLine {
    pub kind: PreviewKind,
    pub text: String,
}

impl PreviewLine {
    fn new(kind: PreviewKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
        }
    }
}

/// Filterable, scrollable view over search results.
///
/// `selected` indexes `visible`, not `results`; use [`TuiState::selected`] to
/// get the index into the full result list.
#[derive(Debug, Clone)]
pub struct TuiState {
    results: Vec<FileResult>,
    filter: String,
    visible: Vec<usize>,
    selected: usize,
    offset: usize,
    viewport_rows: usize,
    mode: Mode,
    status: Option<String>,
    assessment: Option<Assessment>,
}

impl TuiState {
    /// Build the state over a result list. `viewport_rows` is how many list
    /// rows fit on screen; it is re-synced on every draw.
    pub fn new(results: Vec<FileResult>, viewport_rows: usize) -> Self {
        let visible = (0..results.len()).collect();
        let mut state = Self {
            results,
            filter: String::new(),
            visible,
            selected: 0,
            offset: 0,
            viewport_rows,
            mode: Mode::List,
            status: None,
            assessment: None,
        };
        state.clamp();
        state
    }

    /// Number of results before filtering.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Number of results matching the current filter.
    pub fn visible_count(&self) -> usize {
        self.visible.len()
    }

    /// The current filter query.
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// Which pane owns the keyboard.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Transient message shown in the footer.
    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Set the footer message.
    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status = Some(message.into());
    }

    /// Drop the footer message.
    pub fn clear_status(&mut self) {
        self.status = None;
    }

    /// Switch the keyboard to the filter box.
    pub fn enter_filter(&mut self) {
        self.mode = Mode::Filter;
    }

    /// Switch the keyboard back to list navigation, keeping the filter.
    pub fn leave_filter(&mut self) {
        self.mode = Mode::List;
    }

    /// Append a character to the filter and re-run it.
    pub fn push_filter(&mut self, c: char) {
        self.filter.push(c);
        self.refilter();
    }

    /// Remove the last character of the filter and re-run it.
    pub fn pop_filter(&mut self) {
        self.filter.pop();
        self.refilter();
    }

    /// Clear the filter and show every result again.
    pub fn clear_filter(&mut self) {
        if self.filter.is_empty() {
            return;
        }
        self.filter.clear();
        self.refilter();
    }

    /// Index into the unfiltered result list of the selected row.
    pub fn selected(&self) -> Option<usize> {
        self.visible.get(self.selected).copied()
    }

    /// The selected result.
    pub fn selected_result(&self) -> Option<&FileResult> {
        self.selected().and_then(|index| self.results.get(index))
    }

    /// A result by its index in the unfiltered list.
    pub fn result(&self, index: usize) -> Option<&FileResult> {
        self.results.get(index)
    }

    /// Path of the selected result, if any.
    pub fn selected_path(&self) -> Option<&Path> {
        self.selected_result().map(|result| result.path.as_path())
    }

    /// Scroll offset of the visible window.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// How many list rows fit on screen.
    pub fn viewport_rows(&self) -> usize {
        self.viewport_rows
    }

    /// Tell the state how many rows the list pane will draw. Keeps the
    /// selection inside the window.
    pub fn set_viewport_rows(&mut self, rows: usize) {
        self.viewport_rows = rows;
        self.clamp();
    }

    /// Move the selection by `delta` rows, clamped to the list bounds.
    pub fn move_selection(&mut self, delta: i64) {
        if self.visible.is_empty() {
            return;
        }
        let last = self.visible.len().saturating_sub(1) as i64;
        let next = (self.selected as i64 + delta).clamp(0, last);
        if next as usize == self.selected {
            return;
        }
        self.selected = next as usize;
        self.assessment = None;
        self.clamp();
    }

    /// Select the first result.
    pub fn select_first(&mut self) {
        if self.visible.is_empty() {
            return;
        }
        self.selected = 0;
        self.assessment = None;
        self.clamp();
    }

    /// Select the last result.
    pub fn select_last(&mut self) {
        if self.visible.is_empty() {
            return;
        }
        self.selected = self.visible.len().saturating_sub(1);
        self.assessment = None;
        self.clamp();
    }

    /// Move the selection up one page.
    pub fn page_up(&mut self) {
        let page = self.page_rows();
        self.move_selection(-page);
    }

    /// Move the selection down one page.
    pub fn page_down(&mut self) {
        let page = self.page_rows();
        self.move_selection(page);
    }

    /// The slice of `visible` rows currently on screen.
    pub fn window(&self) -> &[usize] {
        if self.visible.is_empty() {
            return &[];
        }
        let end = self
            .visible
            .len()
            .min(self.offset.saturating_add(self.viewport_rows.max(1)));
        let start = self.offset.min(end);
        &self.visible[start..end]
    }

    /// Preview lines for the selected result: path, metadata, security signal,
    /// then content matches with their context.
    pub fn preview(&self) -> Vec<PreviewLine> {
        let Some(result) = self.selected_result() else {
            return vec![PreviewLine::new(
                PreviewKind::Note,
                if self.results.is_empty() {
                    "no results"
                } else {
                    "no result matches the filter"
                },
            )];
        };

        let mut lines = vec![PreviewLine::new(
            PreviewKind::Path,
            result.path.display().to_string(),
        )];

        let meta = format_metadata(&result.metadata);
        if !meta.is_empty() {
            lines.push(PreviewLine::new(PreviewKind::Meta, meta));
        }

        if result.filename_matched {
            lines.push(PreviewLine::new(PreviewKind::Match, "name matched"));
        }

        if !result.security.is_clean() {
            lines.push(PreviewLine::new(
                PreviewKind::Security,
                format!("security: {}", result.security.verdict.as_str()),
            ));
            for reason in &result.security.reasons {
                lines.push(PreviewLine::new(
                    PreviewKind::Security,
                    format!("  {} ({})", reason.message, reason.code),
                ));
            }
        }

        if let Some(assessment) = &self.assessment {
            lines.push(PreviewLine::new(
                PreviewKind::Scan,
                format!("scan: {}", assessment.verdict.as_str()),
            ));
            for reason in &assessment.reasons {
                lines.push(PreviewLine::new(
                    PreviewKind::Scan,
                    format!("  {} ({})", reason.message, reason.code),
                ));
            }
        }

        for m in &result.content_matches {
            for context in &m.context_before {
                lines.push(PreviewLine::new(
                    PreviewKind::Context,
                    format!("{}| {}", context.line_number, context.line),
                ));
            }
            lines.push(PreviewLine::new(
                PreviewKind::Match,
                format!("{}| {}", m.line_number, m.line),
            ));
            for context in &m.context_after {
                lines.push(PreviewLine::new(
                    PreviewKind::Context,
                    format!("{}| {}", context.line_number, context.line),
                ));
            }
        }

        if lines.len() == 1 && !result.filename_matched {
            lines.push(PreviewLine::new(
                PreviewKind::Note,
                "no content preview for this hit",
            ));
        }

        lines
    }

    /// The last on-demand heuristic scan result, if any.
    pub fn assessment(&self) -> Option<&Assessment> {
        self.assessment.as_ref()
    }

    /// Run the always-on heuristics against the selected path using the same
    /// engine as `guara search` and keep the outcome for the preview pane.
    ///
    /// Returns the assessment, or `None` when nothing is selected.
    pub fn scan_selected(&mut self, cfg: &HeuristicConfig) -> Option<Assessment> {
        let path = self.selected_path()?.to_path_buf();
        let assessment = security::assess_file(&path, cfg);
        self.status = Some(format!(
            "scanned {}: {}",
            path.display(),
            assessment.verdict.as_str()
        ));
        self.assessment = Some(assessment.clone());
        Some(assessment)
    }

    /// Forget the previous on-demand scan (call when the selection moves).
    pub fn clear_assessment(&mut self) {
        self.assessment = None;
    }

    fn page_rows(&self) -> i64 {
        self.viewport_rows.max(1) as i64
    }

    /// Recompute `visible` from the filter, then keep the selection and scroll
    /// window valid.
    fn refilter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.visible = self
            .results
            .iter()
            .enumerate()
            .filter(|(_, result)| result_matches(result, &needle))
            .map(|(index, _)| index)
            .collect();
        self.selected = 0;
        self.offset = 0;
        self.assessment = None;
        self.clamp();
    }

    /// Keep `selected` inside `visible` and `offset` such that `selected` is
    /// inside the drawn window.
    fn clamp(&mut self) {
        if self.visible.is_empty() {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        self.selected = self.selected.min(self.visible.len() - 1);

        let rows = self.viewport_rows.max(1);
        if self.selected < self.offset {
            self.offset = self.selected;
        }
        if self.selected >= self.offset + rows {
            self.offset = self.selected + 1 - rows;
        }
        let max_offset = self.visible.len().saturating_sub(1);
        self.offset = self.offset.min(max_offset);
    }
}

/// Case-insensitive match of a result against a lowercased needle. The path,
/// the file name, and every matching line are searched.
fn result_matches(result: &FileResult, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if result
        .path
        .to_string_lossy()
        .to_lowercase()
        .contains(needle)
    {
        return true;
    }
    result
        .content_matches
        .iter()
        .any(|m| m.line.to_lowercase().contains(needle))
}

fn format_metadata(metadata: &crate::search::FileMetadata) -> String {
    let mut parts = Vec::new();
    if let Some(size) = metadata.size {
        parts.push(format_size(size));
    }
    if let Some(modified) = metadata.modified {
        parts.push(format!("modified {modified}"));
    }
    if let Some(permissions) = metadata.permissions {
        parts.push(format!("mode {permissions:o}"));
    }
    parts.join(", ")
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    if bytes >= MB {
        format!("{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Open a path in the user's editor (`$EDITOR`, then `$VISUAL`, then the OS
/// opener). Kept next to the state so the keybinding and the tests agree on
/// what "open" means.
pub fn open_command(path: &Path) -> Vec<String> {
    let mut words = Vec::new();
    if let Some(editor) = non_empty_env("EDITOR").or_else(|| non_empty_env("VISUAL")) {
        words.extend(editor.split_whitespace().map(|word| word.to_string()));
        words.push(path.display().to_string());
        return words;
    }

    let target = path.display().to_string();
    if cfg!(target_os = "macos") {
        words.push("open".to_string());
    } else if cfg!(target_os = "windows") {
        words.push("cmd".to_string());
        words.push("/C".to_string());
        words.push("start".to_string());
        words.push(String::new());
    } else {
        words.push("xdg-open".to_string());
    }
    words.push(target);
    words
}

fn non_empty_env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

/// Path of the file the TUI would open for a given selection.
pub fn open_target(results: &[FileResult], selected: Option<usize>) -> Option<PathBuf> {
    selected
        .and_then(|index| results.get(index))
        .map(|result| result.path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::{ContentMatch, FileMetadata};
    use crate::security::Verdict;

    fn result(path: &str, lines: &[&str]) -> FileResult {
        FileResult {
            path: PathBuf::from(path),
            filename_matched: false,
            content_matches: lines
                .iter()
                .enumerate()
                .map(|(index, line)| ContentMatch {
                    line_number: index + 1,
                    line: (*line).to_string(),
                    context_before: Vec::new(),
                    context_after: Vec::new(),
                })
                .collect(),
            metadata: FileMetadata {
                size: Some(2048),
                modified: Some(1_700_000_000),
                permissions: Some(0o644),
            },
            security: Assessment::clean(),
        }
    }

    fn state_with(names: &[&str]) -> TuiState {
        let results = names
            .iter()
            .map(|name| result(name, &[&format!("line in {name}")]))
            .collect();
        let mut state = TuiState::new(results, 10);
        state.set_viewport_rows(2);
        state
    }

    #[test]
    fn starts_with_every_result_visible_and_first_selected() {
        let state = state_with(&["a.txt", "b.txt", "c.txt"]);
        assert_eq!(state.result_count(), 3);
        assert_eq!(state.visible_count(), 3);
        assert_eq!(state.selected(), Some(0));
        assert_eq!(state.mode(), Mode::List);
    }

    #[test]
    fn selection_is_clamped_at_both_ends() {
        let mut state = state_with(&["a.txt", "b.txt", "c.txt"]);
        state.move_selection(-5);
        assert_eq!(state.selected(), Some(0));
        state.move_selection(99);
        assert_eq!(state.selected(), Some(2));
        state.select_last();
        assert_eq!(state.selected(), Some(2));
        state.select_first();
        assert_eq!(state.selected(), Some(0));
    }

    #[test]
    fn moving_the_selection_scrolls_the_window() {
        let mut state = state_with(&["a.txt", "b.txt", "c.txt", "d.txt"]);
        assert_eq!(state.offset(), 0);
        state.move_selection(3);
        assert_eq!(state.selected(), Some(3));
        assert_eq!(state.offset(), 2);
        assert_eq!(state.window(), &[2, 3]);

        state.select_first();
        assert_eq!(state.offset(), 0);
        assert_eq!(state.window(), &[0, 1]);
    }

    #[test]
    fn page_moves_by_the_viewport_height() {
        let mut state = state_with(&["a", "b", "c", "d", "e"]);
        state.set_viewport_rows(2);
        state.page_down();
        assert_eq!(state.selected(), Some(2));
        state.page_down();
        assert_eq!(state.selected(), Some(4));
        state.page_up();
        assert_eq!(state.selected(), Some(2));
    }

    #[test]
    fn typing_filters_case_insensitively() {
        let mut state = state_with(&["Alpha.rs", "beta.rs", "gamma.rs"]);
        state.enter_filter();
        assert_eq!(state.mode(), Mode::Filter);
        for c in "BETA".chars() {
            state.push_filter(c);
        }
        assert_eq!(state.filter(), "BETA");
        assert_eq!(state.visible_count(), 1);
        assert_eq!(state.selected_path().unwrap().to_str().unwrap(), "beta.rs");

        state.clear_filter();
        assert_eq!(state.visible_count(), 3);
        assert_eq!(state.filter(), "");
        state.leave_filter();
        assert_eq!(state.mode(), Mode::List);
    }

    #[test]
    fn backspace_widens_the_filter_again() {
        let mut state = state_with(&["alpha.rs", "beta.rs"]);
        state.enter_filter();
        for c in "alpha.rs".chars() {
            state.push_filter(c);
        }
        assert_eq!(state.visible_count(), 1);
        state.pop_filter();
        assert_eq!(state.filter(), "alpha.r");
        assert_eq!(state.visible_count(), 1);
    }

    #[test]
    fn filter_can_match_content_lines() {
        let mut state = state_with(&["one.txt", "two.txt"]);
        state.enter_filter();
        for c in "line in two".chars() {
            state.push_filter(c);
        }
        assert_eq!(state.visible_count(), 1);
        assert_eq!(state.selected_path().unwrap().to_str().unwrap(), "two.txt");
    }

    #[test]
    fn empty_match_set_is_safe_to_navigate() {
        let mut state = state_with(&["alpha.rs"]);
        state.enter_filter();
        for c in "nothing-matches".chars() {
            state.push_filter(c);
        }
        assert_eq!(state.visible_count(), 0);
        assert_eq!(state.selected(), None);
        assert_eq!(state.window(), &[] as &[usize]);
        state.move_selection(1);
        state.page_down();
        assert_eq!(state.selected(), None);
        let preview = state.preview();
        assert_eq!(preview.len(), 1);
        assert!(preview[0].text.contains("no result matches"));
    }

    #[test]
    fn preview_shows_path_metadata_and_context() {
        let results = vec![FileResult {
            path: PathBuf::from("src/main.rs"),
            filename_matched: true,
            content_matches: vec![ContentMatch {
                line_number: 12,
                line: "let needle = 1;".to_string(),
                context_before: vec![crate::search::ContextLine {
                    line_number: 11,
                    line: "fn main() {".to_string(),
                }],
                context_after: vec![crate::search::ContextLine {
                    line_number: 13,
                    line: "}".to_string(),
                }],
            }],
            metadata: FileMetadata {
                size: Some(10),
                modified: None,
                permissions: None,
            },
            security: Assessment {
                verdict: Verdict::Suspicious,
                reasons: vec![crate::security::Reason {
                    code: "double-extension".to_string(),
                    message: "executable-looking extension".to_string(),
                }],
            },
        }];
        let state = TuiState::new(results, 20);
        let preview = state.preview();
        let text: Vec<&str> = preview.iter().map(|line| line.text.as_str()).collect();

        assert!(text.contains(&"src/main.rs"));
        assert!(text.iter().any(|line| line.contains("10 B")));
        assert!(text.iter().any(|line| line.contains("name matched")));
        assert!(text
            .iter()
            .any(|line| line.contains("security: Suspicious")));
        assert!(text
            .iter()
            .any(|line| line.contains("executable-looking extension")));
        assert!(text.iter().any(|line| line.contains("11| fn main() {")));
        assert!(text.iter().any(|line| line.contains("12| let needle = 1;")));
        assert!(text.iter().any(|line| line.contains("13| }")));
    }

    #[test]
    fn scan_uses_the_heuristic_engine_on_the_selected_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("invoice.pdf.exe");
        std::fs::write(&path, b"stub").unwrap();

        let results = vec![FileResult {
            path: path.clone(),
            filename_matched: true,
            content_matches: Vec::new(),
            metadata: FileMetadata::default(),
            security: Assessment::clean(),
        }];
        let mut state = TuiState::new(results, 10);
        let assessment = state.scan_selected(&HeuristicConfig::default()).unwrap();
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert_eq!(state.assessment().unwrap().verdict, Verdict::Suspicious);
        assert!(state.status().unwrap().contains("Suspicious"));
        assert!(state
            .preview()
            .iter()
            .any(|line| line.kind == PreviewKind::Scan));
    }

    #[test]
    fn scan_without_selection_returns_none() {
        let mut state = TuiState::new(Vec::new(), 10);
        assert!(state.scan_selected(&HeuristicConfig::default()).is_none());
    }

    #[test]
    fn moving_the_selection_forgets_the_previous_scan() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("invoice.pdf.exe");
        std::fs::write(&path, b"stub").unwrap();

        let results = vec![
            FileResult {
                path,
                filename_matched: true,
                content_matches: Vec::new(),
                metadata: FileMetadata::default(),
                security: Assessment::clean(),
            },
            result("other.txt", &["x"]),
        ];
        let mut state = TuiState::new(results, 10);
        state.scan_selected(&HeuristicConfig::default()).unwrap();
        assert!(state.assessment().is_some());

        state.move_selection(1);
        assert_eq!(state.selected(), Some(1));
        assert!(state.assessment().is_none());
    }

    #[test]
    fn open_command_prefers_editor_then_os_opener() {
        let path = PathBuf::from("some file.txt");
        let previous = std::env::var_os("EDITOR");
        std::env::set_var("EDITOR", "vim -u NONE");
        let words = open_command(&path);
        assert_eq!(words[0], "vim");
        assert_eq!(words[1], "-u");
        assert_eq!(words[2], "NONE");
        assert_eq!(words[3], "some file.txt");

        std::env::remove_var("EDITOR");
        let os_words = open_command(&path);
        assert!(os_words.iter().any(|word| word == "some file.txt"));
        assert_ne!(os_words[0], "vim");

        if let Some(previous) = previous {
            std::env::set_var("EDITOR", previous);
        }
    }

    #[test]
    fn open_target_follows_the_selection() {
        let results = vec![result("a.txt", &["x"]), result("b.txt", &["y"])];
        assert_eq!(
            open_target(&results, Some(1)).unwrap(),
            PathBuf::from("b.txt")
        );
        assert!(open_target(&results, Some(9)).is_none());
        assert_eq!(open_target(&results, None), None);
    }
}
