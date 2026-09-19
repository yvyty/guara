//! Tray companion logic.
//!
//! The Tauri shell is deliberately thin: icon state, tooltip text, recent
//! queries, pinned scopes, and the auto-start preference all live here so they
//! can be tested without launching a GUI.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ipc::{Scope, StatusReport, MAX_RECENTS};
use crate::security::{Assessment, Verdict};

/// What the tray icon shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrayState {
    /// Nothing running, last scan clean.
    #[default]
    Idle,
    /// The index is being built or walked.
    Indexing,
    /// The last assessment raised a signal.
    Threat,
}

impl TrayState {
    /// Stable name of the icon the shell should show.
    pub fn icon_name(self) -> &'static str {
        match self {
            TrayState::Idle => "tray-idle",
            TrayState::Indexing => "tray-indexing",
            TrayState::Threat => "tray-threat",
        }
    }

    /// Short state label for menus and tooltips.
    pub fn label(self) -> &'static str {
        match self {
            TrayState::Idle => "Idle",
            TrayState::Indexing => "Indexing",
            TrayState::Threat => "Threat detected",
        }
    }

    /// Tooltip text: state plus the index/roots summary.
    pub fn tooltip(self, status: &StatusReport) -> String {
        let roots = status.roots.len();
        let mut tooltip = format!(
            "Guará: {} | {} path(s) indexed across {} root(s)",
            self.label(),
            status.indexed_paths,
            roots
        );
        if status.watching {
            tooltip.push_str(" | watching");
        }
        tooltip
    }
}

/// Map a status report and the latest assessment to a tray state. A finding
/// outranks activity so a threat is never hidden by an indexing pass.
pub fn state_for(status: &StatusReport, assessment: Option<&Assessment>) -> TrayState {
    if assessment.is_some_and(|assessment| !assessment.is_clean()) {
        return TrayState::Threat;
    }
    if status.watching {
        return TrayState::Indexing;
    }
    match assessment.map(|assessment| assessment.verdict) {
        Some(Verdict::Suspicious) | Some(Verdict::HighRisk) => TrayState::Threat,
        _ => TrayState::Idle,
    }
}

/// Persisted tray preferences. Auto-start is off unless the user opts in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    /// Start the tray at login. Default: `false`.
    pub auto_start: bool,
    /// Scopes the user pinned, in insertion order.
    pub pinned_scopes: Vec<Scope>,
    /// Recent queries, newest first.
    pub recent_queries: Vec<String>,
    /// Root used when no scope is selected.
    pub last_root: Option<PathBuf>,
}

impl Preferences {
    /// Load preferences. A missing file is not an error: it yields defaults.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(serde_json::from_str(&text).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Save preferences, creating the parent directory when needed.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, text)
    }

    /// Flip auto-start and return the new value.
    pub fn toggle_auto_start(&mut self) -> bool {
        self.auto_start = !self.auto_start;
        self.auto_start
    }

    /// Record a query, newest first, without duplicates.
    pub fn remember_query(&mut self, query: &str) {
        let query = query.trim();
        if query.is_empty() {
            return;
        }
        self.recent_queries.retain(|existing| existing != query);
        self.recent_queries.insert(0, query.to_string());
        self.recent_queries.truncate(MAX_RECENTS);
    }

    /// Pin a scope, re-labelling it when the root is already pinned.
    pub fn pin_scope(&mut self, root: PathBuf, label: Option<String>) {
        let label = label.unwrap_or_else(|| scope_label(&root));
        match self
            .pinned_scopes
            .iter_mut()
            .find(|scope| scope.root == root)
        {
            Some(existing) => existing.label = label,
            None => self.pinned_scopes.push(Scope { root, label }),
        }
    }

    /// Forget a pinned scope. Returns `true` when something was removed.
    pub fn unpin_scope(&mut self, root: &Path) -> bool {
        let before = self.pinned_scopes.len();
        self.pinned_scopes.retain(|scope| scope.root != root);
        self.pinned_scopes.len() != before
    }

    /// Root to search: the first pinned scope, then the last used root.
    pub fn active_root(&self) -> Option<PathBuf> {
        self.pinned_scopes
            .first()
            .map(|scope| scope.root.clone())
            .or_else(|| self.last_root.clone())
    }

    /// Remember the root the palette searched last.
    pub fn set_last_root(&mut self, root: PathBuf) {
        self.last_root = Some(root);
    }
}

/// Default label for a scope: its last path segment.
pub fn scope_label(root: &Path) -> String {
    root.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.display().to_string())
}

/// Preferences file location: `<config_dir>/tray.json`.
pub fn default_preferences_path() -> Option<PathBuf> {
    let base = directories::ProjectDirs::from("", "", "guara")?;
    Some(base.config_dir().join("tray.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Reason, Verdict};

    fn threat() -> Assessment {
        Assessment {
            verdict: Verdict::Suspicious,
            reasons: vec![Reason {
                code: "double-extension".to_string(),
                message: "executable-looking extension".to_string(),
            }],
        }
    }

    #[test]
    fn idle_state_has_a_stable_icon_and_tooltip() {
        let status = StatusReport {
            index_path: Some(PathBuf::from("/tmp/index.db")),
            indexed_paths: 42,
            roots: vec![PathBuf::from("/tmp")],
            watching: false,
            socket: true,
        };
        let state = state_for(&status, None);
        assert_eq!(state, TrayState::Idle);
        assert_eq!(state.icon_name(), "tray-idle");
        let tooltip = state.tooltip(&status);
        assert!(tooltip.contains("Idle"));
        assert!(tooltip.contains("42 path(s)"));
        assert!(tooltip.contains("1 root(s)"));
        assert!(!tooltip.contains("watching"));
    }

    #[test]
    fn watching_state_reports_indexing() {
        let status = StatusReport {
            watching: true,
            roots: vec![PathBuf::from("/tmp")],
            ..StatusReport::default()
        };
        let state = state_for(&status, None);
        assert_eq!(state, TrayState::Indexing);
        assert_eq!(state.icon_name(), "tray-indexing");
        assert!(state.tooltip(&status).contains("watching"));
    }

    #[test]
    fn a_finding_outranks_indexing() {
        let status = StatusReport {
            watching: true,
            ..StatusReport::default()
        };
        let state = state_for(&status, Some(&threat()));
        assert_eq!(state, TrayState::Threat);
        assert_eq!(state.icon_name(), "tray-threat");
    }

    #[test]
    fn a_clean_assessment_stays_idle() {
        let state = state_for(&StatusReport::default(), Some(&Assessment::clean()));
        assert_eq!(state, TrayState::Idle);
    }

    #[test]
    fn auto_start_defaults_off_and_toggles() {
        let mut preferences = Preferences::default();
        assert!(!preferences.auto_start, "auto-start must default to off");
        assert!(preferences.toggle_auto_start());
        assert!(preferences.auto_start);
        assert!(!preferences.toggle_auto_start());
    }

    #[test]
    fn pinned_scopes_survive_a_save_and_load_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested").join("tray.json");

        let mut saved = Preferences::default();
        saved.pin_scope(PathBuf::from("/tmp/work"), None);
        saved.pin_scope(PathBuf::from("/tmp/clients"), Some("clients".to_string()));
        saved.remember_query("needle");
        saved.set_last_root(PathBuf::from("/tmp/work"));
        saved.toggle_auto_start();
        saved.save(&path).unwrap();

        // A restart loads the same state back.
        let loaded = Preferences::load(&path).unwrap();
        assert_eq!(loaded, saved);
        assert_eq!(loaded.pinned_scopes.len(), 2);
        assert_eq!(loaded.pinned_scopes[0].label, "work");
        assert_eq!(loaded.pinned_scopes[1].label, "clients");
        assert!(loaded.auto_start);
        assert_eq!(loaded.active_root(), Some(PathBuf::from("/tmp/work")));
    }

    #[test]
    fn missing_preferences_file_is_defaults() {
        let dir = tempfile::TempDir::new().unwrap();
        let loaded = Preferences::load(&dir.path().join("absent.json")).unwrap();
        assert_eq!(loaded, Preferences::default());
    }

    #[test]
    fn corrupt_preferences_fall_back_to_defaults() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("tray.json");
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(Preferences::load(&path).unwrap(), Preferences::default());
    }

    #[test]
    fn pinning_the_same_scope_updates_the_label() {
        let mut preferences = Preferences::default();
        preferences.pin_scope(PathBuf::from("/tmp/work"), None);
        preferences.pin_scope(PathBuf::from("/tmp/work"), Some("office".to_string()));
        assert_eq!(preferences.pinned_scopes.len(), 1);
        assert_eq!(preferences.pinned_scopes[0].label, "office");

        assert!(preferences.unpin_scope(Path::new("/tmp/work")));
        assert!(preferences.pinned_scopes.is_empty());
        assert!(!preferences.unpin_scope(Path::new("/tmp/work")));
    }

    #[test]
    fn active_root_falls_back_to_the_last_used_root() {
        let mut preferences = Preferences::default();
        assert_eq!(preferences.active_root(), None);
        preferences.set_last_root(PathBuf::from("/tmp/last"));
        assert_eq!(preferences.active_root(), Some(PathBuf::from("/tmp/last")));
        preferences.pin_scope(PathBuf::from("/tmp/pinned"), None);
        assert_eq!(
            preferences.active_root(),
            Some(PathBuf::from("/tmp/pinned")),
            "a pinned scope wins over the last root"
        );
    }

    #[test]
    fn recent_queries_are_bounded_and_deduplicated() {
        let mut preferences = Preferences::default();
        preferences.remember_query(" alpha ");
        preferences.remember_query("beta");
        preferences.remember_query("alpha");
        assert_eq!(
            preferences.recent_queries,
            vec!["alpha".to_string(), "beta".to_string()]
        );

        for index in 0..(MAX_RECENTS + 3) {
            preferences.remember_query(&format!("q{index}"));
        }
        assert_eq!(preferences.recent_queries.len(), MAX_RECENTS);
    }

    #[test]
    fn preferences_serialize_as_json() {
        let preferences = Preferences::default();
        let text = serde_json::to_string(&preferences).unwrap();
        assert!(text.contains("\"auto_start\":false"));
        assert_eq!(
            serde_json::from_str::<Preferences>(&text).unwrap(),
            preferences
        );
    }

    #[test]
    fn default_preferences_path_ends_with_tray_json() {
        if let Some(path) = default_preferences_path() {
            assert_eq!(path.file_name().unwrap().to_string_lossy(), "tray.json");
        }
    }
}
