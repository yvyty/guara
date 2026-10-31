//! Configuration system: XDG/AppData TOML config with defaults and flag overrides.
//!
//! Precedence: CLI flag > env > config file > built-in default.
//! (Env support is a stub for v0.1; only flag > file > default is wired.)

use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::security::HeuristicConfig;

/// Top-level config file.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct Config {
    pub search: SearchSection,
    /// Security heuristics. See [`HeuristicConfig`].
    pub security: HeuristicConfig,
}

/// `[search]` section.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct SearchSection {
    /// Global ignore patterns (glob syntax, e.g. `["*.tmp", "target"]`).
    pub ignore: Vec<String>,
    /// Number of worker threads. `None` = auto.
    pub threads: Option<usize>,
    /// Maximum file size in bytes for content search.
    pub max_file_size: Option<u64>,
    /// Maximum directory depth. `None` = unlimited.
    pub max_depth: Option<usize>,
    /// Follow symlinks.
    pub follow_symlinks: bool,
    /// Case-insensitive matching.
    pub case_insensitive: bool,
    /// Match whole words only.
    pub whole_word: bool,
    /// Number of context lines.
    pub context: usize,
}

/// Errors that can occur while loading config.
#[derive(Debug)]
pub enum ConfigError {
    /// Failed to read the file.
    Read(PathBuf, String),
    /// Failed to parse TOML.
    Parse(PathBuf, String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read(path, msg) => {
                write!(f, "cannot read config {}: {}", path.display(), msg)
            }
            ConfigError::Parse(path, msg) => {
                write!(f, "invalid config {}: {}", path.display(), msg)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Resolve the default config file path using the `directories` crate.
///
/// Returns `None` if the OS does not provide a config directory.
pub fn config_path() -> Option<PathBuf> {
    let proj = ProjectDirs::from("dev", "guara", "guara")?;
    Some(proj.config_dir().join("config.toml"))
}

/// Load config from a specific path.
///
/// A missing file returns `Config::default()` (no error).
/// An unreadable or unparseable file returns a `ConfigError`.
pub fn load_from(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let content = fs::read_to_string(path)
        .map_err(|e| ConfigError::Read(path.to_path_buf(), e.to_string()))?;
    toml::from_str(&content).map_err(|e| ConfigError::Parse(path.to_path_buf(), e.to_string()))
}

/// Load config from the default OS-specific path.
pub fn load() -> Result<Config, ConfigError> {
    match config_path() {
        Some(path) => load_from(&path),
        None => Ok(Config::default()),
    }
}

/// Effective search settings after merging config and CLI overrides.
///
/// For boolean fields: CLI `true` overrides config. CLI `false` falls back
/// to the config value.
#[derive(Debug, Clone)]
pub struct EffectiveSearch {
    pub ignore: Vec<String>,
    pub threads: Option<usize>,
    pub max_file_size: Option<u64>,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub case_insensitive: bool,
    pub whole_word: bool,
    pub context: usize,
}

impl Config {
    /// Merge config with CLI overrides. CLI values that are `Some` / `true`
    /// take precedence; absent CLI values fall back to config.
    pub fn effective_search(
        &self,
        max_depth: Option<usize>,
        follow_symlinks: bool,
        case_insensitive: bool,
        whole_word: bool,
        context: usize,
        ignore: Vec<String>,
    ) -> EffectiveSearch {
        let s = &self.search;
        EffectiveSearch {
            ignore: if ignore.is_empty() {
                s.ignore.clone()
            } else {
                ignore
            },
            threads: s.threads,
            max_file_size: s.max_file_size,
            max_depth: max_depth.or(s.max_depth),
            follow_symlinks: follow_symlinks || s.follow_symlinks,
            case_insensitive: case_insensitive || s.case_insensitive,
            whole_word: whole_word || s.whole_word,
            context: if context > 0 { context } else { s.context },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;
    use tempfile::TempDir;

    #[test]
    fn missing_file_uses_defaults() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.toml");
        let config = load_from(&path).expect("missing file should not error");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn valid_toml_loads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        stdfs::write(
            &path,
            r#"
[search]
ignore = ["*.tmp", "target"]
threads = 4
max_depth = 5
follow_symlinks = true
case_insensitive = true
context = 2
"#,
        )
        .unwrap();

        let config = load_from(&path).expect("valid TOML should load");
        assert_eq!(config.search.ignore, vec!["*.tmp", "target"]);
        assert_eq!(config.search.threads, Some(4));
        assert_eq!(config.search.max_depth, Some(5));
        assert!(config.search.follow_symlinks);
        assert!(config.search.case_insensitive);
        assert_eq!(config.search.context, 2);
    }

    #[test]
    fn invalid_toml_errors_with_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.toml");
        stdfs::write(&path, "this is not valid toml = = =").unwrap();

        let err = load_from(&path).unwrap_err();
        match err {
            ConfigError::Parse(p, _) => {
                assert_eq!(p, path);
            }
            other => panic!("expected Parse error, got: {other:?}"),
        }
    }

    #[test]
    fn unreadable_file_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("unreadable.toml");

        // Create a directory instead of a file to trigger a read error
        stdfs::create_dir(&path).unwrap();

        let err = load_from(&path);
        assert!(err.is_err());
    }

    #[test]
    fn flag_overrides_config() {
        let config = Config {
            search: SearchSection {
                max_depth: Some(3),
                follow_symlinks: false,
                case_insensitive: false,
                context: 1,
                ignore: vec!["*.tmp".to_string()],
                ..Default::default()
            },
            security: Default::default(),
        };

        let effective =
            config.effective_search(Some(10), true, true, false, 5, vec!["*.log".to_string()]);

        assert_eq!(effective.max_depth, Some(10));
        assert!(effective.follow_symlinks);
        assert!(effective.case_insensitive);
        assert!(!effective.whole_word);
        assert_eq!(effective.context, 5);
        assert_eq!(effective.ignore, vec!["*.log"]);
    }

    #[test]
    fn absent_flag_falls_back_to_config() {
        let config = Config {
            search: SearchSection {
                max_depth: Some(3),
                follow_symlinks: true,
                case_insensitive: true,
                context: 2,
                ignore: vec!["*.tmp".to_string()],
                ..Default::default()
            },
            security: Default::default(),
        };

        let effective = config.effective_search(None, false, false, false, 0, vec![]);

        assert_eq!(effective.max_depth, Some(3));
        assert!(effective.follow_symlinks);
        assert!(effective.case_insensitive);
        assert_eq!(effective.context, 2);
        assert_eq!(effective.ignore, vec!["*.tmp"]);
    }

    #[test]
    fn effective_search_keeps_threads_and_max_file_size() {
        let config = Config {
            search: SearchSection {
                threads: Some(4),
                max_file_size: Some(1024),
                ..Default::default()
            },
            security: Default::default(),
        };

        let effective = config.effective_search(None, false, false, false, 0, vec![]);

        assert_eq!(effective.threads, Some(4));
        assert_eq!(effective.max_file_size, Some(1024));
    }

    #[test]
    fn empty_config_section_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.toml");
        stdfs::write(&path, "").unwrap();

        let config = load_from(&path).expect("empty file should use defaults");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn partial_config_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("partial.toml");
        stdfs::write(&path, "[search]\nthreads = 8\n").unwrap();

        let config = load_from(&path).expect("partial config should load");
        assert_eq!(config.search.threads, Some(8));
        assert!(!config.search.follow_symlinks);
    }

    #[test]
    fn security_section_loads_and_defaults() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("security.toml");
        stdfs::write(
            &path,
            "[security]\nentropy_threshold = 6.5\nsuspicious_patterns = [\"evil\"]\n",
        )
        .unwrap();

        let config = load_from(&path).expect("security config should load");
        assert!((config.security.entropy_threshold - 6.5).abs() < f64::EPSILON);
        assert_eq!(config.security.suspicious_patterns, vec!["evil"]);
        // Fields not present in the file keep their documented defaults.
        assert!(config.security.enabled);
        assert_eq!(
            config.security.sample_limit,
            crate::security::DEFAULT_SAMPLE_LIMIT
        );
    }
}
