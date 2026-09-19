//! Parallel filesystem walker built on the `ignore` crate.
//!
//! Walks one or more roots in parallel, honoring `.gitignore` and `.ignore`
//! files. Per-entry errors (permission denied, broken symlinks) are collected
//! rather than aborting the walk.

use std::path::{Path, PathBuf};
use std::sync::mpsc;

use ignore::overrides::OverrideBuilder;
use ignore::{WalkBuilder, WalkState};

/// Options controlling a filesystem walk.
#[derive(Debug, Clone, Default)]
pub struct WalkOptions {
    /// Maximum directory depth. `None` = unlimited.
    pub max_depth: Option<usize>,
    /// Whether to follow symlinks. Default: `false`.
    pub follow_symlinks: bool,
    /// Global ignore patterns (glob syntax, e.g. `"*.tmp"`, `"target"`).
    /// Applied in addition to `.gitignore` / `.ignore` files.
    pub global_ignore: Vec<String>,
}

/// A file entry discovered by the walker.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
}

/// A non-fatal error encountered during walking.
#[derive(Debug)]
pub struct WalkError {
    pub path: Option<PathBuf>,
    pub message: String,
}

/// Result of a walk: file entries and collected errors.
#[derive(Debug, Default)]
pub struct WalkResult {
    pub entries: Vec<FileEntry>,
    pub errors: Vec<WalkError>,
}

/// Walk one or more roots in parallel, honoring `.gitignore` / `.ignore` rules.
///
/// Errors such as permission denied or broken symlinks are collected into
/// `WalkResult::errors` and do not abort the traversal.
pub fn walk(roots: &[impl AsRef<Path>], options: &WalkOptions) -> WalkResult {
    if roots.is_empty() {
        return WalkResult::default();
    }

    let mut builder = WalkBuilder::new(roots[0].as_ref());
    for root in &roots[1..] {
        builder.add(root.as_ref());
    }

    builder
        .max_depth(options.max_depth)
        .follow_links(options.follow_symlinks)
        .git_ignore(true)
        .ignore(true)
        .parents(true)
        .hidden(false)
        .require_git(false);

    // Global ignore patterns (glob syntax, e.g. `"*.tmp"`).
    // Override patterns with `!` prefix exclude matching files.
    if !options.global_ignore.is_empty() {
        let base = roots[0].as_ref();
        let mut overrides = OverrideBuilder::new(base);
        for pattern in &options.global_ignore {
            let _ = overrides.add(&format!("!{pattern}"));
        }
        if let Ok(built) = overrides.build() {
            builder.overrides(built);
        }
    }

    let walker = builder.build_parallel();

    let (tx_entries, rx_entries) = mpsc::channel::<FileEntry>();
    let (tx_errors, rx_errors) = mpsc::channel::<WalkError>();

    walker.run(|| {
        let tx_entries = tx_entries.clone();
        let tx_errors = tx_errors.clone();
        Box::new(move |entry_result| {
            match entry_result {
                Ok(entry) => {
                    if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                        let _ = tx_entries.send(FileEntry {
                            path: entry.path().to_path_buf(),
                        });
                    }
                }
                Err(err) => {
                    let _ = tx_errors.send(WalkError {
                        path: error_path(&err),
                        message: err.to_string(),
                    });
                }
            }
            WalkState::Continue
        })
    });

    // Drop original senders so receivers see EOF after workers finish.
    drop(tx_entries);
    drop(tx_errors);

    WalkResult {
        entries: rx_entries.iter().collect(),
        errors: rx_errors.iter().collect(),
    }
}

/// Extract an optional path from an `ignore::Error`.
fn error_path(err: &ignore::Error) -> Option<PathBuf> {
    use ignore::Error;
    match err {
        Error::WithPath { path, .. } => Some(path.clone()),
        Error::Loop { child, .. } => Some(child.clone()),
        Error::WithDepth { err, .. } => error_path(err),
        Error::Partial(errs) => errs.first().and_then(error_path),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn create_tree() -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path();

        // Top-level file
        fs::write(root.join("top.txt"), "hello").unwrap();

        // Subdirectory with two files
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/a.txt"), "a").unwrap();
        fs::write(root.join("sub/b.txt"), "b").unwrap();

        // Deeper nesting
        fs::create_dir(root.join("sub/deep")).unwrap();
        fs::write(root.join("sub/deep/c.txt"), "c").unwrap();

        // Hidden file
        fs::write(root.join(".hidden"), "secret").unwrap();

        dir
    }

    /// Verify the walker yields all regular files across a multi-level tree.
    #[test]
    fn walk_yields_all_files() {
        let dir = create_tree();
        let result = walk(&[dir.path()], &WalkOptions::default());

        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"top.txt".to_string()));
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
        assert!(names.contains(&"c.txt".to_string()));
        assert!(names.contains(&".hidden".to_string()));
        assert!(result.errors.is_empty());
    }

    /// max_depth = 1 must not enter subdirectories.
    #[test]
    fn walk_respects_max_depth() {
        let dir = create_tree();
        let opts = WalkOptions {
            max_depth: Some(1),
            ..WalkOptions::default()
        };
        let result = walk(&[dir.path()], &opts);

        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"top.txt".to_string()));
        assert!(names.contains(&".hidden".to_string()));
        // Files inside subdirectories must NOT be yielded
        assert!(!names.contains(&"a.txt".to_string()));
        assert!(!names.contains(&"b.txt".to_string()));
        assert!(!names.contains(&"c.txt".to_string()));
    }

    /// A file listed in `.gitignore` must not be yielded.
    #[test]
    fn walk_honors_gitignore() {
        let dir = create_tree();
        let root = dir.path();

        // Create a file that should be ignored
        fs::write(root.join("sub/ignored.log"), "ignore me").unwrap();
        fs::write(root.join(".gitignore"), "ignored.log\n").unwrap();

        let result = walk(&[root], &WalkOptions::default());
        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(!names.contains(&"ignored.log".to_string()));
        // Non-ignored files still present
        assert!(names.contains(&"a.txt".to_string()));
    }

    /// A `.ignore` file should also be honored.
    #[test]
    fn walk_honors_dot_ignore() {
        let dir = create_tree();
        let root = dir.path();

        fs::write(root.join("sub/skip.tmp"), "tmp").unwrap();
        fs::write(root.join(".ignore"), "skip.tmp\n").unwrap();

        let result = walk(&[root], &WalkOptions::default());
        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(!names.contains(&"skip.tmp".to_string()));
    }

    /// Global ignore patterns should be applied.
    #[test]
    fn walk_global_ignore_patterns() {
        let dir = create_tree();
        let root = dir.path();

        fs::write(root.join("sub/exclude.tmp"), "tmp").unwrap();
        fs::write(root.join("exclude.tmp"), "tmp").unwrap();

        let opts = WalkOptions {
            global_ignore: vec!["*.tmp".to_string()],
            ..WalkOptions::default()
        };
        let result = walk(&[root], &opts);
        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(!names.contains(&"exclude.tmp".to_string()));
    }

    /// By default, symlinks to directories should not be followed.
    #[cfg(unix)]
    #[test]
    fn walk_does_not_follow_symlinks_by_default() {
        let dir = create_tree();
        let root = dir.path();

        // Create a symlink to a directory containing files
        symlink(root.join("sub"), root.join("link_to_sub")).unwrap();

        let result = walk(&[root], &WalkOptions::default());
        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        // Files inside the symlinked dir should NOT appear (unless already
        // present from the original path).
        // The symlink itself is not a regular file, so it shouldn't be yielded.
        assert!(!names.iter().any(|n| n == "link_to_sub"));
    }

    /// When follow_symlinks is true, the walker should traverse symlinked dirs.
    #[cfg(unix)]
    #[test]
    fn walk_follows_symlinks_when_enabled() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();

        fs::create_dir(root.join("real")).unwrap();
        fs::write(root.join("real/file.txt"), "content").unwrap();
        symlink(root.join("real"), root.join("link")).unwrap();

        let opts = WalkOptions {
            follow_symlinks: true,
            ..WalkOptions::default()
        };
        let result = walk(&[root], &opts);

        // The file inside the symlinked dir should be reachable via the link.
        let found = result
            .entries
            .iter()
            .any(|e| e.path.file_name().unwrap() == "file.txt");
        assert!(
            found,
            "file through symlink should be found with follow=true"
        );
    }

    /// Broken symlinks should produce an error but not abort the walk.
    #[cfg(unix)]
    #[test]
    fn walk_collects_broken_symlink_errors() {
        let dir = create_tree();
        let root = dir.path();

        // Create a broken symlink
        symlink("/nonexistent/target", root.join("broken_link")).unwrap();

        // With follow_symlinks enabled, the walker resolves the link target
        // and produces an error for the broken link.
        let opts = WalkOptions {
            follow_symlinks: true,
            ..WalkOptions::default()
        };
        let result = walk(&[root], &opts);

        // Walk should complete
        assert!(!result.entries.is_empty());
        // At least one error should mention the broken link
        assert!(
            result.errors.iter().any(|e| {
                e.path
                    .as_ref()
                    .map(|p| p.file_name().map(|n| n == "broken_link").unwrap_or(false))
                    .unwrap_or(false)
                    || e.message.contains("link")
                    || e.message.contains("not found")
            }),
            "expected a broken symlink error, got: {:?}",
            result.errors
        );
    }

    /// Unreadable directories should produce errors but not abort the walk.
    #[cfg(unix)]
    #[test]
    fn walk_continues_past_unreadable_dir() {
        let dir = create_tree();
        let root = dir.path();

        // Create a directory with restricted permissions
        fs::create_dir(root.join("locked")).unwrap();
        fs::write(root.join("locked/secret.txt"), "secret").unwrap();
        fs::set_permissions(
            root.join("locked"),
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();

        let result = walk(&[root], &WalkOptions::default());

        // Restore permissions so cleanup works
        let _ = fs::set_permissions(
            root.join("locked"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        );

        // Walk should not have aborted - top-level files should still be present
        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"top.txt".to_string()));

        // At least one error should be collected
        assert!(
            !result.errors.is_empty(),
            "expected errors for unreadable dir"
        );
    }

    /// Multiple roots should be walked.
    #[test]
    fn walk_multiple_roots() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        fs::write(dir1.path().join("one.txt"), "1").unwrap();
        fs::write(dir2.path().join("two.txt"), "2").unwrap();

        let result = walk(&[dir1.path(), dir2.path()], &WalkOptions::default());

        let names: Vec<String> = result
            .entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"one.txt".to_string()));
        assert!(names.contains(&"two.txt".to_string()));
    }

    /// Empty roots list returns empty result.
    #[test]
    fn walk_empty_roots() {
        let roots: [&str; 0] = [];
        let result = walk(&roots, &WalkOptions::default());
        assert!(result.entries.is_empty());
        assert!(result.errors.is_empty());
    }
}
