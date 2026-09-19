//! Background mode: index-first search support, watching loop, and local
//! history.
//!
//! `guara serve` owns a [`WatchSession`] and applies each debounced batch to the
//! index. It stops when the caller sets the shutdown flag, always after the batch
//! currently being applied has committed, so a signal cannot truncate SQLite.
//! Signal installation lives in the binary; the loop only reads an
//! `AtomicBool`, which keeps it testable.
//!
//! OS service units (systemd/launchd/Windows Service) are out of scope for v0.1.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::index::{BatchReport, Change, IndexError, IndexStore};
use crate::watch::WatchSession;

/// How long the loop waits for the first event before checking the shutdown
/// flag again. Bounds how long a signal takes to be honoured while idle.
pub const DEFAULT_IDLE: Duration = Duration::from_millis(200);

/// Largest file considered for watched-term content matching.
const TERM_SCAN_LIMIT: u64 = 1024 * 1024;

/// Runtime configuration for the serve loop.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Roots to watch.
    pub roots: Vec<PathBuf>,
    /// Debounce window: a burst of writes becomes one transaction.
    pub debounce: Duration,
    /// Idle wait between shutdown-flag checks.
    pub idle: Duration,
}

impl ServeConfig {
    /// Config for `roots` with the default debounce and idle waits.
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            debounce: crate::watch::DEFAULT_DEBOUNCE,
            idle: DEFAULT_IDLE,
        }
    }
}

/// A watched term matched a newly indexed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedMatch {
    pub term: String,
    pub path: PathBuf,
}

/// What a serve run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ServeReport {
    /// Debounced batches committed.
    pub batches: usize,
    /// Rows touched across those batches.
    pub changes: usize,
    /// Watched-term hits, in event order.
    pub watched_matches: Vec<WatchedMatch>,
    /// Whether the loop ended because shutdown was requested.
    pub shutdown_requested: bool,
}

/// The serve loop: a watch session plus the store it feeds.
pub struct Server<'a> {
    store: &'a mut IndexStore,
    session: WatchSession,
    config: ServeConfig,
    terms: Vec<String>,
}

impl<'a> Server<'a> {
    /// Open a watch session on `config.roots`, excluding the index database
    /// itself, and prepare the watched-term list.
    pub fn new(
        store: &'a mut IndexStore,
        config: ServeConfig,
        terms: Vec<String>,
    ) -> Result<Self, IndexError> {
        let db_path = store.db_path().to_path_buf();
        let session = WatchSession::start(&config.roots, &db_path, config.debounce)?;
        Ok(Self {
            store,
            session,
            config,
            terms,
        })
    }

    /// The underlying watch session (roots, debounce).
    pub fn session(&self) -> &WatchSession {
        &self.session
    }

    /// Persisted watched terms in effect.
    pub fn terms(&self) -> &[String] {
        &self.terms
    }

    /// Run until `shutdown` is true.
    ///
    /// Each batch is applied to the index before the flag is checked again, so a
    /// signal arriving mid-batch still lets that transaction commit. `on_batch`
    /// is called once per committed batch for logging.
    pub fn run<F>(
        &mut self,
        shutdown: &AtomicBool,
        mut on_batch: F,
    ) -> Result<ServeReport, IndexError>
    where
        F: FnMut(&BatchReport, &[WatchedMatch]),
    {
        let mut report = ServeReport::default();

        loop {
            if shutdown.load(Ordering::SeqCst) {
                report.shutdown_requested = true;
                break;
            }

            let changes = self.session.wait_and_collect(self.config.idle);
            if changes.is_empty() {
                continue;
            }

            // One transaction per burst; it completes before the next check.
            let batch = self.store.apply_batch(&changes)?;
            let matches = watched_matches(&self.terms, &changes);

            report.batches += 1;
            report.changes += batch.touched();
            report.watched_matches.extend(matches.iter().cloned());

            on_batch(&batch, &matches);
        }

        Ok(report)
    }
}

/// Watched-term hits for a batch of changes. Removals never match.
pub fn watched_matches(terms: &[String], changes: &[Change]) -> Vec<WatchedMatch> {
    let mut matches = Vec::new();
    for change in changes {
        let path = match change {
            Change::Upsert(path) => path,
            Change::Rename { to, .. } => to,
            Change::Remove(_) => continue,
        };
        for term in terms {
            if path_matches_term(term, path) {
                matches.push(WatchedMatch {
                    term: term.clone(),
                    path: path.clone(),
                });
            }
        }
    }
    matches
}

/// Case-insensitive literal match against a file's name or the first MiB of its
/// contents. Local only: nothing is sent anywhere.
pub fn path_matches_term(term: &str, path: &Path) -> bool {
    let needle = term.trim().to_lowercase();
    if needle.is_empty() {
        return false;
    }

    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name.contains(&needle) {
        return true;
    }

    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= TERM_SCAN_LIMIT => {
            match std::fs::read(path) {
                Ok(bytes) => String::from_utf8_lossy(&bytes)
                    .to_lowercase()
                    .contains(&needle),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Watched terms match a file name or the first MiB of the contents,
    /// case-insensitively.
    #[test]
    fn path_matches_term_by_name_and_contents() {
        let dir = TempDir::new().unwrap();
        let named = dir.path().join("NEEDLE-report.txt");
        stdfs::write(&named, "nothing relevant").unwrap();
        let content = dir.path().join("plain.log");
        stdfs::write(&content, "a needle inside the haystack").unwrap();
        let other = dir.path().join("unrelated.txt");
        stdfs::write(&other, "nothing to see").unwrap();

        assert!(path_matches_term("needle", &named));
        assert!(path_matches_term("needle", &content));
        assert!(path_matches_term("NEEDLE", &content));
        assert!(!path_matches_term("needle", &other));
        assert!(!path_matches_term("   ", &other));
        assert!(!path_matches_term("needle", &dir.path().join("gone.txt")));
    }

    /// Removals are not reported as watched-term hits.
    #[test]
    fn watched_matches_ignores_removals() {
        let dir = TempDir::new().unwrap();
        let removed = dir.path().join("needle-removed.txt");
        let created = dir.path().join("needle-created.txt");
        stdfs::write(&created, "contents").unwrap();

        let changes = vec![
            Change::Remove(removed),
            Change::Upsert(created.clone()),
            Change::Rename {
                from: dir.path().join("old.txt"),
                to: created.clone(),
            },
        ];
        let matches = watched_matches(&["needle".to_string()], &changes);

        assert_eq!(
            matches,
            vec![
                WatchedMatch {
                    term: "needle".to_string(),
                    path: created.clone(),
                },
                WatchedMatch {
                    term: "needle".to_string(),
                    path: created,
                },
            ]
        );
    }

    /// The loop applies a batch, then stops on shutdown with a healthy database
    /// and the batch already committed.
    #[test]
    #[cfg_attr(
        any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"),
        ignore = "kqueue does not deliver events fast enough to assert within the test timeout"
    )]
    fn server_commits_batches_then_stops_cleanly() {
        let dir = TempDir::new().unwrap();
        let watched = dir.path().join("watched");
        stdfs::create_dir(&watched).unwrap();
        let db = dir.path().join("index.db");
        let store = IndexStore::open(&db).unwrap();

        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let watched_root = watched.clone();

        let handle = std::thread::spawn(move || {
            let mut store = store;
            let mut server = Server::new(
                &mut store,
                ServeConfig {
                    roots: vec![watched_root],
                    debounce: Duration::from_millis(100),
                    idle: DEFAULT_IDLE,
                },
                vec!["needle".to_string()],
            )
            .unwrap();

            let report = server
                .run(&flag, |batch, matches| {
                    let _ = tx.send((batch.clone(), matches.to_vec()));
                })
                .unwrap();

            (store, report)
        });

        // Give the watch session time to register, then create a matching file.
        std::thread::sleep(Duration::from_secs(1));
        stdfs::write(watched.join("needle.txt"), "a needle in here\n").unwrap();

        let (batch, matches) = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the watcher commits a batch");
        assert_eq!(batch.upserts, 1);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].term, "needle");

        shutdown.store(true, Ordering::SeqCst);
        let (store, report) = handle.join().unwrap();

        assert!(report.shutdown_requested);
        assert!(report.batches >= 1);
        assert!(report.changes >= 1);
        assert!(!report.watched_matches.is_empty());
        assert!(store.path_count().unwrap() >= 1);
        assert!(
            store.integrity_ok().unwrap(),
            "shutdown must not truncate SQLite"
        );
    }
}
