//! Filesystem watching for the persistent index.
//!
//! `notify` events are collected into a debounced batch and applied as a single
//! SQLite transaction ([`IndexStore::apply_batch`]). Nothing here mutates the
//! user's files; events only update the index.
//!
//! Platform note: the underlying watcher is an OS facility (FSEvents, inotify,
//! ReadDirectoryChangesW). Backends coalesce or drop metadata-only events
//! differently, so the event-to-change mapping is a pure function
//! ([`map_event`]) that is tested directly, while tests that need real events
//! use generous timeouts and an explicit `#[ignore]` reason where the platform
//! watcher is unreliable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::index::{canonicalize, database_files, BatchReport, Change, IndexError, IndexStore};

/// Default debounce window. A burst of writes inside this window becomes one
/// transaction.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(250);

/// A live watcher over one or more roots.
pub struct WatchSession {
    /// Kept alive for as long as the session lives; dropping it stops events.
    _watcher: RecommendedWatcher,
    rx: Receiver<notify::Result<Event>>,
    roots: Vec<PathBuf>,
    debounce: Duration,
    /// Paths that are never indexed: the database and its journal siblings.
    /// Watching a root that contains the data directory (for example `$HOME`)
    /// would otherwise feed the index's own writes back into the index.
    excluded: Vec<PathBuf>,
}

impl WatchSession {
    /// Start watching `roots` recursively. `db_path` and its `-wal`, `-shm`,
    /// and `-journal` siblings are excluded.
    pub fn start(
        roots: &[PathBuf],
        db_path: &Path,
        debounce: Duration,
    ) -> Result<Self, IndexError> {
        let Some(first) = roots.first() else {
            return Err(IndexError::Io(
                PathBuf::from("."),
                "no roots to watch".to_string(),
            ));
        };

        let (tx, rx) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            move |result: notify::Result<Event>| {
                // Send failures only mean the session was dropped.
                let _ = tx.send(result);
            },
            notify::Config::default(),
        )
        .map_err(|e| IndexError::Io(first.clone(), e.to_string()))?;

        let mut canonical_roots = Vec::with_capacity(roots.len());
        for root in roots {
            let root = canonicalize(root);
            let mode = if root.is_dir() {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };
            watcher
                .watch(&root, mode)
                .map_err(|e| IndexError::Io(root.clone(), e.to_string()))?;
            canonical_roots.push(root);
        }

        let excluded = database_files(db_path);

        Ok(Self {
            _watcher: watcher,
            rx,
            roots: canonical_roots,
            debounce,
            excluded,
        })
    }

    /// Canonicalized roots being watched.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Configured debounce window.
    pub fn debounce(&self) -> Duration {
        self.debounce
    }

    /// Collect events until the watcher is quiet for the debounce window.
    pub fn collect(&self) -> Vec<Change> {
        self.drain(None)
    }

    /// Wait up to `idle` for the first event, then debounce the burst that
    /// follows. Returns an empty list when nothing arrives.
    pub fn wait_and_collect(&self, idle: Duration) -> Vec<Change> {
        match self.rx.recv_timeout(idle) {
            Ok(Ok(event)) => self.drain(Some(event)),
            Ok(Err(err)) => {
                tracing::debug!(error = %err, "watch error");
                Vec::new()
            }
            Err(_) => Vec::new(),
        }
    }

    /// Apply everything pending as one transaction.
    pub fn drain_into(&self, store: &mut IndexStore) -> Result<BatchReport, IndexError> {
        let changes = self.collect();
        apply(store, changes)
    }

    /// Wait for a burst, then apply it as one transaction.
    pub fn wait_and_drain(
        &self,
        store: &mut IndexStore,
        idle: Duration,
    ) -> Result<BatchReport, IndexError> {
        let changes = self.wait_and_collect(idle);
        apply(store, changes)
    }

    fn drain(&self, first: Option<Event>) -> Vec<Change> {
        let mut changes = Vec::new();
        let mut pending_from: Option<PathBuf> = None;
        let mut next = first;
        let mut deadline = Instant::now() + self.debounce;

        loop {
            match next.take() {
                Some(event) => {
                    changes.extend(map_event(
                        &event,
                        &self.roots,
                        &self.excluded,
                        &mut pending_from,
                    ));
                    // Each event restarts the window, so a burst settles.
                    deadline = Instant::now() + self.debounce;
                }
                None => {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    match self.rx.recv_timeout(deadline - now) {
                        Ok(Ok(event)) => next = Some(event),
                        Ok(Err(err)) => {
                            tracing::debug!(error = %err, "watch error");
                        }
                        Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
                            break;
                        }
                    }
                }
            }
        }

        coalesce(changes)
    }
}

fn apply(store: &mut IndexStore, changes: Vec<Change>) -> Result<BatchReport, IndexError> {
    if changes.is_empty() {
        return Ok(BatchReport::default());
    }
    store.apply_batch(&changes)
}

/// Map one `notify` event to index changes.
///
/// Create and data/metadata modifications upsert, removals delete, and rename
/// events move the row. Events outside the watched roots, and events for the
/// index database itself, are ignored.
pub fn map_event(
    event: &Event,
    roots: &[PathBuf],
    excluded: &[PathBuf],
    pending_from: &mut Option<PathBuf>,
) -> Vec<Change> {
    let mut changes = Vec::new();

    if matches!(event.kind, EventKind::Access(_)) {
        return changes;
    }

    let relevant: Vec<&PathBuf> = event
        .paths
        .iter()
        .filter(|path| is_relevant(path, roots, excluded))
        .collect();

    match &event.kind {
        EventKind::Access(_) => {}
        EventKind::Remove(_) => {
            for path in &relevant {
                changes.push(Change::Remove((*path).clone()));
            }
        }
        EventKind::Create(_) => {
            for path in &relevant {
                changes.push(Change::Upsert((*path).clone()));
            }
        }
        // A rename may arrive as a From/To pair, as one Both event, or (some
        // backends) as a plain remove plus create.
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
            if let Some(path) = relevant.first() {
                *pending_from = Some((*path).clone());
            }
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            for path in &relevant {
                match pending_from.take() {
                    Some(from) => changes.push(Change::Rename {
                        from,
                        to: (*path).clone(),
                    }),
                    None => changes.push(Change::Upsert((*path).clone())),
                }
            }
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            match (event.paths.first(), event.paths.get(1)) {
                (Some(from), Some(to)) => changes.push(Change::Rename {
                    from: from.clone(),
                    to: to.clone(),
                }),
                _ => {
                    for path in &relevant {
                        changes.push(Change::Upsert((*path).clone()));
                    }
                }
            }
        }
        // Name(Any)/Name(Other), data changes, metadata changes (chmod), and
        // undifferentiated modifications all refresh the row from disk.
        EventKind::Modify(_) => {
            for path in &relevant {
                changes.push(Change::Upsert((*path).clone()));
            }
        }
        EventKind::Any | EventKind::Other => {
            for path in &relevant {
                changes.push(Change::Upsert((*path).clone()));
            }
        }
    }

    changes
}

/// Whether an event path is inside a watched root and is not the index DB.
fn is_relevant(path: &Path, roots: &[PathBuf], excluded: &[PathBuf]) -> bool {
    if excluded.iter().any(|excluded| path == excluded) {
        return false;
    }
    roots.iter().any(|root| path.starts_with(root))
}

/// Keep the last operation per path so a burst of writes collapses. Renames are
/// keyed by destination.
fn coalesce(changes: Vec<Change>) -> Vec<Change> {
    let mut order: Vec<PathBuf> = Vec::new();
    let mut by_path: HashMap<PathBuf, Change> = HashMap::new();

    for change in changes {
        let key = match &change {
            Change::Upsert(path) | Change::Remove(path) => path.clone(),
            Change::Rename { from, to } => {
                // The source row goes away; make sure that removal survives
                // even when an upsert for the same path is also queued.
                by_path.remove(from);
                to.clone()
            }
        };
        if !by_path.contains_key(&key) {
            order.push(key.clone());
        }
        by_path.insert(key, change);
    }

    order
        .into_iter()
        .filter_map(|key| by_path.remove(&key))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::IndexQuery;
    use notify::event::EventAttributes;
    use notify::event::{AccessKind, CreateKind, DataChange, MetadataKind, RemoveKind};
    use std::fs as stdfs;
    use tempfile::TempDir;

    fn event(kind: EventKind, paths: &[&Path]) -> Event {
        Event {
            kind,
            paths: paths.iter().map(|path| path.to_path_buf()).collect(),
            attrs: EventAttributes::new(),
        }
    }

    fn watched_roots(dir: &TempDir) -> Vec<PathBuf> {
        vec![canonicalize(dir.path())]
    }

    /// Event paths arrive canonicalized by the backend, so tests build their
    /// paths from the canonical root too.
    fn file_in(dir: &TempDir, name: &str) -> PathBuf {
        canonicalize(dir.path()).join(name)
    }

    /// Files created under a watched root are indexed.
    #[test]
    #[cfg_attr(
        any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"),
        ignore = "kqueue does not deliver events fast enough to assert within the test timeout"
    )]
    fn watcher_observes_created_files_in_one_batch() {
        let dir = TempDir::new().unwrap();
        let mut store = IndexStore::open_in_memory().unwrap();
        let session = WatchSession::start(
            &watched_roots(&dir),
            store.db_path(),
            Duration::from_millis(100),
        )
        .unwrap();

        stdfs::write(dir.path().join("a.txt"), "a").unwrap();
        stdfs::write(dir.path().join("b.txt"), "b").unwrap();
        stdfs::write(dir.path().join("c.txt"), "c").unwrap();

        let report = session
            .wait_and_drain(&mut store, Duration::from_secs(20))
            .unwrap();

        assert_eq!(
            store.path_count().unwrap(),
            3,
            "every created file is indexed"
        );
        assert_eq!(store.batch_commits(), 1, "a burst becomes one transaction");
        assert_eq!(report.upserts, 3);
    }

    /// Deleting a file removes its row.
    #[test]
    #[cfg_attr(
        any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"),
        ignore = "kqueue does not deliver events fast enough to assert within the test timeout"
    )]
    fn watcher_removes_rows_for_deleted_files() {
        let dir = TempDir::new().unwrap();
        let mut store = IndexStore::open_in_memory().unwrap();
        let session = WatchSession::start(
            &watched_roots(&dir),
            store.db_path(),
            Duration::from_millis(100),
        )
        .unwrap();

        let file = dir.path().join("gone.txt");
        stdfs::write(&file, "bye").unwrap();
        session
            .wait_and_drain(&mut store, Duration::from_secs(20))
            .unwrap();
        assert_eq!(store.path_count().unwrap(), 1);

        stdfs::remove_file(&file).unwrap();
        session
            .wait_and_drain(&mut store, Duration::from_secs(20))
            .unwrap();

        assert_eq!(store.path_count().unwrap(), 0);
    }

    /// Renaming a file leaves the row at the new path. Backends
    /// report renames differently, so this asserts the end state.
    #[test]
    #[cfg_attr(
        any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"),
        ignore = "kqueue does not deliver events fast enough to assert within the test timeout"
    )]
    fn watcher_follows_renames() {
        let dir = TempDir::new().unwrap();
        let mut store = IndexStore::open_in_memory().unwrap();
        let session = WatchSession::start(
            &watched_roots(&dir),
            store.db_path(),
            Duration::from_millis(100),
        )
        .unwrap();

        stdfs::write(dir.path().join("before.txt"), "content").unwrap();
        session
            .wait_and_drain(&mut store, Duration::from_secs(20))
            .unwrap();

        stdfs::rename(dir.path().join("before.txt"), dir.path().join("after.txt")).unwrap();
        session
            .wait_and_drain(&mut store, Duration::from_secs(20))
            .unwrap();

        let rows = store.query(&IndexQuery::default()).unwrap();
        let names: Vec<String> = rows
            .iter()
            .map(|row| row.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["after.txt".to_string()]);
    }

    /// Permission changes refresh the row. FSEvents is unreliable for
    /// metadata-only events, hence the explicit ignore on macOS.
    #[test]
    #[cfg(unix)]
    #[cfg_attr(
        target_os = "macos",
        ignore = "FSEvents does not reliably report chmod; modify_events_upsert covers the mapping"
    )]
    fn watcher_observes_permission_changes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let mut store = IndexStore::open_in_memory().unwrap();
        let session = WatchSession::start(
            &watched_roots(&dir),
            store.db_path(),
            Duration::from_millis(100),
        )
        .unwrap();

        let file = dir.path().join("mode.txt");
        stdfs::write(&file, "content").unwrap();
        session
            .wait_and_drain(&mut store, Duration::from_secs(20))
            .unwrap();

        stdfs::set_permissions(&file, stdfs::Permissions::from_mode(0o444)).unwrap();
        session
            .wait_and_drain(&mut store, Duration::from_secs(20))
            .unwrap();

        let rows = store.query(&IndexQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].mode.unwrap() & 0o777, 0o444);
    }

    /// Create events become upserts.
    #[test]
    fn create_event_upserts() {
        let dir = TempDir::new().unwrap();
        let file = file_in(&dir, "new.txt");
        let mut pending = None;

        let changes = map_event(
            &event(EventKind::Create(CreateKind::File), &[&file]),
            &watched_roots(&dir),
            &[],
            &mut pending,
        );

        assert_eq!(changes, vec![Change::Upsert(file)]);
    }

    /// Data and metadata (permission) changes become upserts.
    #[test]
    fn modify_events_upsert() {
        let dir = TempDir::new().unwrap();
        let file = file_in(&dir, "data.txt");
        let roots = watched_roots(&dir);

        for kind in [
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Permissions)),
            EventKind::Any,
        ] {
            let mut pending = None;
            let changes = map_event(&event(kind, &[&file]), &roots, &[], &mut pending);
            assert_eq!(changes, vec![Change::Upsert(file.clone())], "kind {kind:?}");
        }
    }

    /// Remove events become removes.
    #[test]
    fn remove_event_removes() {
        let dir = TempDir::new().unwrap();
        let file = file_in(&dir, "old.txt");
        let mut pending = None;

        let changes = map_event(
            &event(EventKind::Remove(RemoveKind::File), &[&file]),
            &watched_roots(&dir),
            &[],
            &mut pending,
        );

        assert_eq!(changes, vec![Change::Remove(file)]);
    }

    /// A From/To rename pair becomes one rename change.
    #[test]
    fn rename_from_then_to_becomes_a_rename() {
        let dir = TempDir::new().unwrap();
        let from = file_in(&dir, "old.txt");
        let to = file_in(&dir, "new.txt");
        let roots = watched_roots(&dir);
        let mut pending = None;

        let first = map_event(
            &event(
                EventKind::Modify(ModifyKind::Name(RenameMode::From)),
                &[&from],
            ),
            &roots,
            &[],
            &mut pending,
        );
        assert!(first.is_empty());
        assert_eq!(pending, Some(from.clone()));

        let second = map_event(
            &event(EventKind::Modify(ModifyKind::Name(RenameMode::To)), &[&to]),
            &roots,
            &[],
            &mut pending,
        );
        assert_eq!(second, vec![Change::Rename { from, to }]);
        assert_eq!(pending, None);
    }

    /// A `Both` rename event carries the source and destination paths.
    #[test]
    fn both_rename_event_becomes_a_rename() {
        let dir = TempDir::new().unwrap();
        let from = file_in(&dir, "old.txt");
        let to = file_in(&dir, "new.txt");
        let mut pending = None;

        let changes = map_event(
            &event(
                EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
                &[&from, &to],
            ),
            &watched_roots(&dir),
            &[],
            &mut pending,
        );

        assert_eq!(changes, vec![Change::Rename { from, to }]);
    }

    /// Access events, paths outside the roots, and the database itself are all
    /// ignored.
    #[test]
    fn irrelevant_events_are_ignored() {
        let dir = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let db = file_in(&dir, "index.db");
        let roots = watched_roots(&dir);

        let outside = file_in(&other, "elsewhere.txt");
        let mut pending = None;
        assert!(map_event(
            &event(EventKind::Create(CreateKind::File), &[&outside]),
            &roots,
            std::slice::from_ref(&db),
            &mut pending
        )
        .is_empty());

        assert!(map_event(
            &event(
                EventKind::Access(AccessKind::Any),
                &[&file_in(&dir, "read.txt")]
            ),
            &roots,
            std::slice::from_ref(&db),
            &mut pending
        )
        .is_empty());

        assert!(map_event(
            &event(EventKind::Create(CreateKind::File), &[&db]),
            &roots,
            std::slice::from_ref(&db),
            &mut pending
        )
        .is_empty());
    }

    /// A burst of operations on one path collapses to the last one, and an
    /// incoming rename supersedes a queued removal of its source.
    #[test]
    fn coalesce_keeps_the_last_operation_per_path() {
        let dir = TempDir::new().unwrap();
        let a = file_in(&dir, "a.txt");
        let b = file_in(&dir, "b.txt");

        assert_eq!(
            coalesce(vec![
                Change::Upsert(a.clone()),
                Change::Remove(a.clone()),
                Change::Upsert(a.clone()),
                Change::Upsert(b.clone()),
            ]),
            vec![Change::Upsert(a.clone()), Change::Upsert(b.clone())]
        );

        assert_eq!(
            coalesce(vec![
                Change::Remove(a.clone()),
                Change::Rename {
                    from: a.clone(),
                    to: b.clone(),
                },
            ]),
            vec![Change::Rename { from: a, to: b }]
        );
    }
}
