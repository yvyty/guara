//! Persistent SQLite index of file paths and metadata.
//!
//! The index is a cache with an honest failure mode: it may be stale, and every
//! consumer must be able to fall back to a live walk. `docs/architecture/index.md`
//! records why SQLite is the v0.1 store (and not sled), the schema, and the
//! staleness rules.
//!
//! Nothing here mutates the user's files. The only writes are to the database.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use directories::ProjectDirs;
use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection, OptionalExtension};

use crate::fs::{self, FileEntry, WalkOptions};

/// Schema version stored in the `meta` table.
pub const SCHEMA_VERSION: i64 = 1;

/// Errors produced by the index layer.
#[derive(Debug)]
pub enum IndexError {
    /// SQLite-level failure (open, query, commit).
    Db(String),
    /// The OS did not provide a data directory for the default DB path.
    NoDataDir,
    /// Filesystem failure while building or updating the index.
    Io(PathBuf, String),
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndexError::Db(msg) => write!(f, "index database error: {msg}"),
            IndexError::NoDataDir => {
                write!(
                    f,
                    "could not determine a data directory for the index on this OS"
                )
            }
            IndexError::Io(path, msg) => {
                write!(f, "index io error for {}: {msg}", path.display())
            }
        }
    }
}

impl std::error::Error for IndexError {}

impl From<rusqlite::Error> for IndexError {
    fn from(err: rusqlite::Error) -> Self {
        IndexError::Db(err.to_string())
    }
}

/// Default index path: `<data_dir>/index.db`, resolved with the same
/// `directories` crate used for the config file.
pub fn default_db_path() -> Option<PathBuf> {
    let proj = ProjectDirs::from("dev", "guara", "guara")?;
    Some(proj.data_dir().join("index.db"))
}

/// The database file and the journal files SQLite may create beside it. These
/// are never indexed, so an index stored inside a watched or indexed root does
/// not feed its own writes back into itself.
pub fn database_files(db_path: &Path) -> Vec<PathBuf> {
    // Canonicalize the parent so the comparison works even when the journal
    // file does not exist yet and the path goes through a symlink.
    let base = match (db_path.parent(), db_path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            canonicalize(parent).join(name)
        }
        _ => db_path.to_path_buf(),
    };

    let mut files = vec![base.clone()];
    for suffix in ["-wal", "-shm", "-journal"] {
        files.push(PathBuf::from(format!("{}{suffix}", base.display())));
    }
    files
}

/// A row as stored in the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedFile {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: u64,
    pub mode: Option<u32>,
    pub content_hash: Option<String>,
}

/// Filters applied in SQL so an indexed query does not enumerate every row.
///
/// Fields mirror [`crate::search::FileFilter`]. Picking candidates from indexed
/// metadata is the point: name/content matching and staleness checks stay in the
/// search layer.
#[derive(Debug, Clone, Default)]
pub struct IndexQuery {
    /// Allowed extensions (without leading dot). Empty = all.
    pub extensions: Vec<String>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    /// Only rows with `mtime >= after`.
    pub after: Option<u64>,
    /// Only rows with `mtime < before`.
    pub before: Option<u64>,
    /// Restrict to paths under these directories (matched as prefixes).
    pub unders: Vec<PathBuf>,
    pub limit: Option<usize>,
}

/// What an index pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IndexStats {
    /// Files visited during the walk.
    pub scanned: usize,
    /// New rows written.
    pub inserted: usize,
    /// Existing rows rewritten.
    pub updated: usize,
    /// Files skipped because `size` and `mtime` were unchanged.
    pub unchanged: usize,
    /// Rows deleted because the file disappeared.
    pub removed: usize,
    /// Per-entry filesystem errors (unreadable directories, vanished files).
    pub errors: usize,
}

impl IndexStats {
    /// Rows written (inserted + updated).
    pub fn written(&self) -> usize {
        self.inserted + self.updated
    }

    /// One-line summary for stderr. Includes the unchanged count so a second
    /// index of an unchanged tree is visibly cheap.
    pub fn summary(&self) -> String {
        format!(
            "index: {} added, {} updated, {} unchanged (skipped), {} removed; {} file(s) scanned",
            self.inserted, self.updated, self.unchanged, self.removed, self.scanned
        )
    }
}

/// Options for [`IndexStore::update`].
#[derive(Debug, Clone, Default)]
pub struct UpdateOptions {
    /// Drop the stored rows for the indexed roots first (full rebuild).
    pub force: bool,
    /// Compute a SHA-256 content hash per file. Expensive; opt-in via `--hash`
    /// and only compiled in with the `security-hash` feature.
    pub content_hash: bool,
}

/// Index state for `guara index status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexStatus {
    pub db_path: PathBuf,
    pub path_count: usize,
    pub last_updated: Option<u64>,
    pub roots: Vec<PathBuf>,
    pub schema_version: i64,
}

/// A single write for the watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Create or modify: (re)read metadata and upsert.
    Upsert(PathBuf),
    /// Delete: drop the row.
    Remove(PathBuf),
    /// Rename: drop `from`, upsert `to`.
    Rename { from: PathBuf, to: PathBuf },
}

/// Result of applying one debounced batch.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BatchReport {
    pub upserts: usize,
    pub removes: usize,
    pub renames: usize,
    pub skipped: usize,
}

impl BatchReport {
    /// Total rows touched by the batch.
    pub fn touched(&self) -> usize {
        self.upserts + self.removes + self.renames
    }
}

/// A persisted history row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub query: String,
    pub created: u64,
}

/// A persisted watched term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedTerm {
    pub term: String,
    pub created: u64,
}

/// Handle to the persistent index.
pub struct IndexStore {
    conn: Connection,
    db_path: PathBuf,
    /// Transactions committed by [`IndexStore::apply_batch`]. Tests and
    /// `guara serve` use this to prove a burst became a single transaction.
    batch_commits: u64,
}

impl IndexStore {
    /// Open (creating if needed) the index at `path`, then create the schema.
    pub fn open(path: &Path) -> Result<Self, IndexError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| IndexError::Io(parent.to_path_buf(), e.to_string()))?;
            }
        }
        let conn = Connection::open(path).map_err(|e| IndexError::Db(e.to_string()))?;
        Self::from_connection(conn, path.to_path_buf())
    }

    /// In-memory index. Used by tests so no user database is ever touched.
    pub fn open_in_memory() -> Result<Self, IndexError> {
        let conn = Connection::open_in_memory().map_err(|e| IndexError::Db(e.to_string()))?;
        Self::from_connection(conn, PathBuf::from(":memory:"))
    }

    fn from_connection(conn: Connection, db_path: PathBuf) -> Result<Self, IndexError> {
        // WAL keeps the watcher's writes cheap; in-memory databases ignore it.
        let _ = conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()));
        let _ = conn.execute_batch("PRAGMA synchronous = NORMAL");
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let mut store = Self {
            conn,
            db_path,
            batch_commits: 0,
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Create the schema on first use and refuse a database
    /// written by a newer Guará.
    pub fn init_schema(&mut self) -> Result<(), IndexError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS files (
                     path         TEXT PRIMARY KEY,
                     size         INTEGER NOT NULL,
                     mtime        INTEGER NOT NULL,
                     mode         INTEGER,
                     content_hash TEXT
                 );
                 CREATE INDEX IF NOT EXISTS files_size  ON files(size);
                 CREATE INDEX IF NOT EXISTS files_mtime ON files(mtime);
                 CREATE TABLE IF NOT EXISTS meta (
                     key   TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS roots (
                     path TEXT PRIMARY KEY
                 );
                 CREATE TABLE IF NOT EXISTS history (
                     id      INTEGER PRIMARY KEY AUTOINCREMENT,
                     query   TEXT NOT NULL,
                     created INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS watched_terms (
                     term    TEXT PRIMARY KEY,
                     created INTEGER NOT NULL
                 );",
            )
            .map_err(|e| IndexError::Db(e.to_string()))?;

        if let Some(stored) = self.meta("schema_version")? {
            if let Ok(version) = stored.parse::<i64>() {
                if version > SCHEMA_VERSION {
                    return Err(IndexError::Db(format!(
                        "index schema version {version} is newer than this Guará supports \
                         ({SCHEMA_VERSION}); upgrade Guará or use a different --db"
                    )));
                }
            }
        }
        self.set_meta("schema_version", &SCHEMA_VERSION.to_string())?;
        Ok(())
    }

    /// Path of the underlying database file.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Transactions committed by [`IndexStore::apply_batch`].
    pub fn batch_commits(&self) -> u64 {
        self.batch_commits
    }

    /// Row count.
    pub fn path_count(&self) -> Result<usize, IndexError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(count as usize)
    }

    /// `PRAGMA integrity_check`. Used to prove a shutdown did not truncate the
    /// database.
    pub fn integrity_ok(&self) -> Result<bool, IndexError> {
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(result == "ok")
    }

    /// Status for `guara index status`.
    pub fn status(&self) -> Result<IndexStatus, IndexError> {
        Ok(IndexStatus {
            db_path: self.db_path.clone(),
            path_count: self.path_count()?,
            last_updated: self
                .meta("last_updated")?
                .and_then(|v| v.parse::<u64>().ok()),
            roots: self.roots()?,
            schema_version: self
                .meta("schema_version")?
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(SCHEMA_VERSION),
        })
    }

    /// Canonicalized roots recorded by the last index pass.
    pub fn roots(&self) -> Result<Vec<PathBuf>, IndexError> {
        let mut stmt = self
            .conn
            .prepare("SELECT path FROM roots ORDER BY path")
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let mut roots = Vec::new();
        for row in rows {
            roots.push(PathBuf::from(
                row.map_err(|e| IndexError::Db(e.to_string()))?,
            ));
        }
        Ok(roots)
    }

    /// Whether the recorded roots cover every requested root. Index-first
    /// search only applies when this is true.
    pub fn covers(&self, requested: &[PathBuf]) -> Result<bool, IndexError> {
        let recorded = self.roots()?;
        if recorded.is_empty() {
            return Ok(false);
        }
        Ok(requested.iter().all(|want| {
            let want = canonicalize(want);
            recorded
                .iter()
                .any(|have| want == *have || want.starts_with(have))
        }))
    }

    /// Walk `roots` and update the index incrementally.
    ///
    /// Roots are canonicalized before the walk so stored paths, recorded roots,
    /// watcher events, and query prefixes all agree even when the user spells a
    /// root through a symlink (`/tmp` on macOS).
    pub fn update(
        &mut self,
        roots: &[PathBuf],
        walk_options: &WalkOptions,
        options: &UpdateOptions,
    ) -> Result<IndexStats, IndexError> {
        let canonical_roots: Vec<PathBuf> = roots.iter().map(|root| canonicalize(root)).collect();
        let walk_result = fs::walk(&canonical_roots, walk_options);
        self.update_entries(
            &walk_result.entries,
            &canonical_roots,
            walk_result.errors.len(),
            options,
        )
    }

    /// Update from an already-collected entry list.
    pub fn update_entries(
        &mut self,
        entries: &[FileEntry],
        roots: &[PathBuf],
        walk_errors: usize,
        options: &UpdateOptions,
    ) -> Result<IndexStats, IndexError> {
        let root_keys: Vec<PathBuf> = roots.iter().map(|r| canonicalize(r)).collect();
        // Never index the database itself, even when it lives inside a root.
        let db_files = database_files(&self.db_path);

        // Preload existing (size, mtime) per path so unchanged files need no SQL.
        let mut existing: HashMap<String, (u64, u64)> = HashMap::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT path, size, mtime FROM files")
                .map_err(|e| IndexError::Db(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)? as u64,
                    ))
                })
                .map_err(|e| IndexError::Db(e.to_string()))?;
            for row in rows {
                let (path, size, mtime) = row.map_err(|e| IndexError::Db(e.to_string()))?;
                existing.insert(path, (size, mtime));
            }
        }

        let mut stats = IndexStats {
            scanned: entries.len(),
            errors: walk_errors,
            ..Default::default()
        };
        let mut seen: HashSet<String> = HashSet::with_capacity(entries.len());

        let tx = self
            .conn
            .transaction()
            .map_err(|e| IndexError::Db(e.to_string()))?;

        if options.force {
            for root in &root_keys {
                let prefix = path_key(root);
                tx.execute("DELETE FROM files WHERE instr(path, ?1) = 1", [&prefix])
                    .map_err(|e| IndexError::Db(e.to_string()))?;
            }
            // The rows are gone, so nothing is preloaded as "existing" anymore;
            // every entry must be inserted again.
            existing.clear();
        }

        for entry in entries {
            if db_files.contains(&entry.path) {
                stats.scanned = stats.scanned.saturating_sub(1);
                continue;
            }

            let key = path_key(&entry.path);
            seen.insert(key.clone());

            let metadata = match std::fs::metadata(&entry.path) {
                Ok(m) => m,
                Err(_) => {
                    stats.errors += 1;
                    continue;
                }
            };
            let size = metadata.len();
            let mtime = mtime_secs(&metadata);
            let mode = mode_bits(&metadata);

            match existing.get(&key) {
                Some((old_size, old_mtime))
                    if !options.force && *old_size == size && *old_mtime == mtime =>
                {
                    stats.unchanged += 1;
                    continue;
                }
                Some(_) => {
                    tx.execute(
                        "UPDATE files SET size = ?1, mtime = ?2, mode = ?3 WHERE path = ?4",
                        params_from_iter([
                            Value::Integer(size as i64),
                            Value::Integer(mtime as i64),
                            mode.map(|m| Value::Integer(m as i64))
                                .unwrap_or(Value::Null),
                            Value::Text(key.clone()),
                        ]),
                    )
                    .map_err(|e| IndexError::Db(e.to_string()))?;
                    stats.updated += 1;
                }
                None => {
                    tx.execute(
                        "INSERT OR REPLACE INTO files (path, size, mtime, mode, content_hash)
                         VALUES (?1, ?2, ?3, ?4, NULL)",
                        params_from_iter([
                            Value::Text(key.clone()),
                            Value::Integer(size as i64),
                            Value::Integer(mtime as i64),
                            mode.map(|m| Value::Integer(m as i64))
                                .unwrap_or(Value::Null),
                        ]),
                    )
                    .map_err(|e| IndexError::Db(e.to_string()))?;
                    stats.inserted += 1;
                }
            }

            if options.content_hash {
                let hash = content_hash(&entry.path);
                tx.execute(
                    "UPDATE files SET content_hash = ?1 WHERE path = ?2",
                    params_from_iter([
                        hash.map(Value::Text).unwrap_or(Value::Null),
                        Value::Text(key),
                    ]),
                )
                .map_err(|e| IndexError::Db(e.to_string()))?;
            }
        }

        // Prune rows for files that vanished from an indexed root.
        for path in existing.keys() {
            if seen.contains(path) {
                continue;
            }
            if under_roots(path, &root_keys) {
                stats.removed += tx
                    .execute("DELETE FROM files WHERE path = ?1", [path])
                    .map_err(|e| IndexError::Db(e.to_string()))?;
            }
        }

        for root in &root_keys {
            tx.execute(
                "INSERT OR REPLACE INTO roots (path) VALUES (?1)",
                [path_key(root)],
            )
            .map_err(|e| IndexError::Db(e.to_string()))?;
        }
        set_meta_tx(&tx, "last_updated", &now_secs().to_string())?;
        set_meta_tx(&tx, "schema_version", &SCHEMA_VERSION.to_string())?;

        tx.commit().map_err(|e| IndexError::Db(e.to_string()))?;

        tracing::info!(
            scanned = stats.scanned,
            inserted = stats.inserted,
            updated = stats.updated,
            unchanged = stats.unchanged,
            removed = stats.removed,
            "index update complete"
        );
        Ok(stats)
    }

    /// Query indexed rows. Filtering happens in SQL; only the
    /// matched rows are returned.
    pub fn query(&self, query: &IndexQuery) -> Result<Vec<IndexedFile>, IndexError> {
        let mut sql = String::from("SELECT path, size, mtime, mode, content_hash FROM files");
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<Value> = Vec::new();

        if !query.extensions.is_empty() {
            let mut parts = Vec::new();
            for ext in &query.extensions {
                parts.push("lower(path) LIKE ? ESCAPE '\\'".to_string());
                args.push(Value::Text(format!(
                    "%.{ext}",
                    ext = escape_like(&ext.to_lowercase())
                )));
            }
            clauses.push(format!("({})", parts.join(" OR ")));
        }
        if let Some(min) = query.min_size {
            clauses.push("size >= ?".to_string());
            args.push(Value::Integer(min as i64));
        }
        if let Some(max) = query.max_size {
            clauses.push("size <= ?".to_string());
            args.push(Value::Integer(max as i64));
        }
        if let Some(after) = query.after {
            clauses.push("mtime >= ?".to_string());
            args.push(Value::Integer(after as i64));
        }
        if let Some(before) = query.before {
            clauses.push("mtime < ?".to_string());
            args.push(Value::Integer(before as i64));
        }
        if !query.unders.is_empty() {
            let mut parts = Vec::new();
            for root in &query.unders {
                parts.push("instr(path, ?) = 1".to_string());
                args.push(Value::Text(path_key(&canonicalize(root))));
            }
            clauses.push(format!("({})", parts.join(" OR ")));
        }

        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY path");
        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            args.push(Value::Integer(limit as i64));
        }

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let rows = stmt
            .query_map(params_from_iter(args), |row| {
                Ok(IndexedFile {
                    path: PathBuf::from(row.get::<_, String>(0)?),
                    size: row.get::<_, i64>(1)? as u64,
                    mtime: row.get::<_, i64>(2)? as u64,
                    mode: row.get::<_, Option<i64>>(3)?.map(|m| m as u32),
                    content_hash: row.get::<_, Option<String>>(4)?,
                })
            })
            .map_err(|e| IndexError::Db(e.to_string()))?;

        let mut files = Vec::new();
        for row in rows {
            files.push(row.map_err(|e| IndexError::Db(e.to_string()))?);
        }
        Ok(files)
    }

    /// Write one row (used by tests and the watcher).
    pub fn upsert_file(&self, file: &IndexedFile) -> Result<(), IndexError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO files (path, size, mtime, mode, content_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params_from_iter([
                    Value::Text(path_key(&file.path)),
                    Value::Integer(file.size as i64),
                    Value::Integer(file.mtime as i64),
                    file.mode
                        .map(|m| Value::Integer(m as i64))
                        .unwrap_or(Value::Null),
                    file.content_hash
                        .clone()
                        .map(Value::Text)
                        .unwrap_or(Value::Null),
                ]),
            )
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(())
    }

    /// Delete one row. Returns whether a row existed.
    pub fn remove_file(&self, path: &Path) -> Result<bool, IndexError> {
        let deleted = self
            .conn
            .execute("DELETE FROM files WHERE path = ?1", [path_key(path)])
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(deleted > 0)
    }

    /// Move a row from `from` to `to`, re-reading metadata from disk.
    pub fn rename_file(&self, from: &Path, to: &Path) -> Result<bool, IndexError> {
        self.remove_file(from)?;
        let metadata = match std::fs::metadata(to) {
            Ok(m) if m.is_file() => m,
            _ => return Ok(false),
        };
        self.upsert_file(&IndexedFile {
            path: to.to_path_buf(),
            size: metadata.len(),
            mtime: mtime_secs(&metadata),
            mode: mode_bits(&metadata),
            content_hash: None,
        })?;
        Ok(true)
    }

    /// Apply one debounced burst of changes as a single transaction
    pub fn apply_batch(&mut self, changes: &[Change]) -> Result<BatchReport, IndexError> {
        let mut report = BatchReport::default();
        let now = now_secs();

        let tx = self
            .conn
            .transaction()
            .map_err(|e| IndexError::Db(e.to_string()))?;

        for change in changes {
            match change {
                Change::Upsert(path) => match std::fs::metadata(path) {
                    Ok(metadata) if metadata.is_file() => {
                        tx.execute(
                            "INSERT OR REPLACE INTO files (path, size, mtime, mode, content_hash)
                             VALUES (?1, ?2, ?3, ?4, NULL)",
                            params_from_iter([
                                Value::Text(path_key(path)),
                                Value::Integer(metadata.len() as i64),
                                Value::Integer(mtime_secs(&metadata) as i64),
                                mode_bits(&metadata)
                                    .map(|m| Value::Integer(m as i64))
                                    .unwrap_or(Value::Null),
                            ]),
                        )
                        .map_err(|e| IndexError::Db(e.to_string()))?;
                        report.upserts += 1;
                    }
                    _ => {
                        // A path that is gone (or is now a directory) cannot stay
                        // in the index.
                        let deleted = tx
                            .execute("DELETE FROM files WHERE path = ?1", [path_key(path)])
                            .map_err(|e| IndexError::Db(e.to_string()))?;
                        report.removes += if deleted > 0 { 1 } else { 0 };
                        report.skipped += if deleted > 0 { 0 } else { 1 };
                    }
                },
                Change::Remove(path) => {
                    let deleted = tx
                        .execute("DELETE FROM files WHERE path = ?1", [path_key(path)])
                        .map_err(|e| IndexError::Db(e.to_string()))?;
                    report.removes += if deleted > 0 { 1 } else { 0 };
                }
                Change::Rename { from, to } => {
                    tx.execute("DELETE FROM files WHERE path = ?1", [path_key(from)])
                        .map_err(|e| IndexError::Db(e.to_string()))?;
                    if let Ok(metadata) = std::fs::metadata(to) {
                        if metadata.is_file() {
                            tx.execute(
                                "INSERT OR REPLACE INTO files (path, size, mtime, mode, content_hash)
                                 VALUES (?1, ?2, ?3, ?4, NULL)",
                                params_from_iter([
                                    Value::Text(path_key(to)),
                                    Value::Integer(metadata.len() as i64),
                                    Value::Integer(mtime_secs(&metadata) as i64),
                                    mode_bits(&metadata)
                                        .map(|m| Value::Integer(m as i64))
                                        .unwrap_or(Value::Null),
                                ]),
                            )
                            .map_err(|e| IndexError::Db(e.to_string()))?;
                            report.renames += 1;
                        }
                    }
                }
            }
        }

        set_meta_tx(&tx, "last_updated", &now.to_string())?;
        tx.commit().map_err(|e| IndexError::Db(e.to_string()))?;
        self.batch_commits += 1;
        Ok(report)
    }

    /// Record a search query locally. Never sent anywhere.
    pub fn record_history(&self, query: &str) -> Result<(), IndexError> {
        if query.trim().is_empty() {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO history (query, created) VALUES (?1, ?2)",
                params_from_iter([
                    Value::Text(query.to_string()),
                    Value::Integer(now_secs() as i64),
                ]),
            )
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(())
    }

    /// Most recent queries, newest first.
    pub fn history(&self, limit: usize) -> Result<Vec<HistoryEntry>, IndexError> {
        let mut stmt = self
            .conn
            .prepare("SELECT query, created FROM history ORDER BY id DESC LIMIT ?1")
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let rows = stmt
            .query_map([limit as i64], |row| {
                Ok(HistoryEntry {
                    query: row.get::<_, String>(0)?,
                    created: row.get::<_, i64>(1)? as u64,
                })
            })
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| IndexError::Db(e.to_string()))?);
        }
        Ok(entries)
    }

    /// Add (or re-affirm) a watched term.
    pub fn add_watched_term(&self, term: &str) -> Result<(), IndexError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO watched_terms (term, created) VALUES (?1, ?2)",
                params_from_iter([
                    Value::Text(term.to_string()),
                    Value::Integer(now_secs() as i64),
                ]),
            )
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(())
    }

    /// Remove a watched term. Returns whether it existed.
    pub fn remove_watched_term(&self, term: &str) -> Result<bool, IndexError> {
        let deleted = self
            .conn
            .execute("DELETE FROM watched_terms WHERE term = ?1", [term])
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(deleted > 0)
    }

    /// All watched terms, oldest first.
    pub fn watched_terms(&self) -> Result<Vec<WatchedTerm>, IndexError> {
        let mut stmt = self
            .conn
            .prepare("SELECT term, created FROM watched_terms ORDER BY created, term")
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(WatchedTerm {
                    term: row.get::<_, String>(0)?,
                    created: row.get::<_, i64>(1)? as u64,
                })
            })
            .map_err(|e| IndexError::Db(e.to_string()))?;
        let mut terms = Vec::new();
        for row in rows {
            terms.push(row.map_err(|e| IndexError::Db(e.to_string()))?);
        }
        Ok(terms)
    }

    /// Read one `meta` value.
    pub fn meta(&self, key: &str) -> Result<Option<String>, IndexError> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(|e| IndexError::Db(e.to_string()))
    }

    /// Write one `meta` value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), IndexError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params_from_iter([Value::Text(key.to_string()), Value::Text(value.to_string())]),
            )
            .map_err(|e| IndexError::Db(e.to_string()))?;
        Ok(())
    }
}

fn set_meta_tx(tx: &rusqlite::Transaction<'_>, key: &str, value: &str) -> Result<(), IndexError> {
    tx.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        params_from_iter([Value::Text(key.to_string()), Value::Text(value.to_string())]),
    )
    .map_err(|e| IndexError::Db(e.to_string()))?;
    Ok(())
}

/// Stored form of a path. Lossy for non-UTF-8 paths; documented in
/// `docs/architecture/index.md`.
fn path_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Format Unix seconds as an RFC 3339 timestamp in UTC, without pulling in a
/// date library.
pub fn format_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since the Unix epoch to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Canonicalize when possible so recorded roots compare cleanly. Falls back to
/// the input path when the directory does not exist yet.
pub fn canonicalize(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn under_roots(path: &str, roots: &[PathBuf]) -> bool {
    let path = Path::new(path);
    roots.iter().any(|root| path.starts_with(root))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mtime_secs(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn mode_bits(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.mode())
}

#[cfg(not(unix))]
fn mode_bits(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

/// Escape `%` and `_` so a user-provided extension cannot widen a LIKE match.
fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Optional content hash. Only compiled in with the `security-hash` feature so
/// the default build does not pay for hashing.
#[cfg(feature = "security-hash")]
fn content_hash(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(format!("{:x}", hasher.finalize()))
}

#[cfg(not(feature = "security-hash"))]
fn content_hash(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;
    use tempfile::TempDir;

    fn walk_options() -> WalkOptions {
        WalkOptions::default()
    }

    /// Roots only.
    fn one_root(dir: &TempDir) -> Vec<PathBuf> {
        vec![dir.path().to_path_buf()]
    }

    /// The default DB path must come from the same `directories` crate as the
    /// config file.
    #[test]
    fn default_db_path_is_the_guara_data_dir() {
        let path = default_db_path().expect("this OS provides a data directory");
        let proj = ProjectDirs::from("dev", "guara", "guara").unwrap();
        assert_eq!(path, proj.data_dir().join("index.db"));
        assert_eq!(
            crate::config::config_path().unwrap(),
            proj.config_dir().join("config.toml")
        );
    }

    /// A fresh database creates the schema on first open.
    #[test]
    fn fresh_database_creates_schema() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("nested").join("index.db");
        let store = IndexStore::open(&db).unwrap();

        assert!(db.exists());
        assert_eq!(store.path_count().unwrap(), 0);
        assert_eq!(store.meta("schema_version").unwrap().as_deref(), Some("1"));
        assert!(store.integrity_ok().unwrap());
        // Every table exists and is queryable.
        assert!(store.history(5).unwrap().is_empty());
        assert!(store.watched_terms().unwrap().is_empty());
        assert!(store.roots().unwrap().is_empty());
        assert_eq!(store.status().unwrap().schema_version, SCHEMA_VERSION);
    }

    /// A database written by a newer schema is refused rather than misread.
    #[test]
    fn newer_schema_version_is_refused() {
        let mut store = IndexStore::open_in_memory().unwrap();
        store.set_meta("schema_version", "99").unwrap();
        let err = store.init_schema().unwrap_err();
        assert!(err.to_string().contains("newer"));
    }

    /// Rows carry path, size, mtime, and mode.
    #[test]
    fn index_records_path_size_mtime_and_mode() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "hello").unwrap();

        let mut store = IndexStore::open_in_memory().unwrap();
        let stats = store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();

        assert_eq!(stats.inserted, 1);
        assert_eq!(stats.updated, 0);
        assert_eq!(stats.scanned, 1);

        let rows = store.query(&IndexQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].size, 5);
        assert!(rows[0].mtime > 0);
        assert!(rows[0].content_hash.is_none());

        let metadata = stdfs::metadata(&rows[0].path).unwrap();
        assert_eq!(rows[0].size, metadata.len());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(rows[0].mode, Some(metadata.mode()));
        }
    }

    /// A second pass skips unchanged files by mtime+size.
    #[test]
    fn second_pass_skips_unchanged_files() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "a").unwrap();
        stdfs::write(dir.path().join("b.txt"), "b").unwrap();

        let mut store = IndexStore::open_in_memory().unwrap();
        store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();
        let second = store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();

        assert_eq!(second.inserted, 0);
        assert_eq!(second.updated, 0);
        assert_eq!(second.unchanged, 2);
        assert_eq!(second.written(), 0);
        assert_eq!(store.path_count().unwrap(), 2);
    }

    /// Only the changed file is rewritten.
    #[test]
    fn changed_file_is_updated_and_others_are_skipped() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "a").unwrap();
        stdfs::write(dir.path().join("b.txt"), "b").unwrap();

        let mut store = IndexStore::open_in_memory().unwrap();
        store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();
        stdfs::write(dir.path().join("a.txt"), "a changed and longer").unwrap();

        let second = store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();

        assert_eq!(second.updated, 1);
        assert_eq!(second.unchanged, 1);
        assert_eq!(second.inserted, 0);
    }

    /// Rows for files that disappeared under an indexed root are pruned.
    #[test]
    fn deleted_file_is_pruned() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "a").unwrap();
        stdfs::write(dir.path().join("b.txt"), "b").unwrap();

        let mut store = IndexStore::open_in_memory().unwrap();
        store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();
        stdfs::remove_file(dir.path().join("b.txt")).unwrap();

        let second = store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();

        assert_eq!(second.removed, 1);
        assert_eq!(store.path_count().unwrap(), 1);
    }

    /// Force (used by `guara reindex`) rewrites every row.
    #[test]
    fn force_rewrites_every_row() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "a").unwrap();
        stdfs::write(dir.path().join("b.txt"), "b").unwrap();

        let mut store = IndexStore::open_in_memory().unwrap();
        store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();

        let forced = UpdateOptions {
            force: true,
            content_hash: false,
        };
        let stats = store
            .update(&one_root(&dir), &walk_options(), &forced)
            .unwrap();

        assert_eq!(stats.inserted, 2);
        assert_eq!(stats.updated, 0);
        assert_eq!(stats.unchanged, 0);
        assert_eq!(store.path_count().unwrap(), 2);
    }

    /// Status reports the row count, DB path, and last update time.
    #[test]
    fn status_reports_count_path_and_time() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "a").unwrap();
        let db = dir.path().join("index.db");

        let mut store = IndexStore::open(&db).unwrap();
        store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();

        let status = store.status().unwrap();
        assert_eq!(status.db_path, db);
        assert_eq!(status.path_count, 1);
        assert!(status.last_updated.unwrap() > 0);
        assert_eq!(status.roots, vec![canonicalize(dir.path())]);
    }

    /// An index stored inside a root does not index its own database file.
    #[test]
    fn index_ignores_its_own_database() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("a.txt"), "a").unwrap();
        let db = dir.path().join("index.db");

        let mut store = IndexStore::open(&db).unwrap();
        let stats = store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();

        assert_eq!(stats.inserted, 1);
        assert_eq!(stats.scanned, 1);
        let rows = store.query(&IndexQuery::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].path.ends_with("a.txt"));
    }

    /// `covers` gates index-first search to roots the index was built from.
    #[test]
    fn covers_only_indexed_roots() {
        let indexed = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        stdfs::write(indexed.path().join("a.txt"), "a").unwrap();

        let mut store = IndexStore::open_in_memory().unwrap();
        store
            .update(
                &one_root(&indexed),
                &walk_options(),
                &UpdateOptions::default(),
            )
            .unwrap();

        assert!(store.covers(&one_root(&indexed)).unwrap());
        assert!(!store.covers(&one_root(&other)).unwrap());
    }

    /// Row primitives used by the watcher: upsert, remove, rename.
    #[test]
    fn upsert_remove_and_rename_move_rows() {
        let dir = TempDir::new().unwrap();
        let ghost = dir.path().join("ghost.txt");
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        stdfs::write(&a, "a").unwrap();

        let store = IndexStore::open_in_memory().unwrap();
        store
            .upsert_file(&IndexedFile {
                path: ghost.clone(),
                size: 1,
                mtime: 1,
                mode: None,
                content_hash: None,
            })
            .unwrap();
        assert_eq!(store.path_count().unwrap(), 1);

        assert!(store.rename_file(&ghost, &a).unwrap());
        assert_eq!(store.path_count().unwrap(), 1);

        // Renaming onto a path that does not exist drops the old row.
        assert!(!store.rename_file(&a, &b).unwrap());
        assert_eq!(store.path_count().unwrap(), 0);

        assert!(!store.remove_file(&b).unwrap());
    }

    /// One debounced burst is one transaction, and delete/rename are handled
    #[test]
    fn batch_is_one_transaction_and_handles_delete_and_rename() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        let moved = dir.path().join("moved.txt");
        let missing = dir.path().join("never-existed.txt");
        stdfs::write(&a, "a").unwrap();
        stdfs::write(&b, "b").unwrap();

        let mut store = IndexStore::open_in_memory().unwrap();
        let report = store
            .apply_batch(&[
                Change::Upsert(a.clone()),
                Change::Upsert(b.clone()),
                Change::Upsert(missing),
            ])
            .unwrap();
        assert_eq!(report.upserts, 2);
        assert_eq!(store.batch_commits(), 1);
        assert_eq!(store.path_count().unwrap(), 2);

        let report = store.apply_batch(&[Change::Remove(a.clone())]).unwrap();
        assert_eq!(report.removes, 1);
        assert_eq!(store.path_count().unwrap(), 1);

        stdfs::rename(&b, &moved).unwrap();
        let report = store
            .apply_batch(&[Change::Rename {
                from: b.clone(),
                to: moved.clone(),
            }])
            .unwrap();
        assert_eq!(report.renames, 1);
        assert_eq!(store.path_count().unwrap(), 1);
        let rows = store.query(&IndexQuery::default()).unwrap();
        assert_eq!(rows[0].path, moved);
    }

    /// Filters run in SQL: extension, size, mtime, and prefix.
    #[test]
    fn query_applies_extension_size_time_and_prefix_filters() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("sub");
        stdfs::create_dir(&sub).unwrap();
        stdfs::write(dir.path().join("top.txt"), "12345").unwrap();
        stdfs::write(sub.join("inner.md"), "1").unwrap();

        let mut store = IndexStore::open_in_memory().unwrap();
        store
            .update(&one_root(&dir), &walk_options(), &UpdateOptions::default())
            .unwrap();

        let by_ext = store
            .query(&IndexQuery {
                extensions: vec!["md".to_string()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_ext.len(), 1);
        assert_eq!(by_ext[0].path.file_name().unwrap(), "inner.md");

        let by_size = store
            .query(&IndexQuery {
                min_size: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_size.len(), 1);
        assert_eq!(by_size[0].path.file_name().unwrap(), "top.txt");

        let by_time = store
            .query(&IndexQuery {
                before: Some(1), // everything is newer than the epoch
                ..Default::default()
            })
            .unwrap();
        assert!(by_time.is_empty());

        let by_prefix = store
            .query(&IndexQuery {
                unders: vec![sub.clone()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_prefix.len(), 1);
        assert_eq!(by_prefix[0].path.file_name().unwrap(), "inner.md");
    }

    /// History survives a reopen.
    #[test]
    fn history_round_trips_across_reopen() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("index.db");

        {
            let store = IndexStore::open(&db).unwrap();
            store.record_history("first").unwrap();
            store.record_history("second").unwrap();
            store.record_history("   ").unwrap(); // blank queries are ignored

            let history = store.history(2).unwrap();
            assert_eq!(history.len(), 2);
            assert_eq!(history[0].query, "second");
            assert_eq!(history[1].query, "first");
            assert!(history[0].created > 0);
        }

        let reopened = IndexStore::open(&db).unwrap();
        assert_eq!(reopened.history(10).unwrap().len(), 2);
    }

    /// Watched terms persist and can be removed.
    #[test]
    fn watched_terms_round_trip() {
        let store = IndexStore::open_in_memory().unwrap();
        store.add_watched_term("needle").unwrap();
        store.add_watched_term("report").unwrap();

        let terms: Vec<String> = store
            .watched_terms()
            .unwrap()
            .into_iter()
            .map(|term| term.term)
            .collect();
        assert_eq!(terms, vec!["needle".to_string(), "report".to_string()]);

        // Re-affirming a term does not duplicate it.
        store.add_watched_term("needle").unwrap();
        assert_eq!(store.watched_terms().unwrap().len(), 2);

        assert!(store.remove_watched_term("report").unwrap());
        assert!(!store.remove_watched_term("report").unwrap());
        assert_eq!(store.watched_terms().unwrap().len(), 1);
    }

    /// Timestamp formatting used by `index status` and `history`.
    #[test]
    fn format_timestamp_matches_known_dates() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp(1_789_704_502), "2026-09-18T04:08:22Z");
    }
}
