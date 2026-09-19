# Persistent index architecture

Status: v0.1.

## Store choice: SQLite

The v0.1 index lives in a single SQLite database, accessed through `rusqlite`
with the `bundled` feature (a vendored SQLite, so users do not need a system
`libsqlite3`).

**Why SQLite instead of sled**

- The index is *relational*: rows are files (path, size, mtime, mode, optional
  content hash) and queries are filters over those columns. SQL `WHERE`, indexes
  on `size`/`mtime`, and `LIMIT` express that directly; a key/value tree needs a
  hand-rolled secondary index for every filter.
- Durability is a solved problem: a single file, WAL journal, `PRAGMA
  integrity_check`, and crash-safe transactions. `sled` is a pure-Rust
  key/value store, but its on-disk format is still documented as beta, and
  recovery guarantees are the reason a search cache should not be a storage
  engine decision users have to make.
- Tooling: `sqlite3` can inspect a user's index without Guará. That matters when
  someone reports "my index says X".
- Watch updates are batches of create/modify/delete/rename
  events. One transaction per debounce window is a one-liner here.

The tradeoff: a C dependency (`libsqlite3-sys`) is compiled into the binary.
The `bundled` build keeps that hermetic, and the index is optional, so a build
without the dependency is possible later if binary size becomes a concern.

## Location

`config::config_path()` and `index::default_db_path()` both resolve through the
`directories` crate (`ProjectDirs::from("dev", "guara", "guara")`):

| Item | Path |
| ---- | ---- |
| config | `<config_dir>/config.toml` |
| index | `<data_dir>/index.db` |

`--db <PATH>` overrides the index path on every index-aware command, which is
what tests and probing use. No command ever writes to a path the user did not
choose implicitly (the default data dir) or explicitly (`--db`).

## Schema (version 1)

```sql
CREATE TABLE files (
    path         TEXT PRIMARY KEY,  -- UTF-8, lossy for non-UTF-8 paths
    size         INTEGER NOT NULL,
    mtime        INTEGER NOT NULL,  -- seconds since the Unix epoch
    mode         INTEGER,           -- Unix permission bits; NULL elsewhere
    content_hash TEXT               -- optional SHA-256, opt-in via --hash
);
CREATE TABLE meta        (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE roots       (path TEXT PRIMARY KEY);   -- canonicalized roots
CREATE TABLE history     (id INTEGER PRIMARY KEY, query TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE watched_terms (term TEXT PRIMARY KEY, created INTEGER NOT NULL);
```

`meta` holds `schema_version` and `last_updated`. A database written by a newer
schema version is refused rather than silently misread.

Known v0.1 limitation: paths are stored as UTF-8 with a lossy conversion, so two
distinct non-UTF-8 paths could collide on exotic filenames. Recorded here rather
than hidden.

## Index is a cache, never the truth

The index may be stale. Consumers must behave as follows:

- A **missing** index means a live walk, with identical results to the
  walk-only path.
- Name and metadata filters **may** read indexed columns; `size`, `mtime`, and
  `mode` are what was true when the file was last indexed.
- Content is always read live. Before reading, each candidate is `stat`ed: if
  `size` or `mtime` differs from the row, the file is rescanned (that is the
  documented stale-entry behavior) and the fresh values are written back on the
  next index pass.
- Rows whose file no longer exists are dropped from the candidate list and
  pruned by the next `guara index`.
- Index-first search only applies when the index's recorded `roots` cover the
  requested roots; otherwise Guará walks live.

## Incremental update

`guara index` walks the roots and compares `(size, mtime)` per file against the
preloaded row set. Unchanged files are counted and skipped, so a second index of
an unchanged tree performs no writes for them. `guara reindex` forces the same
walk while dropping the stored rows for the indexed roots first, so every file is
written again.

Query construction and row mapping live in `crates/guara-core/src/index.rs`;
watching lives in `crates/guara-core/src/watch.rs`.

## Watching and background mode

`guara serve` watches the configured roots, debounces events for
`--debounce` milliseconds, and applies each burst as a single SQLite
transaction. Create and metadata/rename events upsert, delete events remove, and
explicit rename events move the row.

On SIGINT/SIGTERM the daemon stops after the batch currently being applied has
committed, so the database is never truncated mid-write. Signal handling lives in
the binary (`ctrlc`); the loop itself only polls an `AtomicBool`, which keeps it
testable.

Search history and watched terms are stored locally in the same database
(`history`, `watched_terms`). Nothing is sent over the network.

**OS service units (systemd/launchd/Windows Service) are explicitly out of
scope for v0.1.** `guara serve` is a foreground process you run yourself; unit
files and background installation are later work.
