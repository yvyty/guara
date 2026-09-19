# 05. Index and history

The index is an optional SQLite cache of paths plus size, mtime, and
mode. It makes repeat queries cheap without becoming the source of
truth: contents are always read live, stale rows are rescanned, and a
missing index falls back to a normal walk.

The examples here use an isolated database so you never touch your
real index while learning.

## Build and rebuild

```sh
guara index ./src --db /tmp/guara-examples-index.db
```

Builds or updates incrementally (default root is `.`). Run it again
after files change, or use `serve` to watch continuously.

```sh
guara reindex ./src --db /tmp/guara-examples-index.db
```

Rebuilds from scratch for the given roots.

## Inspect

```sh
guara index status --db /tmp/guara-examples-index.db
```

Reports path count, DB path, last update time, and roots. This command
never creates a database just to report on it.

## Search with the index

```sh
guara needle ./src --db /tmp/guara-examples-index.db
```

Guara uses the index when it exists and its recorded roots cover the
roots you asked for. Otherwise it walks live. Without `--quiet`,
stderr notes `(index: N candidates, N stale, N missing)` so an indexed
search explains itself.

```sh
guara needle ./src --db /tmp/guara-examples-index.db --no-index
```

Use `--no-index` when you want to force a walk for comparison.

## Hashes (opt-in build)

```sh
guara index --hash ./src --db /tmp/guara-examples-index.db
```

Also stores a SHA-256 content hash per file. This needs a build with
`--features security-hash`. Without that feature, rows are stored
without a hash and Guara says so.

## History and config

```sh
guara history --limit 5 --db /tmp/guara-examples-index.db
```

Prints recent local queries. History lives in the same local database
and nothing is sent over the network.

```sh
guara config
```

Prints the config file path for your OS plus the effective settings
as JSON. A missing file is fine, built-in defaults are used.

Next: [06. Serve and browse](06-serve-watch.md) for the watcher daemon
and the terminal UI.
