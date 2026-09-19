# 06. Serve and browse

`serve` keeps the index fresh while you work. `tui` gives you an
interactive way to browse hits. Both use the same matcher and
heuristics as plain search.

## Watch a folder

```sh
guara serve ./src
```

Indexes the roots, then watches for changes until you press Ctrl-C
(`SIGINT` or `SIGTERM`). Each debounced burst becomes one SQLite
transaction, and the batch in flight finishes committing on shutdown.

## Tune the watcher

```sh
guara serve ./src --debounce 500
```

A burst of writes inside the debounce window becomes a single index
transaction. The value is in milliseconds.

```sh
guara serve ./src --watch-term invoice --watch-term .exe
```

Remembers watched terms locally and reports newly indexed files whose
name or contents match. Repeat `--watch-term` for each term.

```sh
guara serve ./src --no-initial-index
```

Watches for changes without indexing the roots first. Useful when
another process already keeps the index current.

## Expose the local socket (Unix only)

```sh
guara serve ./src --socket
```

Also answers the tray IPC protocol on the default socket path
(`<data_dir>/guara.sock`). An explicit path needs an equals sign:

```sh
guara serve ./src --socket=/tmp/guara.sock
```

Bare `--socket` uses the default, `--socket=PATH` uses your path.
Windows returns `Unsupported` here and the tray uses the shared library
instead.

## Browse hits interactively

```sh
guara tui needle ./src
```

Opens the terminal browser with incremental filter, preview pane, open
with `$EDITOR`, and rescan of the selected path. Without a TTY it falls
back to plain result output, so it stays scriptable in CI.

Next: [07. Security](07-security.md) for verdicts, deep scan, and
quarantine.
