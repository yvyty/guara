# Changelog

All notable changes to Guará are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Progress spinner on an interactive stderr, hidden by `--quiet` or a pipe.
- Shell installer asset published with each tagged release.

### Changed

- Dual-licensed under MIT or Apache-2.0.
- Tagged releases publish Linux x86_64 and Windows x86_64 archives. macOS
  remains covered by CI build-smoke and builds from source.

### Fixed

- `[search] threads` and `max_file_size` from the config file are now applied.

## [0.1.0] - 2026-09-19

First public version of the CLI.

### Added

- Filesystem search that matches file names and file contents in the same pass,
  with `--regex`, `--ignore-case`, `--word`, `--context`, `--max-count`, and
  multi-term AND/OR matching.
- File filters: extension, size range, modification date, binary policy, maximum
  depth, and symlink policy (not followed by default).
- Output modes: human (default, colored, `NO_COLOR` aware), compact, table,
  newline-delimited JSON, CSV, and a self-contained HTML report. Statistics go
  to stderr so JSON stdout stays clean.
- Always-on security heuristics: double extensions, unusual permission bits,
  executable headers, and high-entropy samples. Report-only.
- Optional deep scanners behind Cargo features: local `clamd`, local YARA rules,
  and a local known-bad SHA-256 list. A build without a backend explains how to
  enable it instead of failing mid-search.
- Report-only quarantine behind `--quarantine` plus `--quarantine-dir`, with a
  manifest. Files are moved, never deleted in place, and never moved by default.
- TOML configuration with documented precedence (CLI flag > file > default) and
  `guara config` to print the effective settings.
- Persistent SQLite index (`guara index`, `guara reindex`, `guara index
  status`) that is always a cache: content is read live, stale rows are
  rescanned, and a missing index falls back to a normal walk.
- `guara serve`: watches the roots, debounces changes into single transactions,
  records local search history and watched terms, and shuts down cleanly on
  SIGINT/SIGTERM.
- `guara tui`: terminal browser with an incremental filter, preview pane,
  opening a hit with `$EDITOR` or the OS opener, and re-running the heuristics on
  the selected path.
- Local IPC protocol (`guara serve --socket`, Unix) with documented `search` and
  `status` request/response pairs.
- Experimental Tauri 2 tray companion with idle/indexing/threat states, a
  global-hotkey quick-search palette, recent queries, pinned scopes, and an
  auto-start toggle that is off by default.
- Documented exit codes: 0 hits or success, 1 no hits, 2 usage or config error,
  3 partial filesystem errors.

### Notes

- Deep scanners are off in the default build and in CI.
- The tray app is verified on macOS only; the Linux and Windows rows in
  `docs/tray.md` are waiting on manual QA.
- No telemetry, no network reputation lookup, and no OS service units in v0.1.

[Unreleased]: https://github.com/yvyty/guara/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yvyty/guara/releases/tag/v0.1.0
