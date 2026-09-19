# Guara quick guide

New here? Read these in order. Each page is short, copy-paste ready,
and safe: nothing mutates your files except the quarantine example,
which moves files only when you pass both `--quarantine` and
`--quarantine-dir`.

`guara` below means the installed binary (`cargo install --path
crates/guara` or a release archive). Replace `./src` with any folder
you want to search.

## Start here

1. [01. Basic search](01-basic-search.md): default search, roots, depth
2. [02. Match modes](02-match-modes.md): regex, case, whole word, context, AND/OR
3. [03. Filters](03-filters.md): extension, size, date, binary, timeout

## Go further

4. [04. Output formats](04-output.md): human, JSON, CSV, HTML, quiet, color
5. [05. Index and history](05-index-history.md): cheap repeat searches, isolated `--db`
6. [06. Serve and browse](06-serve-watch.md): watcher daemon, socket, terminal UI
7. [07. Security](07-security.md): verdicts, deep scan backends, quarantine
8. [08. Scripting](08-scripting.md): exit codes, `jq` pipes, CI-safe patterns

## Rules that apply everywhere

- Search is the default command, so `guara PATTERN` equals
  `guara search PATTERN`.
- Stats and the security summary go to stderr, so `--json` and
  `--csv` on stdout stay machine readable.
- Exit codes: `0` hits, `1` no hits, `2` usage or config error,
  `3` partial filesystem errors.
- Symlinks are not followed unless `--follow-symlinks` is passed.
- The index is a cache. Content is always read live.

Full reference lives in the main [README](../README.md) and
`guara --help`.
