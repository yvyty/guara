# Guará

A fast Rust filesystem search, tracking, and light-security CLI.

Inspired by the maned wolf. Security is a signal. Default actions never mutate the
user's files.

## Install

```sh
# Linux x86_64
sh -c "$(curl -fsSL https://github.com/yvyty/guara/releases/latest/download/guara-installer.sh)"

# From crates.io, once published
cargo install guara

# From a checkout
cargo install --path crates/guara
```

Prebuilt archives are attached to each tagged release; the tag pipeline in
[`.github/workflows/release.yml`](.github/workflows/release.yml) builds them for
Linux (x86_64) and Windows (x86_64). macOS builds from source. Distribution
channels and their status are listed under [Packaging](#packaging).

## Build

```sh
cargo build -p guara            # debug build at target/debug/guara
cargo build -p guara --release  # optimized build at target/release/guara
cargo run -p guara -- --help    # run without installing
cargo build -p guara-tray       # optional Tauri 2 tray app
```

## Usage

Guará searches file **names** and file **contents** in the same pass. Search is
the default command, so `guara <pattern>` and `guara search <pattern>` are
equivalent.

```sh
# Files whose name or content contains the literal "config"
guara config

# Restrict the search to one or more roots (default: current directory)
guara config ./src ./tests

# Only top-level entries
guara config --max-depth 1
```

### Matching

```sh
guara -e 'fn\s+\w+' src     # regular expression (instead of literal)
guara -i README              # case-insensitive
guara -w fn                  # whole word only (skips "fnord")
guara println --context 2    # show 2 lines before and after each content match
guara todo --max-count 10    # stop after 10 hits (reports when capped)
```

### Multiple terms (AND / OR)

The first positional argument is the pattern and the remaining positionals are
roots (`guara <PATTERN> [ROOTS]...`). `-t/--term` adds more patterns.

```sh
guara unsafe -t TODO src        # both terms must appear on a line (default: AND)
guara cache -t index --or .     # either term matches (OR)
```

### Filters

Filters reject files before content is read, when possible.

```sh
guara todo --ext rs --ext toml          # by extension (repeatable)
guara error --min-size 1k --max-size 5M # by size (k/M/G suffixes)
guara panic --after 2024-01-01          # modified after a date (YYYY-MM-DD)
guara panic --before 2025-01-01         # modified before a date
guara needle --binary                   # also search binary files
guara needle --timeout 5                # skip files taking over 5 seconds
```

## Output

Human output shows one block per file with size, mtime, and permissions, then the
matching lines:

```text
$ guara println src
src/main.rs (37 bytes, modified: 1700000000, mode: 100644)
  src/main.rs:2:     println!("hello");
```

Machine- and export-friendly formats:

```sh
guara todo --json      # newline-delimited JSON objects (one per file)
guara todo --csv       # CSV with path, match, line number, line, metadata
guara todo --html > report.html   # self-contained HTML report
guara todo --compact   # one line per file
guara todo --table     # tabular summary
```

The JSON shape is one object per hit:

```json
{"path":"src/main.rs","filename_matched":false,"content_matches":[{"line_number":2,"line":"    println!(\"hello\");","context_before":[],"context_after":[]}],"metadata":{"size":37,"modified":1700000000,"permissions":33188},"verdict":"clean","reasons":[]}
```

### Color

Color is used only when stdout is a TTY. `--color always|never|auto` overrides
this, and the `NO_COLOR` environment variable disables it.

```sh
guara todo --color never
NO_COLOR=1 guara todo
```

### Verbosity and stats

Search statistics go to **stderr**, so stdout stays clean for `--json`/`--csv`.
`--quiet` silences them; `-v`/`-vv` add log detail.

```sh
guara todo -q          # results only
guara todo -vv 2>log   # debug logging to stderr
```

## Security heuristics

Every search attaches a lightweight, always-on security verdict to each hit:
`Clean`, `Suspicious`, or `High Risk`, plus a short explanation. This is a
**signal**, not antivirus.

- **Entropy.** A bounded sample (default 1 MiB) of each file is scored with
  Shannon entropy. Samples at or above **7.2 bits/byte** are flagged as
  packed/compressed/encrypted-like. Files under 256 bytes are skipped by this
  rule; multi-gigabyte files are sampled, never read whole.
- **Permissions (Unix).** setuid, setgid, and world-writable executables are
  flagged. This check is a documented no-op on Windows, which has no such mode
  bits.
- **Names.** A double extension whose final extension is executable-like
  (for example `invoice.pdf.exe`) is flagged. Extra path substrings can be
  added through the `suspicious_patterns` config list.
- **Headers.** PE and ELF magic is checked along with minimal header sanity.
  Truncated or corrupt headers are `Suspicious` with an explanation.

Human output adds a one-line security suffix to files that are not clean:

```text
$ guara invoice ./downloads
downloads/invoice.pdf.exe (12 bytes, modified: 1700000000, mode: 100644)
  security: Suspicious: executable extension '.exe' follows another extension
```

`--json` puts `verdict` and a `reasons[]` array at the top level of each hit.
A summary of counts by verdict is printed to **stderr** unless `--quiet` is set:

```sh
guara todo -q                 # results only, no stats or security summary
guara todo                    # stderr: security: 3 clean, 1 suspicious, 0 high risk
```

### Limitations and false positives

These heuristics are **not** an antivirus and will produce false positives.
Packed installers, archives, media containers, and legitimate setuid binaries
routinely score as `Suspicious`. There is **no** real-time protection, no
guaranteed detection, and no network lookup; Guará only inspects local file
properties and never modifies, moves, or deletes a file as part of a search.

### Deep scan (opt-in)

Deeper scanning is never on by default and each backend is a Cargo feature, so
the default build pulls in no ClamAV/YARA/hash dependencies. Enable
`--deep-scan` (alias `--security`) and point it at one or more backends:

```sh
# clamd over a Unix socket (build with --features security-clamav)
guara suspicious ./downloads --deep-scan --clamd-socket /run/clamav/clamd.ctl

# YARA rules from a directory of .yar/.yara files (--features security-yara)
guara suspicious ./downloads --deep-scan --rules-dir ./rules

# Known-bad SHA-256 list, one hex digest per line (--features security-hash)
guara suspicious ./downloads --deep-scan --hash-db ./known-bad.txt
```

A backend hit raises the file to `High Risk`. If `--deep-scan` is requested and
no backend is usable, Guará explains how to enable one and exits with code `2`
instead of failing silently. A missing hash DB is a warning, not a hard error.

### Quarantine (explicit, report-only by default)

Reporting never mutates files. Quarantine only happens when you pass
`--quarantine` **and** a destination directory, and even then it is a
**move/rename** into that directory plus a manifest entry. Files are never
deleted in place, and a file (or clean file) is never touched otherwise.

```sh
guara suspicious ./downloads --quarantine --quarantine-dir ./vault
```

`--quarantine-dir` is created if missing. Each moved file is recorded in
`quarantine-manifest.tsv` inside that directory with its timestamp, original
path, new path, verdict, and reason codes. If a move cannot be performed (for
example across filesystems), the file is left exactly where it was and an error
is reported.

### Threat model

Guará **does** help a local user notice packed-looking blobs, odd modes, and
suspicious names, and can optionally consult a local `clamd`, local YARA rules,
or a local known-bad hash list.

Guará **does not** stop processes, hook syscalls, or protect the system in real
time, and does **not** guarantee detection of malware. Everything is local;
there is no network reputation lookup and no telemetry. Files being inspected
are untrusted: parsers must fail safe (skip and record), never crash.

## Configuration

Guará reads an optional TOML config (`guara config` prints the exact path for
your OS). A missing file is fine, built-in defaults are used.

```sh
guara config
# path: /home/you/.config/guara/config.toml
# { "search": { "ignore": [], "threads": null, ... } }
```

Example `config.toml`:

```toml
[search]
ignore = ["*.tmp", "target"]  # extra global ignore patterns
threads = 8                   # worker threads (null = auto)
max_file_size = 10485760      # bytes
max_depth = 4
follow_symlinks = false
case_insensitive = false
whole_word = false
context = 0

[security]
enabled = true                # run the always-on heuristics
entropy_threshold = 7.2       # bits/byte; at or above is Suspicious
sample_limit = 1048576        # bytes read per file for entropy/header checks
# executable_extensions = ["exe", "scr", "bat"]   # override the double-extension set
suspicious_patterns = ["my-secret-token"]  # extra case-insensitive path substrings to flag
```

Precedence is: **CLI flag > config file > built-in default**. `.gitignore` and
`.ignore` files are always honored, symlinks are not followed by default, and a
single unreadable directory never aborts a search.

## Persistent index and watching

The index is an optional SQLite cache of paths plus size, mtime, and mode. It
makes repeat queries cheap without ever becoming the source of truth: contents
are always read live, stale or vanished rows are rescanned, and a missing index
falls back to a normal walk.

```sh
guara index                    # build/update incrementally (default root: .)
guara index ./src ./tests      # index specific roots
guara reindex                  # rebuild from scratch (every row rewritten)
guara index status             # path count, DB path, last updated, roots
guara history                  # recent queries (local only)
guara history --limit 5
```

`--db <PATH>` overrides the database location on any of these commands. The
default is `<data_dir>/index.db`, resolved with the same `directories` crate as
the config file. Rows store absolute paths, and the index never indexes its own
database file.

`--hash` also stores a SHA-256 content hash per file. It needs a build with
`--features security-hash`; without one, rows are stored without a hash and
Guará says so.

### How search uses the index

`guara <pattern>` uses the index when it exists **and** its recorded roots cover
the roots you asked for; otherwise it walks live. `--no-index` always walks.

- Name and metadata filters (extension, size, date) are answered from indexed
  columns, and no tree walk happens: files created after the last `guara index`
  are not found until you re-index.
- Contents are read live, and every candidate is `stat`ed first. A file whose
  size or mtime changed since it was indexed is rescanned rather than trusted.
- Without `--quiet`, stderr notes `(index: N candidates, N stale, N missing)` so
  an indexed search explains itself.

### `serve`

```sh
guara serve                    # index the roots, then watch for changes
guara serve ./downloads --debounce 500
guara serve ./downloads --watch-term invoice --watch-term .exe
```

`serve` runs in the foreground until Ctrl-C (`SIGINT`/`SIGTERM`). Each debounced
burst of filesystem events becomes one SQLite transaction; on shutdown the batch
in flight finishes committing, so the database is never truncated. Watched terms
are remembered locally and reported when a newly indexed file matches them by
name or contents. Search history and watched terms live in the same local
database; nothing is sent over the network.

OS service units (systemd/launchd/Windows Service) are **not** part of v0.1. Run
`serve` yourself, or under whatever process manager you already use.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Success, at least one hit (or non-search command succeeded) |
| 1 | Success, no hits |
| 2 | Usage / config parse error (this includes `--deep-scan` with no usable backend) |
| 3 | Run finished with partial filesystem errors |

Note: files skipped by an explicit filter (extension, size, date, or the default
binary policy) are not errors and do not produce exit code 3.

## Building with deep-scan backends

Deep scanners are opt-in Cargo features; the default CI build leaves them off:
ClamAV uses a plain clamd Unix socket, YARA uses the pure-Rust `yara-x` crate
(no system `libyara` required), and the hash DB uses `sha2`.

```sh
cargo build -p guara --features security-clamav
cargo build -p guara --features security-yara
cargo build -p guara --features security-hash
cargo build -p guara --features security-clamav,security-yara,security-hash
cargo test  --all-features
```

## Tray companion

`cargo build -p guara-tray` builds a Tauri 2 tray app with a quick-search
palette. It links the same engine as the CLI, so results, security signals, and
pinned scopes match `guara search`. `guara serve --socket[=PATH]` exposes the
same request/response protocol over a local Unix socket; see
[docs/tray.md](docs/tray.md).

What works where (the manual checklist in [docs/tray-qa.md](docs/tray-qa.md)
closes a row):

| Capability | macOS | Linux | Windows |
| ---------- | ----- | ----- | ------- |
| Tray build | built and verified | expected (`libwebkit2gtk-4.1-dev`) | expected |
| Tray launch (process starts, stays up) | smoke-tested | needs QA | needs QA |
| Tray states (idle / indexing / threat) | logic covered by tests, UI needs QA | needs QA | needs QA |
| Global hotkey palette | needs QA | needs QA | needs QA |
| Auto-start toggle (off by default) | preference covered by tests, login item needs QA | needs QA | needs QA |
| Open hit with `$EDITOR` / OS opener | expected (`open`) | expected (`xdg-open`) | expected (`cmd /C start`) |
| `guara serve --socket` IPC | verified, covered by tests | covered by tests | not implemented |

Interactive rows say "needs QA" on purpose: the tray logic, the IPC protocol,
and the search engine are covered by `cargo test`, but nobody has clicked
through a real tray session yet on any desktop.

The tray crate is not a default workspace member, so `cargo build`, `cargo
test`, and `cargo clippy` stay on the CLI and library crates.

## Feature status

**Stable in v0.1** (covered by tests, safe to script against):

| Feature | Command or flag |
| ------- | --------------- |
| Name and content search, filters, AND/OR terms | `guara <pattern>` with `--ext`, `--min-size`, `--after`, `--or`, `-t` |
| JSON, CSV, HTML, compact, and table output | `--json`, `--csv`, `--html`, `--compact`, `--table` |
| Always-on security heuristics | every hit carries a `verdict` |
| Configuration file and precedence | `guara config` |
| Persistent SQLite index, incremental updates | `guara index`, `guara reindex`, `guara index status` |
| Index-aware search with live fallback | `guara <pattern>`, `--no-index` to force a walk |
| Watching daemon with graceful shutdown | `guara serve` |
| Search history and watched terms | `guara history` |
| Exit codes and stop-on-partial-error semantics | see [Exit codes](#exit-codes) |
| Terminal browser | `guara tui` |

**Experimental** (works, but the interface may change before v0.2):

| Feature | Why it is experimental |
| ------- | ---------------------- |
| Quick-search palette | `crates/guara-tray`, desktop shell; verified on macOS only |
| Local IPC protocol over a socket | `guara serve --socket`; Unix only, versioned by `PROTOCOL_VERSION` |
| Deep scanners | opt-in Cargo features, need a local clamd / YARA rules / hash DB |
| Report-only quarantine | explicit flag plus destination; manifest format may change |
| Benchmarks | `benches/run.sh` is informational, not a gate |

**Not in v0.1**: plugins, online hash lookup, remote filesystem guarantees,
real-time protection, and OS service units. The reasons are in
[docs/architecture/overview.md](docs/architecture/overview.md#non-goals-for-v01).

## Packaging

| Channel | Status |
| ------- | ------ |
| Release archives (Linux x86_64, Windows x86_64) | built by the tagged pipeline |
| Shell installer script | published by the tagged pipeline |
| `cargo install guara` | planned for the first crates.io publish |
| Homebrew tap | planned |
| Scoop bucket | planned |
| AUR | planned |
| AppImage / `.deb` / `.rpm` | planned |

The release archives and the shell installer are produced by the tagged
pipeline; the remaining channels are planned. See
[docs/RELEASE.md](docs/RELEASE.md) for the checklist that produces them and the
notes for the remaining channels.

## Documentation

- [docs/architecture/overview.md](docs/architecture/overview.md): crates, data
  flow, security model, and non-goals.
- [docs/architecture/index.md](docs/architecture/index.md): why SQLite and how
  the index stays a cache.
- [docs/tray.md](docs/tray.md): tray app, IPC protocol, per-OS support.
- [docs/man/guara.1](docs/man/guara.1): man page (`man ./docs/man/guara.1`).
- [CHANGELOG.md](CHANGELOG.md): what changed per release.
- [SECURITY.md](SECURITY.md): vulnerability reporting and security scope.
- [CONTRIBUTING.md](CONTRIBUTING.md) and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): how to work on the project.

## License

Licensed under the [MIT license](LICENSE).
