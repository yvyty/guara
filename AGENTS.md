# AGENTS.md — Guará

Instructions for coding agents working in this repository. Guará is a Rust
workspace: a filesystem search, tracking, and light-security CLI at v0.1.0.

Product intent, feature status, and per-OS caveats live in `README.md` and
`docs/`. Do not duplicate product decisions into this file; keep it about how to
work in the repository.

---

## Layout

```text
.
├── crates/
│   ├── guara/          # binary: clap CLI + ratatui terminal rendering
│   ├── guara-core/     # library: all engine logic (no clap, no terminal/GUI)
│   └── guara-tray/     # binary: Tauri 2 tray shell (NOT a default member)
├── tests/fixture_tree.rs   # scripted corpus shared by integration tests
├── benches/            # informational benchmark, not a gate
├── docs/               # architecture, tray, release, man page
└── .github/workflows/  # ci.yml (fmt/clippy/test/build), release.yml (tags)
```

Dependency direction is strict: `guara` and `guara-tray` depend on `guara-core`;
the library never depends on a binary. Pure state machines live in the library
(`guara_core::tui`, `guara_core::tray`, `guara_core::ipc`) so they can be tested
without a terminal or a desktop. Keep `guara-core` free of `clap`, `ratatui`,
`crossterm`, and `tauri`.

`guara-tray` is a workspace member but excluded from `default-members`, so
`cargo build`, `cargo test`, `cargo fmt`, and `cargo clippy` all stay on the CLI
and library crates. Build it explicitly.

---

## Commands

```sh
cargo build -p guara              # debug binary at target/debug/guara
cargo build -p guara --release
cargo run -p guara -- --help
cargo test                        # default members only, default features
cargo test -p guara-core          # library only
cargo test --all-features         # builds yara-x + sha2; slow, but CI-only check
cargo fmt --check
cargo clippy --all-targets -- -D warnings          # what CI runs
cargo clippy --all-targets --all-features -- -D warnings   # local full check
cargo build -p guara-tray         # needs a desktop toolchain (WebKit on Linux)
```

- `rustfmt`: edition 2021, `max_width = 100` (`rustfmt.toml`). Run
  `cargo fmt`, never hand-format against it.
- Clippy warnings are errors. MSRV is 1.74 (`clippy.toml`, workspace
  `rust-version`).
- CI's clippy/test jobs use **default features** only. Deep-scan backends must
  stay opt-in; never enable them in the default workflow.
- `.gitignore` ignores `/target` and `Cargo.lock`; do not commit build output or
  generated databases/corpora.

Benchmark (informational only, safe to skip):

```sh
./benches/run.sh            # appends numbers to benches/results.md
./benches/run.sh --keep     # also keep the generated corpus
```

---

## Architecture and data flow

```text
roots ──► walker (ignore crate) ──► candidates
index (SQLite) ──► rows ───────────┤
                                   ▼
                          matcher (name + content)
                                   │
                      always-on heuristics per hit
                                   ▼
        results ──► output (human/JSON/CSV/HTML/compact/table)
                └──► TUI browser
                └──► IPC response (tray palette, daemon socket)
                ──► report-only quarantine (explicit flag only)
```

Every consumer goes through the same matcher and heuristics, so the CLI, TUI,
tray, and socket cannot disagree about what a hit is (`docs/architecture/overview.md`).

Module responsibilities in `guara-core`:

| Module | Role |
| ------ | ---- |
| `fs` | walker (`ignore`), `WalkOptions`, depth/global-ignore handling |
| `search` | `FileFilter`, regex build, content read (mmap >1 MiB), `parse_size`/`parse_date` |
| `output` | `FileResult` -> human/JSON/CSV/HTML/compact/table, stats, security suffix |
| `security` | always-on heuristics: entropy, modes, double extension, PE/ELF headers |
| `deepscan` | opt-in backends behind Cargo features; `NO_BACKEND_EXIT_CODE = 2` |
| `quarantine` | explicit move + manifest, never delete in place |
| `config` | TOML load + CLI-merge precedence |
| `index` | SQLite schema, `covers()`, incremental `update()`, history, watched terms |
| `watch` | `notify` session, debounce bursts, event -> `Change` mapping |
| `serve` | foreground daemon loop, pure over an `AtomicBool` shutdown flag |
| `ipc` | versioned newline-delimited JSON protocol + Unix socket transport |
| `tray` / `tui` | pure state machines and preference persistence |

`guara/src/cli.rs` is the only place that turns CLI flags into engine options and
maps outcomes to exit codes. `collect_search` is shared by `search` and `tui`.

---

## Non-obvious behavior and gotchas

- **Exit codes** (`guara/src/cli.rs:561`): `0` hits/success, `1` no hits, `2`
  usage/config error (including `--deep-scan` with no usable backend), `3`
  partial filesystem errors. Files skipped by an explicit filter are *not*
  errors.
- **Statistics go to stderr** so `--json`/`--csv` stdout stays clean. `--quiet`
  silences stats and the security summary; `-v`/`-vv`/`-vvv` raise tracing
  levels (`RUST_LOG` wins if set).
- **`--json` is NDJSON**: one JSON object per file result, not one array.
- **The index is a cache, never the truth.** Content is always read live; a
  candidate is `stat`ed first and rescanned if size/mtime changed. Index-backed
  search only happens when the recorded roots `covers()` the requested roots;
  otherwise it falls back to a live walk. `--no-index` forces a walk.
  - `guara index status` deliberately does not create a database just to report
    on it.
  - The index never indexes its own database file, even if the DB lives inside a
    root.
  - Roots are canonicalized before storage/walk, so `/tmp` (a symlink on macOS)
    and the real path agree. Result paths are then *rebased* to match what a live
    walk from the requested root would print.
  - `--db <PATH>` overrides the location on every index-aware command; use it in
    tests and probing. Never write to a user's real DB path in a test.
  - `--hash` stores SHA-256 per row but needs a build with `security-hash`;
    without it, rows are stored without a hash and a note is printed.
- **Deep scanners are opt-in Cargo features** and default-off:
  `security-clamav` (clamd Unix socket; no extra crate), `security-yara`
  (`yara-x`), `security-hash` (`sha2`). `--deep-scan` with no usable backend
  prints how to enable one and exits `2`, not a panic.
- **Quarantine is report-only by default** and `--quarantine` *requires*
  `--quarantine-dir` (clap `requires`). Files are moved with a manifest; a
  cross-device move is reported and the file stays put. Never delete in place and
  never quarantine by default.
- **`guara serve --socket`** uses `require_equals = true`: bare `--socket` uses
  the default path, but an explicit path must be `--socket=PATH`. The socket is
  Unix-only; Windows returns `Unsupported` and the tray uses the shared library.
- **`guara tui` falls back to plain output** when stdout is not a TTY, so it
  stays scriptable (and is what CI tests exercise).
- **IPC protocol** is `PROTOCOL_VERSION`-gated. A mismatched `hello` gets an
  `error` response, never a crash. Malformed lines get an error response and the
  server keeps accepting.
- **Security heuristics are signals, not antivirus.** They will false-positive on
  packed installers, archives, and legitimate setuid binaries. The permission
  check is a documented no-op on Windows.

---

## Conventions

- Comment the *reason*, never narrate the code. Do not add comments unless they
  explain a non-obvious why.
- Prefer explicit errors (`thiserror`-style enums in `guara-core`; the binary
  returns `i32` exit codes and prints to stderr). Avoid `unwrap` outside tests.
- No `TODO` that hides a missing acceptance criterion.
- **No em dashes** in source or docs; use commas, periods, or parentheses.
- Files being inspected are untrusted input: parsers must skip-and-record, never
  crash.
- Adding a new production dependency is a real decision; check whether the
  existing crates already cover it before adding one.

---

## Testing

- Unit tests live in-module under `#[cfg(test)]`; integration tests are in each
  crate's `tests/`.
- All integration suites share one scripted corpus: `tests/fixture_tree.rs`,
  pulled in with `#[path = "../../../tests/fixture_tree.rs"]`. Change the fixture
  in one place, not per-crate. It deliberately has **8 files** (CLI tests assert
  `8 added` / `path count: 8`), contains `guara-needle`, a `.gitignore`d dir, a
  `invoice.pdf.exe` stub, and a high-entropy blob.
- Fixtures are synthetic and tiny (`MAX_FIXTURE_BYTES = 4096`). Never commit live
  malware, ransomware, real executable payloads, or large corpora.
  `crates/guara-core/tests/integration.rs` enforces this:
  `the_checked_in_tree_contains_no_executable_payload` walks the whole repo and
  fails on large files or executable extensions. It also asserts `AGENTS.md`
  exists at the repo root, so do not delete this file.
- Filesystem tests use `tempfile` trees, never `$HOME`.
- Property tests (`crates/guara-core/tests/properties.rs`, `proptest`) cover
  regex flags, glob ignores, and size/date parsing.
- Prefer asserting flags, exit codes, and JSON fields over snapshotting whole
  `--help` pages.

Common suites:

```sh
cargo test -p guara-core --test integration
cargo test -p guara-core --test properties
cargo test -p guara --test integration
cargo test -p guara --test cli
```

---

## Platform notes

- Windows/Linux/macOS are all built by CI's `build-smoke` and `release` jobs.
- Unix-only code is guarded with `#[cfg(unix)]`: permission bits, the IPC Unix
  socket, and some watcher tests. Provide a `#[cfg(not(unix))]` counterpart that
  degrades cleanly (usually `None`/`Unsupported`).
- The tray app is verified on macOS only; Linux needs `libwebkit2gtk-4.1-dev`
  and both Linux and Windows tray paths are still "needs QA" per `docs/tray.md`.
  `docs/tray-qa.md` is the manual checklist.

---

## Git and releases

- Tracks `main` plus `plan/branch-<N>` branches; CI runs on `main` and
  `plan/branch-*`.
- Do not commit unless asked. Do not force-push `main`.
- One logical change per commit; explain the why.
- Versioning is workspace-wide (`0.1.0`) and `CHANGELOG.md` follows Keep a
  Changelog. `docs/RELEASE.md` is the tag checklist; the release workflow builds
  macOS arm64/x86_64, Linux x86_64, and Windows x86_64 archives.

---

## Do not

- Collapse `guara` and `guara-core`, or let `guara-core` depend on
  `clap`/`ratatui`/`tauri`.
- Follow symlinks by default, or abort a whole search because one directory is
  unreadable.
- Print stats or security summaries on stdout under `--json`.
- Enable deep-scan features in the default workflow, or add network reputation
  lookups / telemetry.
- Add file deletion or quarantine-by-default behavior.
- Commit generated databases, corpora, or real executable payloads.