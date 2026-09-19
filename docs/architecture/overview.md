# Guará architecture

Status: v0.1. The index store gets its own
document in [index.md](index.md).

## Crates

| Crate | Kind | Responsibility |
| ----- | ---- | -------------- |
| `guara-core` | library | Walker, search, output types, heuristics, deep scan, quarantine, index, watcher, IPC protocol, tray state, TUI state |
| `guara` | binary | `clap` CLI, terminal rendering, process-level concerns (signals, exit codes) |
| `guara-tray` | binary | Tauri 2 tray shell and quick-search palette over `guara-core` |

The binary depends on the library; the library never depends on a binary, which
is why the TUI state machine, the tray state machine, and the IPC protocol all
live in `guara-core` and stay testable without a terminal or a desktop.

`guara-tray` is a workspace member but not a default member, so `cargo build`,
`cargo test`, and `cargo clippy` stay on the CLI and library crates.

## Data flow

```text
roots ──► walker (ignore) ──► candidate entries
                                  │
index (SQLite) ──► candidate rows ─┤
                                  ▼
                           search matcher (name + content)
                                  │
                        always-on heuristics per hit
                                  ▼
                  results ──► output (human/JSON/CSV/HTML)
                         └──► TUI browser
                         └──► IPC response (tray palette, daemon socket)
                         └──► report-only quarantine (explicit flag only)
```

Every consumer goes through the same matcher and the same heuristics, so the
CLI, the TUI, the palette, and the socket cannot disagree about what a hit is.

## Interfaces

- **CLI**: `clap` derive; `search` is the default command. Statistics go to
  stderr so `--json` stdout stays clean. Exit codes are documented in the
  README and mirrored in `docs/man/guara.1`.
- **TUI** (`guara tui`): `guara_core::tui` holds the pure state machine
  (filter, selection, scrolling, preview); the binary owns key events and
  ratatui rendering. Without a terminal it falls back to plain result output so
  the command stays scriptable.
- **Daemon** (`guara serve`): watches roots, debounces changes into single
  SQLite transactions, and can answer the IPC protocol on a Unix socket.
- **Tray** (`guara-tray`): tray icon states and the quick-search palette. It
  links `guara-core` directly, and the same protocol is available over the
  daemon socket. See [../tray.md](../tray.md).

## Security model

The security layer is a signal, not a shield:

- The always-on heuristics (double extensions, unusual modes, packed-looking
  entropy, executable headers) attach a verdict to each hit. Report-only.
- Deep scanners (ClamAV over a local `clamd`, local YARA rules, a local
  known-bad hash list) are opt-in Cargo features. A build without the backend
  exits with a clear message instead of failing mid-search.
- Quarantine requires `--quarantine` plus `--quarantine-dir`; files are moved
  with a manifest, never deleted in place. A cross-device move is reported as an
  error and the file stays put.
- Files being inspected are untrusted input: parsers skip and record rather
  than crash.

Threat model, as documented for users: Guará **does** help a local user notice
packed blobs, odd modes, and suspicious names. It **does not** stop processes,
hook syscalls, or protect the system in real time, does **not** guarantee
detection, and is entirely local, with no network reputation lookup and no
telemetry.

## Non-goals for v0.1

These are deliberately absent and are not bugs:

- **Plugins.** The library exposes no plugin loading, no dynamic discovery, and
  no third-party extension point. A future plugin point would load from a
  configured directory, receive a hit through a versioned interface, and remain
  report-only by default. Nothing of that is implemented, and the binary has no
  `--plugin` flag to hint otherwise.
- **Online hash lookup / reputation services.** No request is ever made for a
  hash, a path, or a verdict. The opt-in hash comparison reads a local file of
  SHA-256 digests and nothing else.
- **Remote and network filesystems.** Search and the index assume a local
  filesystem with reliable `stat` and rename semantics. Network shares,
  FUSE-mounted object stores, and cloud-synced folders are unsupported as
  roots: they may work, but staleness detection and watcher events are not
  guaranteed, and no retry logic compensates for that.
- **Real-time protection.** No background enforcement, no process interception,
  no automatic action on a finding.
- **OS service units.** `guara serve` is a foreground process; systemd units,
  launchd plists, and Windows services are later work.

Consequences worth stating plainly: a user who wants enforcement should not
deploy Guará for that purpose, and a user who wants exhaustive detection should
treat every verdict here as one weak signal among many.
