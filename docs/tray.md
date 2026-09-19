# Tray companion and local IPC

The tray app (`crates/guara-tray`) is a thin Tauri 2 shell over the same engine
as the CLI. Tray states, tooltip text, recent queries, pinned scopes, and the
auto-start preference live in `guara-core::tray`; search, status, recents,
pinning, and heuristic scans all go through `guara-core::ipc`, so the tray, the
palette, and the daemon socket cannot drift from the CLI.

## Two ways to talk to the engine

1. **Shared library** (default for the tray). The shell calls
   `IpcContext::dispatch` directly. No socket, no daemon required.
2. **Local socket** (optional, Unix only). `guara serve --socket[=PATH]` listens
   on `<data_dir>/guara.sock` and answers the same protocol, so an external
   client can use the running daemon.

On Windows the socket transport is not implemented in this build: the API
returns `Unsupported` with a clear message and the tray uses the shared library.
Windows named pipes are later work.

## Protocol

One newline-delimited JSON request per connection, exactly one JSON response
back. `version` is `ipc::PROTOCOL_VERSION`; a mismatched `hello` is answered with
an `error` response instead of a crash.

### `search`

```json
{"request":"search","query":"invoice","root":"/Users/me/Downloads","limit":50}
```

```json
{"response":"hits","hits":[{"path":"/Users/me/Downloads/invoice.pdf.exe","name_matched":true,"size":48213,"modified":1730000000,"verdict":"suspicious"}],"stats":{"files_scanned":1284,"hits":1,"elapsed_ms":37}}
```

`root` defaults to the daemon's first root; `limit` caps hits. This is the same
walker and matcher as `guara search`, so `--max-count`-style early stop and the
always-on heuristics behave identically.

### `status`

```json
{"request":"status"}
```

```json
{"response":"status","index_path":"/Users/me/Library/Application Support/guara/index.db","indexed_paths":20481,"roots":["/Users/me/Downloads"],"watching":true,"socket":false}
```

### Other requests

| Request | Response | Purpose |
| ------- | -------- | ------- |
| `{"request":"hello","version":1}` | `hello` | Handshake plus capability list |
| `{"request":"recents"}` | `recents` | Recent queries, newest first (max 20) |
| `{"request":"pin_scope","root":"/Users/me/work","label":"work"}` | `pinned` | Persist a scope across restarts |
| `{"request":"scan","path":"/Users/me/x"}` | `assessment` | Always-on heuristics for one path |

Malformed input is answered with
`{"response":"error","message":"malformed request: ..."}` and the connection
closes; the server keeps accepting.

## Running the tray

```sh
cargo build -p guara-tray     # needs a desktop toolchain (WebKit on Linux)
./target/debug/guara-tray /path/to/search     # roots are optional positionals
```

- Left-click the tray icon (or `Cmd/Ctrl+Shift+G`) toggles the quick-search
  palette.
- The palette's Enter runs a search, `o` opens the selected hit with `$EDITOR`
  or the OS opener, `s` runs the heuristic scan on it.
- `Start at login` in the tray menu toggles auto-start. It is **off** until the
  user turns it on, and the choice is stored in `<config_dir>/tray.json`.

## What works per OS

| Capability | macOS | Linux | Windows |
| ---------- | ----- | ----- | ------- |
| `cargo build -p guara-tray` | built and verified | expected (needs `libwebkit2gtk-4.1-dev`) | expected |
| Tray launch (starts, stays running) | smoke-tested with a 6 s timeout | needs QA | needs QA |
| Tray icon states idle/indexing/threat | state logic covered by tests, UI needs QA | needs QA | needs QA |
| Global hotkey palette | needs QA | needs QA | needs QA |
| `open` with `$EDITOR`, else OS opener | expected (`open`), logic covered by tests | expected (`xdg-open`) | expected (`cmd /C start`) |
| Auto-start toggle (off by default) | preference covered by tests, login item needs QA | needs QA | needs QA |
| Daemon socket (`guara serve --socket`) | verified, covered by tests | covered by tests | not implemented |

"Needs QA" means the code path builds and is documented, but nobody has clicked
through it on that desktop yet. Linux and Windows verification is deferred for
v0.1; macOS is launch-tested only.
`docs/tray-qa.md` is the checklist for closing those rows, and the tray state
machine, the protocol, and the search engine are already covered by
`cargo test`.