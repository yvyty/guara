# Contributing to Guará

Thanks for taking a look. This project is a Rust workspace with a small public
API and a bias for honest, testable behaviour over clever behaviour.

## Before anything else

Read [`AGENTS.md`](AGENTS.md) before writing code. Product intent and feature
status live in [`README.md`](README.md) and [`docs/`](docs/); the crate sources
are the source of truth for how things actually work.

## Setup

```sh
git clone <your fork>
cd guara
cargo build -p guara
cargo run -p guara -- --help
```

The default workspace members are `crates/guara` and `crates/guara-core`. The
tray app (`crates/guara-tray`) needs a desktop toolchain and is built explicitly:

```sh
cargo build -p guara-tray
```

Deep scanners are opt-in features and stay off in the default workflow:

```sh
cargo test --all-features
```

## The checks that matter

Run these before opening a pull request. They are the same commands CI runs:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build -p guara
```

- `rustfmt` is law: format, do not hand-format against it.
- Clippy warnings are errors.
- Tests come with the change, not after it. Filesystem tests use `tempfile`
  trees, never `$HOME`. Index tests must not touch the user's real database.
- Prefer explicit errors (`thiserror` / `anyhow` at the binary edge) over
  `unwrap` outside tests.

## Style and conventions

- Match the surrounding code. Read a similar module before writing a new one.
- Keep `guara-core` free of `clap` and of terminal or GUI dependencies. Pure
  state machines (TUI, tray, IPC) belong in the library so they can be tested
  without a terminal or a desktop.
- Never add a comment that narrates the code; comment the reason instead.
- No em dashes in source or docs. Use commas, periods, or parentheses.

## Security rules for contributions

- Security features are report-only by default. Quarantine requires an explicit
  flag plus a destination, and never deletes in place.
- Never commit live malware, ransomware samples, or weaponised files. Synthetic
  fixtures only: tiny stub headers, high-entropy random bytes, and
  `invoice.pdf.exe`-style names. `crates/guara-core/tests/integration.rs` guards
  this and will fail on a large executable payload in the tree.
- Do not add telemetry, and do not call out to VirusTotal or any network
  reputation API.

## Commits and pull requests

- One logical change per commit. Explain the why in the message; the diff
  already shows the what.
- Do not commit generated databases, corpora, or `target/` output.
- Do not force-push `main`.
- Pull requests should explain the behavior change, the commands you ran to
  verify it, and anything still open or untested.

## Reporting bugs

Include the command you ran, the version (`guara --version`), your OS, and the
exit code. If the issue involves the index, add the output of
`guara index status`. Avoid pasting file contents that may be private; a
synthetic reproduction is more useful anyway.