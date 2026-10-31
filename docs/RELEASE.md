# Release checklist

Follow this in order for every tag. It covers the tag itself, CI health, notes,
and an artifact smoke test.

## 0. Before the tag

- [ ] The version in the workspace `Cargo.toml` matches the tag you are about to
      cut (`v0.1.0` -> `0.1.0`).
- [ ] `CHANGELOG.md` has a section for this version, with the date, and the
      `[Unreleased]` section is empty again.
- [ ] Anything still open or experimental is named in the release notes.
- [ ] Every command below is green on the commit you will tag:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build -p guara --release
cargo build -p guara-tray          # needs a desktop toolchain
cargo test --all-features
```

- [ ] `cargo test -p guara-core --test properties` and
      `cargo test -p guara --test integration` pass (they ride along with
      `cargo test`, but they are the suites that guard the fixture corpus).
- [ ] The docs match reality: `README.md` feature status, `docs/tray.md` per-OS
      table, `docs/architecture/overview.md` non-goals.

## 1. Tag

- [ ] `git tag -s v0.1.0 -m "v0.1.0"` on the release commit (`-s` if you have a
      signing key; otherwise `git tag -a`).
- [ ] `git push origin v0.1.0`.
- [ ] Watch the `release` workflow: it builds Linux x86_64 and Windows x86_64,
      packages each binary, and attaches the archives to the GitHub release. The
      job fails if any target misses an artifact.

## 2. Notes

- [ ] The release body starts from `CHANGELOG.md` for the version, with the
      announcement draft below adapted, and names the experimental surfaces
      (tray, IPC socket, deep scanners, quarantine manifest format).
- [ ] Assets are listed in the release body, one line per platform.

## 3. Artifact smoke test

Download each archive and run it on the platform it targets (or the closest
available):

- [ ] The release includes `guara-installer.sh` and each archive contains
      `LICENSE-MIT` and `LICENSE-APACHE`.
- [ ] `guara --version` prints the released version.
- [ ] `guara --help` exits 0 and shows the documented flags.
- [ ] `guara needle .` exits 0 with a hit and 1 with no hit; check both.
- [ ] `guara needle . --json | head -1` is valid JSON on stdout with no statistics
      mixed in.
- [ ] `guara index . && guara needle . && guara index status` works against a
      temporary `--db` path.
- [ ] On a platform with an archive, `guara tui needle .` opens the browser and
      `q` exits 0.
- [ ] The archive does not require a system SQLite (the build is `bundled`).

## 4. Channels

- [ ] Release archives: published by the workflow above.
- [ ] `cargo publish -p guara-core && cargo publish -p guara`, once the crates.io
      names are reserved and the first publish is ready.
- [ ] Homebrew tap, Scoop bucket, AUR, and AppImage/`.deb`/`.rpm`: notes only.
      Each needs its own packaging recipe; none of them block the archives.

## 5. After

- [ ] Announce using the draft below.
- [ ] Open issues from anything the smoke test turned up, tagged with the
      version.

## Announcement draft (v0.1.0)

> **Guará v0.1.0 is out**
>
> Guará is a Rust CLI that searches file names and contents in one pass and
> attaches a lightweight security signal to every hit. It is fast to scan,
> honest about what it does not know, and never changes your files unless you
> ask it to.
>
> What is in this first release:
>
> - Name and content search with filters, regex, whole-word, context lines, and
>   JSON/CSV/HTML output.
> - Always-on heuristics (double extensions, odd permissions, packed-looking
>   samples) plus optional local deep scanners behind build features.
> - A persistent SQLite index and a watching daemon, so repeat searches and live
>   tracking stay cheap.
> - A terminal browser (`guara tui`) and an experimental tray companion with a
>   quick-search palette.
> - Report-only quarantine behind an explicit flag and destination.
>
> What it deliberately is not: real-time protection, a detector you can trust on
> its own, or anything that phones home. No telemetry, no network lookups.
>
> Get it from the release archives (Linux x86_64, Windows x86_64) or build it
> from source with `cargo install --path crates/guara`.

## Changelog automation

The changelog is currently maintained by hand, which is why this checklist
starts with "does the section exist". If that becomes tedious, the intended path
is [git-cliff](https://git-cliff.org) driven by conventional commits:

```sh
cargo install git-cliff
git cliff --tag v0.1.0 --prepend CHANGELOG.md
```

Nothing in CI depends on that tool yet; if it is adopted, it should run locally
before tagging rather than rewriting history in CI.
