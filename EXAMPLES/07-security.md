# 07. Security

Every search attaches a lightweight verdict to each hit: `Clean`,
`Suspicious`, or `High Risk`, plus a short explanation. This is a
signal, not antivirus. Expect false positives on packed installers,
archives, media files, and legitimate setuid binaries.

## Read the verdict

```sh
guara invoice ./downloads
```

Human output adds a one line `security:` suffix to files that are not
clean. The summary counts on stderr look like:

```text
security: 3 clean, 1 suspicious, 0 high risk
```

Hide both stats and the summary when you want results only:

```sh
guara todo -q ./src
```

## Verdicts as JSON

```sh
guara invoice --json ./downloads | head -n 5
```

Each hit carries a top level `verdict` plus a `reasons` array. Filter
for the interesting ones:

```sh
guara invoice --json -q ./downloads | jq -c 'select(.verdict != "clean")'
```

What the always-on checks look at:

- Entropy: a bounded sample (default 1 MiB) at or above 7.2 bits/byte
  is flagged as packed-like. Tiny files are skipped.
- Permissions (Unix): setuid, setgid, and world-writable executables.
  This check is a no-op on Windows.
- Names: double extensions ending in an executable-like suffix
  (for example `invoice.pdf.exe`), plus optional custom substrings
  from `suspicious_patterns` in the config.
- Headers: PE and ELF magic with minimal sanity checks. Truncated
  headers are `Suspicious` with an explanation.

## Deep scan (opt-in)

Deeper scanning is never on by default. Each backend is a Cargo feature,
and `--deep-scan` (alias `--security`) needs at least one usable backend.
With none enabled, Guara explains how to enable one and exits with code 2.

```sh
guara suspicious ./downloads --deep-scan --clamd-socket /run/clamav/clamd.ctl
```

ClamAV over a local `clamd` Unix socket. Build with
`--features security-clamav`.

```sh
guara suspicious ./downloads --deep-scan --rules-dir ./rules
```

YARA rules from a directory of `.yar` or `.yara` files. Build with
`--features security-yara` (pure Rust, no system libyara needed).

```sh
guara suspicious ./downloads --deep-scan --hash-db ./known-bad.txt
```

Known-bad SHA-256 list, one hex digest per line. Build with
`--features security-hash`. A missing hash DB is a warning, not a
hard error.

A backend hit raises the file to `High Risk`.

## Quarantine (explicit only)

Reporting never mutates files. Quarantine needs both flags at once:

```sh
guara suspicious ./downloads --quarantine --quarantine-dir ./vault
```

This moves flagged files into `./vault` (created if missing) and appends
each move to `quarantine-manifest.tsv` with timestamp, original path,
new path, verdict, and reason codes. Files are never deleted in place,
and a move that cannot be performed (for example across filesystems)
leaves the file where it was and reports an error.

```sh
cat ./vault/quarantine-manifest.tsv
```

Next: [08. Scripting](08-scripting.md) for exit codes, pipes, and
CI-safe patterns.
