# 04. Output formats

Guara prints human output by default and machine output on request.
Stats and warnings always go to stderr, so `--json` and `--csv` on
stdout stay clean for pipes.

## Human output

```sh
guara todo ./src
```

One block per file with metadata, then matching lines. Files that are
not clean get a one line `security:` suffix (see `07-security.md`).

Short forms for scanning:

```sh
guara todo --compact ./src
guara todo --table ./src
```

`--compact` prints one line per file. `--table` prints a tabular summary.

## JSON (NDJSON)

```sh
guara todo --json ./src
```

Emits one JSON object per file result (newline-delimited JSON, not an
array). Each hit carries `path`, `content_matches`, `metadata`,
`verdict`, and `reasons`.

Pipe it without losing structure, because stats stay on stderr:

```sh
guara todo --json ./src | jq -r '.path'
```

## CSV and HTML

```sh
guara todo --csv ./src
guara todo --html ./src > report.html
```

`--csv` writes rows with path, match, line number, line, and metadata.
`--html` writes a self-contained report you can open in a browser.

## Quiet and color

```sh
guara todo -q ./src
```

`-q` (or `--quiet`) prints results only. It silences stats and the
security summary on stderr.

```sh
guara todo --color never ./src
NO_COLOR=1 guara todo ./src
```

Color is used only when stdout is a TTY. `--color always|never|auto`
overrides that, and `NO_COLOR` disables color.

## Debug logging

```sh
guara todo -vv ./src 2> guara-debug.log
```

`-v`, `-vv`, and `-vvv` raise tracing detail on stderr. `RUST_LOG`
wins if it is set.

Next: [05. Index and history](05-index-history.md) to make repeat
searches cheap.
