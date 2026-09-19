# 08. Scripting

Guara is built for pipes: machine formats on stdout, diagnostics on
stderr, and stable exit codes.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Hits found (or non-search command succeeded) |
| 1 | No hits, but the run succeeded |
| 2 | Usage or config error (includes `--deep-scan` with no backend) |
| 3 | Finished with partial filesystem errors |

Allow `1` without failing your script:

```sh
set +e
guara needle ./src --json > hits.jsonl
code=$?
set -e
echo "exit code: $code (0 = hits, 1 = no hits)"
```

Treat `3` as the one worth alerting on: the search finished, but some
directories could not be read. Files skipped by an explicit filter
(extension, size, date, binary policy) are not errors.

## NDJSON pipelines

`--json` is newline-delimited JSON (one object per file, not an array):

```sh
guara todo --json -q ./src | jq -r '.path'
guara todo --json -q ./src | jq -c 'select(.verdict != "clean")'
```

`-q` keeps stderr out of the pipe. The first line lists every hit path,
the second keeps only non-clean verdicts.

## Split streams

```sh
guara todo --csv ./src 2> stats.log > hits.csv
```

Results go to `hits.csv`, stats and warnings go to `stats.log`.
Same idea works for `--json` and `--html`.

## Tolerate no hits, fail on partial errors

```sh
set +e
guara needle /some/root --json > out.jsonl 2> err.log
code=$?
set -e
if [ "$code" -eq 3 ]; then echo "partial errors, see err.log"; exit 3; fi
```

## Isolated demo setup

Use `--db` in tests and demos so you never write to the real database:

```sh
guara index ./src --db /tmp/guara-demo.db -q
guara needle ./src --db /tmp/guara-demo.db -q --compact
guara history --limit 3 --db /tmp/guara-demo.db
```

Back to the [guide index](README.md).
