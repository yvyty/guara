# 03. Filters

Filters reject files before content is read when possible, so they also
make searches faster. Files skipped by a filter are not errors.

## By extension

```sh
guara todo --ext rs --ext toml .
```

Repeat `--ext` for each extension you want to keep.

## By size

```sh
guara error --min-size 1k --max-size 5M .
```

Suffixes `k`, `M`, and `G` are accepted (`1k` is 1024 bytes).
Use one bound or both.

## By date

```sh
guara panic --after 2024-01-01 --before 2025-01-01 .
```

Dates use `YYYY-MM-DD` and compare file modification time.
Use one bound or both.

## Include binary files

```sh
guara needle --binary .
```

Binary files are skipped for content search by default. Pass `--binary`
when you really want to look inside them (name matches still work
without it).

## Skip slow files

```sh
guara needle --timeout 5 .
```

Skips files that take longer than 5 seconds each instead of blocking
the whole search.

## Depth and symlinks

```sh
guara needle --max-depth 3 --follow-symlinks .
```

`--max-depth` limits recursion. Symlinks are not followed by default,
so pass `--follow-symlinks` only when you intend to descend into them.

Next: [04. Output formats](04-output.md) for JSON, CSV, HTML, and quiet
scriptable output.
