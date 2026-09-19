# Benchmark results

Appended by [`run.sh`](run.sh). Informational only; see [`README.md`](README.md)
for how to read these.

Corpus: 200 directories x 10 files x 120 lines, every 97th line containing
`guara-needle` (2000 files, about 8 MiB). Times are wall clock including
process startup, so they are comparable within one machine and commit only.

| tool | wall clock (ms) |
| ---- | --------------- |
### 2026-09-19 20:45 UTC · commit `d28a6c3`

| tool | wall clock (ms) |
| ---- | --------------- |
| guara guara-needle | 559.1 |
| guara --no-index | 111.4 |
| rg -l | 61.0 |
| fd (names only) | 245.0 |
