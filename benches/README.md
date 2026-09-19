# Benchmarks

Informational only, never a CI gate. The question these numbers
answer is "is the CLI in the same league as `ripgrep` and `fd` on a synthetic
corpus", not "is it faster".

## Running

```sh
./benches/run.sh          # generates the corpus, measures, appends numbers
./benches/run.sh --keep   # same, but keeps the generated corpus
CORPUS_DIR=/tmp/corpus ./benches/run.sh
```

The script:

1. builds `target/release/guara` when needed (`cargo build --release -p guara`),
2. writes a deterministic corpus to a temporary directory: 200 directories x
   10 files x 120 lines, every 97th line containing `guara-needle`,
3. times `guara <needle>`, `guara --no-index <needle>`, `rg -l <needle>`, and
   `fd -t f <needle>` (the last two only when installed), and
4. appends a table to [`results.md`](results.md).

`ripgrep` and `fd` are optional; a missing tool is recorded as skipped rather
than faked. `fd` matches file names only, so it is a yardstick for name search,
not an equivalent of content search.

There is no `cargo bench` target on purpose: the workspace does not depend on a
benchmarking harness, and the corpus-plus-stopwatch script above is what the
project accepts.

## Reading the numbers

- Compare `guara` and `rg` on the same corpus; `guara` also runs the always-on
  heuristics and records metadata per hit, which `rg -l` does not.
- `guara --no-index` forces a live walk. With an index built over the corpus,
  `guara <needle>` answers from SQLite instead; build one with
  `guara index <corpus>` first if you want to see that path.
- Wall clock includes process startup, so tiny corpora mostly measure launch
  time.
- Numbers are machine-specific. Re-run before comparing commits rather than
  trusting a table from another box.
