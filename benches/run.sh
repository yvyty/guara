#!/usr/bin/env bash
# Informational benchmark: Guará vs ripgrep / fd on a fixed corpus.
#
# asks for numbers, not a gate. Nothing here fails a build: if a
# comparison tool is missing it is skipped, and the numbers are appended to
# benches/results.md for whoever wants to read them.
#
# Usage:
#   ./benches/run.sh              # build a release binary, measure, append
#   ./benches/run.sh --keep       # also keep the generated corpus
#   CORPUS_DIR=/tmp/corpus ./benches/run.sh
#
# Requires bash and python3 (used only for millisecond timing). ripgrep (`rg`)
# and `fd` are optional.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
keep_corpus=0
for argument in "$@"; do
  case "$argument" in
    --keep) keep_corpus=1 ;;
    *) echo "unknown argument: $argument" >&2; exit 2 ;;
  esac
done

bin="${GUARA_BIN:-$repo_root/target/release/guara}"
needle="guara-needle"
dirs=200
files_per_dir=10
lines_per_file=120

if [[ -n "${GUARA_BIN:-}" ]]; then
  echo "using \$GUARA_BIN=$bin"
else
  echo "building release binary..."
  (cd "$repo_root" && cargo build --release -p guara)
fi

corpus="${CORPUS_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/guara-bench-XXXXXX")}"
if [[ ! -f "$corpus/.generated" ]]; then
  echo "writing corpus to $corpus ($((dirs * files_per_dir)) files)..."
  python3 - "$corpus" "$dirs" "$files_per_dir" "$lines_per_file" "$needle" <<'PY'
import os, sys

root, dirs, files_per_dir, lines_per_file, needle = (
    sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
)
for d in range(dirs):
    directory = os.path.join(root, f"dir{d:04d}")
    os.makedirs(directory, exist_ok=True)
    for f in range(files_per_dir):
        path = os.path.join(directory, f"file{f:02d}.txt")
        with open(path, "w", encoding="utf-8") as handle:
            for line in range(lines_per_file):
                if (d + f + line) % 97 == 0:
                    handle.write(f"{needle} appears on line {line}\n")
                else:
                    handle.write(f"filler line {line} in dir{d} file{f}\n")
with open(os.path.join(root, ".generated"), "w", encoding="utf-8") as handle:
    handle.write("generated\n")
PY
fi

time_ms() {
  local label="$1"
  shift
  local ms
  if ! ms=$(python3 - "$@" <<'PY'
import subprocess, sys, time

command = sys.argv[1:]
start = time.perf_counter()
result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
elapsed = (time.perf_counter() - start) * 1000
sys.stdout.write(f"{elapsed:.1f}")
sys.exit(0 if result.returncode in (0, 1) else 1)
PY
  ); then
    echo "  $label: failed" >&2
    return 1
  fi
  echo "  $label: ${ms} ms"
  printf '| %s | %s |\n' "$label" "$ms" >>"$repo_root/benches/results.md"
}

if [[ "$keep_corpus" -eq 0 ]]; then
  trap 'rm -rf "$corpus"' EXIT
fi

commit="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)"

{
  echo ""
  echo "### $(date -u '+%Y-%m-%d %H:%M UTC') · commit \`$commit\`"
  echo ""
  echo "| tool | wall clock (ms) |"
  echo "| ---- | --------------- |"
} >>"$repo_root/benches/results.md"

echo "measuring..."
# Warm-up: the first scan of a fresh corpus is dominated by cold cache, so one
# untimed run keeps the order of the table from mattering.
"$bin" "$needle" "$corpus" -q >/dev/null 2>&1 || true
if command -v rg >/dev/null 2>&1; then
  rg -l "$needle" "$corpus" >/dev/null 2>&1 || true
fi

time_ms "guara $needle" "$bin" "$needle" "$corpus" -q
time_ms "guara --no-index" "$bin" "$needle" "$corpus" --no-index -q
if command -v rg >/dev/null 2>&1; then
  time_ms "rg -l" rg -l "$needle" "$corpus"
else
  echo "  rg: not installed, skipped"
  printf '| rg -l | skipped (not installed) |\n' >>"$repo_root/benches/results.md"
fi
if command -v fd >/dev/null 2>&1; then
  # fd matches file names only; it is here as a name-search yardstick.
  time_ms "fd (names only)" fd -t f "$needle" "$corpus"
else
  echo "  fd: not installed, skipped"
  printf '| fd (names only) | skipped (not installed) |\n' >>"$repo_root/benches/results.md"
fi

echo "numbers appended to benches/results.md"
echo "corpus: $corpus"
