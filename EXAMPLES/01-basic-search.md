# 01. Basic search

Start here. Guara searches file names and file contents in one pass.
Search is the default command, so `guara PATTERN` and `guara search PATTERN`
do the same thing.

## Search the current directory

```sh
guara config
```

This finds files whose name contains `config` and files whose contents
contain `config`. Human output shows one block per file with size, mtime,
permissions, then the matching lines.

The explicit form is identical. Use it when you want to be clear in scripts:

```sh
guara search config
```

## Search specific folders

```sh
guara config ./src ./tests
```

Pass one or more roots. The default root is the current directory.
Roots are walked live unless a usable index already covers them
(see `05-index-history.md`).

## Stay shallow

```sh
guara config --max-depth 1
```

Depth `1` lists only top level entries. Increase the number to go deeper.
Useful for big trees when you only care about nearby files.

## Skip the index for one run

```sh
guara config --no-index ./src
```

Forces a live walk even when an index exists. Good for debugging
("is this hit coming from a stale row?").

## Try it

```sh
guara hello .
guara search hello ./src --max-depth 2
```

Next: [02. Match modes](02-match-modes.md) for regex, case, whole word,
context, and AND/OR terms.
