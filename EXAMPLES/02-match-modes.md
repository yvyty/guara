# 02. Match modes

Control how the pattern itself is interpreted. All of these work with
both `guara PATTERN` and `guara tui PATTERN`.

## Regex

```sh
guara -e 'fn\s+\w+' ./src
```

`-e` (or `--regex`) treats the pattern as a regular expression
instead of a literal substring.

## Case-insensitive

```sh
guara -i readme .
```

`-i` (or `--ignore-case`) matches `readme`, `README`, `ReadMe`, and so on.

## Whole word

```sh
guara -w fn ./src
```

`-w` (or `--word`) skips matches inside longer tokens, so `fn` does not
match `fnord`.

## Context lines

```sh
guara println --context 2 ./src
```

Shows 2 lines before and after each content match. Helpful when a bare
matching line is not enough to understand the hit.

## Stop early

```sh
guara todo --max-count 10 .
```

Stops after 10 hits. Stderr notes when the run was capped, so you know
there could be more.

## Multiple terms

The first positional is the pattern and the rest are roots, so extra
patterns use `-t` (or `--term`):

```sh
guara unsafe -t TODO ./src
```

By default terms use AND, meaning a line must contain both. Switch to OR
when either term is enough:

```sh
guara cache -t index --or .
```

Next: [03. Filters](03-filters.md) to narrow by extension, size, date,
and file type.
