//! Property tests for the parsing and matching rules where edge cases are
//! cheaper to sweep than to enumerate.
//!
//! Every suite is bounded so CI time stays predictable: pure string properties
//! run a few hundred cases, the ones that touch the filesystem run far fewer.

#[path = "../../../tests/fixture_tree.rs"]
mod fixture_tree;

use guara_core::fs::{self, WalkOptions};
use guara_core::search::{self, SearchOptions};
use proptest::prelude::*;

fn case_budget(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Words made of alphanumerics, the shape a real search token has.
fn word() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,6}"
}

/// Lines of words separated by spaces.
fn line() -> impl Strategy<Value = String> {
    prop::collection::vec(word(), 1..8).prop_map(|words| words.join(" "))
}

proptest! {
    #![proptest_config(case_budget(256))]

    /// A literal pattern, escaped and run as a regex, matches exactly the lines
    /// that contain the literal: the `--regex` flag only changes how the
    /// pattern is read, never what counts as a hit.
    #[test]
    fn escaped_literal_regex_matches_only_lines_containing_the_literal(
        text in line(),
        needle in word(),
    ) {
        let options = SearchOptions {
            patterns: vec![regex::escape(&needle)],
            regex: true,
            ..SearchOptions::default()
        };
        let regexes = search::build_regexes(&options).expect("escaped literals always compile");
        prop_assert_eq!(
            regexes[0].is_match(text.as_bytes()),
            text.contains(&needle)
        );
    }

    /// Whole-word mode matches only complete tokens, so `fn` never fires on
    /// `fnord`.
    #[test]
    fn whole_word_matches_only_complete_tokens(
        text in line(),
        needle in word(),
    ) {
        let options = SearchOptions {
            patterns: vec![needle.clone()],
            whole_word: true,
            ..SearchOptions::default()
        };
        let regexes = search::build_regexes(&options).expect("word patterns compile");
        let token_present = text.split_whitespace().any(|token| token == needle);
        prop_assert_eq!(regexes[0].is_match(text.as_bytes()), token_present);
    }

    /// Case-insensitive matching is symmetric in case.
    #[test]
    fn ignore_case_matches_regardless_of_the_pattern_case(
        text in line(),
        needle in word(),
    ) {
        let options = SearchOptions {
            patterns: vec![needle.to_uppercase()],
            ignore_case: true,
            ..SearchOptions::default()
        };
        let regexes = search::build_regexes(&options).expect("patterns compile");
        prop_assert_eq!(
            regexes[0].is_match(text.as_bytes()),
            text.to_lowercase().contains(&needle.to_lowercase())
        );
    }

    /// `parse_size` is exactly the inverse of its documented suffix table.
    #[test]
    fn parse_size_applies_the_documented_multiplier(
        value in 0u64..1_000_000,
        suffix in prop::sample::select(vec!["", "b", "B", "k", "kb", "K", "KB", "m", "mb", "M", "MB", "g", "gb", "G", "GB"]),
    ) {
        let expected_multiplier = match suffix.to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kb" => 1024,
            "m" | "mb" => 1024 * 1024,
            _ => 1024 * 1024 * 1024,
        };
        let parsed = search::parse_size(&format!("{value}{suffix}"));
        prop_assert_eq!(parsed, Some(value * expected_multiplier));
    }

    /// Unknown suffixes are rejected rather than silently treated as bytes.
    #[test]
    fn parse_size_rejects_unknown_suffixes(
        value in 1u64..100_000,
        suffix in "[a-z]{1,3}",
    ) {
        prop_assume!(!matches!(suffix.as_str(), "b" | "k" | "kb" | "m" | "mb" | "g" | "gb"));
        prop_assert_eq!(search::parse_size(&format!("{value}{suffix}")), None);
    }

    /// Dates accept exactly the days the calendar has room for, and nothing
    /// else: this is the boundary `--after` / `--before` depend on.
    #[test]
    fn parse_date_accepts_only_plausible_days(
        year in 1970u32..2100,
        month in 0u32..14,
        day in 0u32..33,
    ) {
        let parsed = search::parse_date(&format!("{year:04}-{month:02}-{day:02}"));
        let expected = (1..=12).contains(&month) && (1..=31).contains(&day);
        prop_assert_eq!(parsed.is_some(), expected);
    }

    /// A record with the wrong number of dashes is not a date.
    #[test]
    fn parse_date_rejects_other_shapes(parts in 1usize..5) {
        let text = (0..parts).map(|index| index.to_string()).collect::<Vec<_>>().join("-");
        prop_assume!(parts != 3);
        prop_assert_eq!(search::parse_date(&text), None);
    }
}

proptest! {
    #![proptest_config(case_budget(32))]

    /// `*.ext` in the global ignore list excludes files with that extension and
    /// leaves everything else alone: the glob parsing users configure.
    #[test]
    fn global_ignore_glob_excludes_matching_extensions(ext in word()) {
        // `keep.txt` must survive, so the generated extension cannot be `txt`.
        prop_assume!(ext != "txt");
        let dir = tempfile::TempDir::new().expect("temp dir");
        let keep = fixture_tree::write(dir.path(), "keep.txt", "keep me\n");
        let drop = fixture_tree::write(dir.path(), &format!("drop.{ext}"), "drop me\n");

        let walk = fs::walk(
            &[dir.path().to_path_buf()],
            &WalkOptions {
                global_ignore: vec![format!("*.{ext}")],
                ..WalkOptions::default()
            },
        );
        let names: Vec<std::path::PathBuf> =
            walk.entries.iter().map(|entry| entry.path.clone()).collect();

        prop_assert!(names.contains(&keep), "the non-matching file must stay: {names:?}");
        prop_assert!(
            !names.contains(&drop),
            "*.{ext} should have excluded {}: {names:?}",
            drop.display()
        );
    }
}
