//! Walk, search, and index integration tests over the shared fixture tree

#[path = "../../../tests/fixture_tree.rs"]
mod fixture_tree;

use std::path::Path;

use guara_core::fs::{self, WalkOptions};
use guara_core::index::{self, IndexQuery, IndexStore, UpdateOptions};
use guara_core::search::{self, SearchOptions};
use guara_core::security::{self, HeuristicConfig, Verdict};

use fixture_tree::{build, Fixture, MAX_FIXTURE_BYTES, NEEDLE};

fn relative_paths(fixture: &Fixture) -> Vec<String> {
    let walk = fs::walk(std::slice::from_ref(&fixture.root), &WalkOptions::default());
    let mut names: Vec<String> = walk
        .entries
        .iter()
        .map(|entry| fixture.relative(&entry.path))
        .collect();
    names.sort();
    names
}

#[test]
fn walk_finds_files_at_every_depth_and_honors_gitignore() {
    let fixture = build();
    let walk = fs::walk(std::slice::from_ref(&fixture.root), &WalkOptions::default());
    let names = relative_paths(&fixture);

    assert!(walk.errors.is_empty(), "walk errors: {:?}", walk.errors);
    for expected in [
        "top.txt",
        "docs/readme.md",
        "src/main.rs",
        "src/lib.rs",
        "nested/deep/deeper/leaf.txt",
        ".gitignore",
    ] {
        assert!(
            names.iter().any(|name| name == expected),
            "missing {expected} in {names:?}"
        );
    }
    assert!(
        !names.iter().any(|name| name.starts_with("ignored/")),
        "the .gitignore'd directory leaked into the walk: {names:?}"
    );
}

#[test]
fn walk_max_depth_stops_before_the_deep_leaf() {
    let fixture = build();
    let walk = fs::walk(
        std::slice::from_ref(&fixture.root),
        &WalkOptions {
            max_depth: Some(1),
            ..WalkOptions::default()
        },
    );
    let names: Vec<String> = walk
        .entries
        .iter()
        .map(|entry| fixture.relative(&entry.path))
        .collect();

    assert!(names.iter().any(|name| name == "top.txt"));
    assert!(
        !names.iter().any(|name| name.contains("leaf.txt")),
        "max_depth 1 must not descend: {names:?}"
    );
}

#[test]
fn search_finds_the_needle_in_contents_and_skips_ignored_files() {
    let fixture = build();
    let walk = fs::walk(std::slice::from_ref(&fixture.root), &WalkOptions::default());
    let options = SearchOptions {
        patterns: vec![NEEDLE.to_string()],
        ..SearchOptions::default()
    };
    let (results, stats) = search::search_entries(&walk.entries, &options);
    let names: Vec<String> = results
        .iter()
        .map(|result| fixture.relative(&result.path))
        .collect();

    for expected in ["top.txt", "docs/readme.md", "src/main.rs"] {
        assert!(
            names.iter().any(|name| name == expected),
            "missing hit {expected} in {names:?}"
        );
    }
    assert!(
        !names.iter().any(|name| name.starts_with("ignored/")),
        "an ignored file was searched: {names:?}"
    );
    assert!(
        !names.iter().any(|name| name == "src/lib.rs"),
        "src/lib.rs does not contain the needle: {names:?}"
    );
    assert_eq!(stats.files_matched, results.len());
}

#[test]
fn index_then_index_backed_search_finds_the_same_files() {
    let fixture = build();
    let db = fixture.tempdir().join("fixture-index.db");
    let mut store = IndexStore::open(&db).expect("open index");

    let stats = store
        .update(
            std::slice::from_ref(&fixture.root),
            &WalkOptions::default(),
            &UpdateOptions::default(),
        )
        .expect("index the fixture tree");
    assert!(stats.errors == 0, "index errors: {stats:?}");
    assert!(store
        .covers(std::slice::from_ref(&fixture.root))
        .unwrap_or(false));

    // Indexed rows use canonical (symlink-resolved) absolute paths, which on
    // macOS differ from the temp dir path, so compare against the same form.
    let canonical_root = index::canonicalize(&fixture.root);
    let query = IndexQuery {
        unders: vec![fixture.root.clone()],
        ..IndexQuery::default()
    };
    let options = SearchOptions {
        patterns: vec![NEEDLE.to_string()],
        ..SearchOptions::default()
    };
    let (results, search_stats) =
        search::search_indexed(&store, &query, &options).expect("index-backed search");
    let names: Vec<String> = results
        .iter()
        .map(|result| {
            result
                .path
                .strip_prefix(&canonical_root)
                .unwrap_or(&result.path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();

    for expected in ["top.txt", "docs/readme.md", "src/main.rs"] {
        assert!(
            names.iter().any(|name| name == expected),
            "index search missed {expected}: {names:?}"
        );
    }
    assert!(
        search_stats.index.is_some(),
        "an index-backed search should report index usage"
    );

    // Deleting a file and re-indexing removes it from the candidate set.
    std::fs::remove_file(&fixture.src_main).expect("remove fixture file");
    store
        .update(
            std::slice::from_ref(&fixture.root),
            &WalkOptions::default(),
            &UpdateOptions::default(),
        )
        .expect("re-index after the delete");
    let (results, _) = search::search_indexed(&store, &query, &options).expect("second search");
    assert!(
        !results
            .iter()
            .any(|result| result.path.ends_with("main.rs")),
        "a deleted file is still indexed"
    );
}

#[test]
fn heuristic_corpus_is_synthetic_small_and_flagged() {
    let fixture = build();
    let heuristics = HeuristicConfig::default();

    for path in fixture.all_paths() {
        let size = std::fs::metadata(path).expect("fixture metadata").len();
        assert!(
            size <= MAX_FIXTURE_BYTES,
            "{} is {size} bytes; the fixture corpus must stay tiny",
            path.display()
        );
    }

    // The double extension is suspicious by name alone.
    let flagged = security::assess(
        &fixture.double_extension,
        &guara_core::search::FileMetadata {
            size: std::fs::metadata(&fixture.double_extension)
                .ok()
                .map(|meta| meta.len()),
            modified: None,
            permissions: None,
        },
        &heuristics,
    );
    assert_eq!(flagged.verdict, Verdict::Suspicious);
    assert!(
        flagged
            .reasons
            .iter()
            .any(|reason| reason.code == "double-extension"),
        "reasons: {:?}",
        flagged.reasons
    );

    // The packed blob trips the entropy rule.
    let packed = security::assess_file(&fixture.high_entropy, &heuristics);
    assert_eq!(packed.verdict, Verdict::Suspicious);
    assert!(
        packed
            .reasons
            .iter()
            .any(|reason| reason.code == "high-entropy"),
        "reasons: {:?}",
        packed.reasons
    );

    // Ordinary text files stay clean.
    assert!(security::assess_file(&fixture.top, &heuristics).is_clean());
    assert!(security::assess_file(&fixture.docs_readme, &heuristics).is_clean());
}

#[test]
fn the_checked_in_tree_contains_no_executable_payload() {
    let repository = fixture_tree::repository_root();
    let walk = fs::walk(std::slice::from_ref(&repository), &WalkOptions::default());

    let mut oversized = Vec::new();
    let mut executables = Vec::new();
    for entry in &walk.entries {
        let size = std::fs::metadata(&entry.path)
            .map(|meta| meta.len())
            .unwrap_or(0);
        if size > MAX_FIXTURE_BYTES {
            oversized.push((entry.path.clone(), size));
        }
        let is_executable = entry
            .path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                matches!(
                    ext.to_ascii_lowercase().as_str(),
                    "exe" | "dll" | "so" | "dylib" | "scr"
                )
            });
        if is_executable && size > MAX_FIXTURE_BYTES {
            executables.push(entry.path.clone());
        }
    }

    assert!(
        executables.is_empty(),
        "no real executable payloads belong in the repo: {executables:?}"
    );
    // Guard against a corpus creeping in: flag anything larger than the tiny
    // fixtures plus the docs and source files the repository already carries.
    let huge: Vec<_> = oversized
        .into_iter()
        .filter(|(_, size)| *size > 512 * 1024)
        .collect();
    assert!(
        huge.is_empty(),
        "unexpected large files committed: {huge:?}"
    );
    assert!(
        Path::new(&repository).join("AGENTS.md").exists(),
        "the repository root was resolved correctly"
    );
}
