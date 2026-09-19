//! One scripted filesystem tree shared by the `guara-core` and `guara`
//! integration tests.
//!
//! Both crates pull this file in with `#[path = "../../../tests/fixture_tree.rs"]`
//! so walk, search, index, and CLI tests all assert against the same tree.
//!
//! Every sample here is synthetic and tiny. The "malware-looking" names carry
//! stub bytes only: no real executable, no live sample, nothing runnable.

#![allow(dead_code)] // Each test target uses a different subset of this module.

use std::path::{Path, PathBuf};

/// Text that appears in several fixture files, used by search assertions.
pub const NEEDLE: &str = "guara-needle";

/// Bytes written to the packed-looking blob. High entropy, no header.
pub const HIGH_ENTROPY_LEN: usize = 512;

/// Largest file any fixture may contain. Keeps the corpus safe and cheap.
pub const MAX_FIXTURE_BYTES: u64 = 4096;

/// A materialized fixture tree plus the paths tests care about.
pub struct Fixture {
    dir: tempfile::TempDir,
    /// Root of the tree, as passed to the walker.
    pub root: PathBuf,
    /// `top.txt`: contains [`NEEDLE`].
    pub top: PathBuf,
    /// `docs/readme.md`: contains [`NEEDLE`].
    pub docs_readme: PathBuf,
    /// `src/main.rs`: contains [`NEEDLE`].
    pub src_main: PathBuf,
    /// `src/lib.rs`: no match, so tests can tell name from content matches.
    pub src_lib: PathBuf,
    /// `nested/deep/deeper/leaf.txt`: reached only without a depth limit.
    pub deep_leaf: PathBuf,
    /// `ignored/skip.txt`: contains [`NEEDLE`] but is `.gitignore`d.
    pub ignored: PathBuf,
    /// `archive/invoice.pdf.exe`: synthetic double extension.
    pub double_extension: PathBuf,
    /// `blobs/packed.bin`: 512 high-entropy bytes.
    pub high_entropy: PathBuf,
}

impl Fixture {
    /// The temporary directory that owns the tree.
    pub fn tempdir(&self) -> &Path {
        self.dir.path()
    }

    /// Every file the fixture wrote.
    pub fn all_paths(&self) -> Vec<&Path> {
        vec![
            self.top.as_path(),
            self.docs_readme.as_path(),
            self.src_main.as_path(),
            self.src_lib.as_path(),
            self.deep_leaf.as_path(),
            self.ignored.as_path(),
            self.double_extension.as_path(),
            self.high_entropy.as_path(),
        ]
    }

    /// Path of a fixture file relative to the root, with forward slashes.
    pub fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

/// Materialize the fixture tree in a fresh temporary directory.
pub fn build() -> Fixture {
    let dir = tempfile::TempDir::new().expect("fixture temp dir");
    let root = dir.path().join("tree");
    std::fs::create_dir_all(&root).expect("fixture root");

    let top = write(&root, "top.txt", &format!("top level {NEEDLE}\n"));
    let docs_readme = write(
        &root,
        "docs/readme.md",
        &format!("# docs\n\nfind the {NEEDLE} here\n"),
    );
    let src_main = write(
        &root,
        "src/main.rs",
        &format!("fn main() {{\n    let {NEEDLE} = 1;\n}}\n"),
    );
    let src_lib = write(&root, "src/lib.rs", "pub fn helper() {}\n");
    let deep_leaf = write(&root, "nested/deep/deeper/leaf.txt", "deep leaf\n");
    let ignored = write(
        &root,
        "ignored/skip.txt",
        &format!("{NEEDLE} lives in an ignored directory\n"),
    );
    write(&root, ".gitignore", "ignored/\n");

    // A double-extension name with DOS-stub bytes: suspicious by name, and not
    // a runnable PE (no `PE\0\0` signature).
    let mut stub = vec![0u8; 128];
    stub[0] = b'M';
    stub[1] = b'Z';
    let double_extension = write_bytes(&root, "archive/invoice.pdf.exe", &stub);

    // Deterministic pseudorandom bytes: entropy sits near 8 bits/byte, above
    // the 7.2 default threshold, without shipping anything meaningful.
    let high_entropy = write_bytes(&root, "blobs/packed.bin", &pseudorandom(HIGH_ENTROPY_LEN));

    Fixture {
        dir,
        root,
        top,
        docs_readme,
        src_main,
        src_lib,
        deep_leaf,
        ignored,
        double_extension,
        high_entropy,
    }
}

/// Write a text file, creating parent directories.
pub fn write(root: &Path, relative: &str, contents: &str) -> PathBuf {
    write_bytes(root, relative, contents.as_bytes())
}

/// Write a binary file, creating parent directories.
pub fn write_bytes(root: &Path, relative: &str, contents: &[u8]) -> PathBuf {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("fixture parent directory");
    }
    std::fs::write(&path, contents).expect("fixture file");
    path
}

/// xorshift-based pseudorandom bytes, seeded so the corpus is reproducible.
pub fn pseudorandom(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// Repository root, for tests that guard the checked-in corpus.
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("a crate inside <repo>/crates/<crate>")
        .to_path_buf()
}
