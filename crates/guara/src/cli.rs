use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use guara_core::config;
use guara_core::fs::{self, WalkOptions};
use guara_core::index::{self, IndexStore, UpdateOptions};
use guara_core::search::{self, FileResult, SearchOptions, SearchStats};
use guara_core::serve::{ServeConfig, Server};
use indicatif::{ProgressBar, ProgressDrawTarget};
use tracing_subscriber::EnvFilter;

/// A filesystem search, tracking, and light-security CLI.
#[derive(Parser)]
#[command(
    name = "guara",
    version,
    about,
    long_about = None,
    propagate_version = true,
    subcommand_required = false,
    args_conflicts_with_subcommands = true,
    after_help = "EXAMPLES:\n  guara needle ./src             search names and contents\n  guara needle --json ./src      one JSON object per hit on stdout\n  guara tui needle ./src         browse the hits in a terminal UI\n  guara index . && guara needle  index once, then repeat searches cheaply\n  guara serve --socket           watch the roots and answer the tray over IPC\n\nRun `guara <COMMAND> --help` for the flags of a single command."
)]
pub struct Cli {
    /// Search options used when no subcommand is given (the default command).
    #[command(flatten)]
    pub search: SearchArgs,

    #[command(subcommand)]
    pub command: Option<Command>,

    /// Increase verbosity: -v (info), -vv (debug), -vvv (trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-essential output (stats, progress). Errors still print.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Index database to use. Defaults to `<data_dir>/index.db`.
    #[arg(long, value_name = "PATH", global = true)]
    pub db: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Search for files by name or content. This is the default command.
    #[command(visible_alias = "s")]
    Search(Box<SearchArgs>),

    /// Print config path and effective settings.
    #[command(visible_alias = "c")]
    Config(ConfigArgs),

    /// Build or update the persistent index.
    #[command(visible_alias = "idx")]
    Index(IndexArgs),

    /// Rebuild the index from scratch, forgetting the stored rows for the roots.
    Reindex(IndexPassArgs),

    /// Print recent local search history.
    History(HistoryArgs),

    /// Watch the roots and update the index as files change, until interrupted.
    Serve(ServeArgs),

    /// Browse results in a terminal UI (filter, preview, open, rescan).
    #[command(visible_alias = "browse")]
    Tui(Box<SearchArgs>),
}

/// Arguments for the `index` command.
#[derive(Args, Default)]
pub struct IndexArgs {
    #[command(flatten)]
    pub pass: IndexPassArgs,

    #[command(subcommand)]
    pub action: Option<IndexAction>,
}

/// Sub-actions of `guara index`.
#[derive(Subcommand)]
pub enum IndexAction {
    /// Print path count, DB path, and last update time.
    Status,
}

/// Arguments shared by `guara index` and `guara reindex`.
#[derive(Args, Default)]
pub struct IndexPassArgs {
    /// Roots to index (default: current directory).
    pub roots: Vec<PathBuf>,

    /// Also store a SHA-256 content hash per file. Needs a build with the
    /// `security-hash` feature; without it rows are stored without a hash.
    #[arg(long)]
    pub hash: bool,
}

/// Arguments for the `history` command.
#[derive(Args, Default)]
pub struct HistoryArgs {
    /// Number of recent queries to show.
    #[arg(long, value_name = "N", default_value = "20")]
    pub limit: usize,
}

/// Arguments for the `serve` command.
#[derive(Args, Default)]
pub struct ServeArgs {
    /// Roots to watch (default: current directory).
    pub roots: Vec<PathBuf>,

    /// Debounce window in milliseconds: a burst of writes inside it becomes a
    /// single index transaction.
    #[arg(long, value_name = "MS", default_value = "250")]
    pub debounce: u64,

    /// Watch for this term and report new files whose name or contents match.
    /// Repeatable; terms are remembered locally for later runs.
    #[arg(long = "watch-term", value_name = "PATTERN")]
    pub watch_terms: Vec<String>,

    /// Watch for changes without indexing the roots first.
    #[arg(long = "no-initial-index")]
    pub no_initial_index: bool,

    /// Serve the local IPC protocol on a Unix socket so the tray companion and
    /// the quick-search palette can ask this daemon for search and status.
    /// Without a value, defaults to `<data_dir>/guara.sock`. Unix only.
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "", require_equals = true)]
    pub socket: Option<PathBuf>,
}

/// Arguments for the `config` command.
#[derive(Args, Default)]
pub struct ConfigArgs {}

/// Arguments for the `search` command.
#[derive(Args, Default)]
pub struct SearchArgs {
    /// Pattern to search for. Without `-e` this is a literal substring match
    /// against file names and file contents.
    pub pattern: Option<String>,

    /// Roots to search (default: current directory).
    pub roots: Vec<PathBuf>,

    /// Treat the pattern as a regular expression.
    #[arg(short = 'e', long = "regex")]
    pub regex: bool,

    /// Case-insensitive matching.
    #[arg(short, long)]
    pub ignore_case: bool,

    /// Match whole words only (prevents substring matches inside longer tokens).
    #[arg(short, long)]
    pub word: bool,

    /// Output results as newline-delimited JSON objects.
    #[arg(long)]
    pub json: bool,

    /// Number of context lines before and after each content match.
    #[arg(long, value_name = "N", default_value = "0")]
    pub context: usize,

    /// Stop after this many hits (0 = unlimited).
    #[arg(long, value_name = "N")]
    pub max_count: Option<usize>,

    /// Maximum directory depth to descend. 1 = only top-level entries.
    #[arg(long, value_name = "N")]
    pub max_depth: Option<usize>,

    /// Follow symlinks (default: do not follow).
    #[arg(long = "follow-symlinks")]
    pub follow_symlinks: bool,

    /// Additional search term (repeatable). Multiple terms default to AND.
    #[arg(short = 't', long = "term", value_name = "PATTERN")]
    pub terms: Vec<String>,

    /// Match any term instead of all terms (OR mode).
    #[arg(long)]
    pub or: bool,

    /// Filter by file extension (repeatable, e.g. `--ext rs --ext toml`).
    #[arg(long, value_name = "EXT")]
    pub ext: Vec<String>,

    /// Minimum file size (e.g. `1k`, `10M`).
    #[arg(long, value_name = "SIZE")]
    pub min_size: Option<String>,

    /// Maximum file size (e.g. `1k`, `10M`).
    #[arg(long, value_name = "SIZE")]
    pub max_size: Option<String>,

    /// Only files modified after this date (YYYY-MM-DD).
    #[arg(long, value_name = "DATE")]
    pub after: Option<String>,

    /// Only files modified before this date (YYYY-MM-DD).
    #[arg(long, value_name = "DATE")]
    pub before: Option<String>,

    /// Search binary files too (default: skip for content search).
    #[arg(long)]
    pub binary: bool,

    /// When to use color: `always`, `never`, or `auto` (default).
    #[arg(long, value_name = "WHEN", default_value = "auto")]
    pub color: String,

    /// Compact output: one line per file.
    #[arg(long)]
    pub compact: bool,

    /// Tabular output mode.
    #[arg(long)]
    pub table: bool,

    /// Export results as CSV to stdout.
    #[arg(long)]
    pub csv: bool,

    /// Export results as a self-contained HTML report to stdout.
    #[arg(long)]
    pub html: bool,

    /// Per-file timeout in seconds. Files exceeding this are skipped.
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,

    /// Enable opt-in deep scanners. Needs a backend built in (see
    /// `--clamd-socket`, `--rules-dir`, `--hash-db`) and a matching Cargo
    /// feature; without one it explains how to enable it and exits.
    #[arg(long = "deep-scan", visible_alias = "security")]
    pub deep_scan: bool,

    /// clamd Unix socket for deep scanning (requires the `security-clamav` feature).
    #[arg(long, value_name = "PATH")]
    pub clamd_socket: Option<PathBuf>,

    /// Directory of YARA rules, `.yar`/`.yara` (requires the `security-yara` feature).
    #[arg(long, value_name = "DIR")]
    pub rules_dir: Option<PathBuf>,

    /// Known-bad SHA-256 list, one hex digest per line
    /// (requires the `security-hash` feature).
    #[arg(long, value_name = "FILE")]
    pub hash_db: Option<PathBuf>,

    /// Move flagged files into `--quarantine-dir` and record them in a manifest.
    /// Report-only by default; never deletes in place.
    #[arg(long, requires = "quarantine_dir")]
    pub quarantine: bool,

    /// Destination directory for `--quarantine` (created if missing).
    #[arg(long, value_name = "DIR")]
    pub quarantine_dir: Option<PathBuf>,

    /// Never use the persistent index; always walk the filesystem. By default
    /// the index is used when it exists and covers the requested roots.
    #[arg(long = "no-index")]
    pub no_index: bool,
}

/// Initialise the tracing subscriber based on verbosity flags.
///
/// - Default: `WARN` level (quiet except warnings/errors).
/// - `-v`: `INFO`
/// - `-vv`: `DEBUG`
/// - `-vvv`+: `TRACE`
///
/// Respects `RUST_LOG` if set.
pub fn init_tracing(verbose: u8, quiet: bool) {
    let default_level = if quiet {
        "error"
    } else {
        match verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .ok();
}

/// Search results plus what the callers need to report on them.
pub struct SearchRun {
    pub results: Vec<FileResult>,
    pub stats: SearchStats,
    /// Entries the walker could not read.
    pub walk_errors: usize,
}

/// Progress is only useful on an interactive stderr, and `--quiet` disables it.
fn progress_enabled_for(quiet: bool, stderr_is_tty: bool) -> bool {
    !quiet && stderr_is_tty
}

/// Start a spinner before a long search, or return `None` when progress is off.
pub fn start_progress(quiet: bool) -> Option<ProgressBar> {
    if !progress_enabled_for(quiet, std::io::stderr().is_terminal()) {
        return None;
    }
    let progress = ProgressBar::new_spinner();
    progress.set_draw_target(ProgressDrawTarget::stderr());
    progress.set_message("searching...");
    progress.enable_steady_tick(Duration::from_millis(100));
    Some(progress)
}

/// Clear the spinner before any stats or results are printed to stderr.
pub fn finish_progress(progress: Option<ProgressBar>) {
    if let Some(progress) = progress {
        progress.finish_and_clear();
    }
}

/// Run the walk-or-index search shared by `guara search` and `guara tui`.
///
/// Loads config, merges CLI flags, prefers the persistent index when it covers
/// the requested roots, rebases indexed paths so output matches a live walk, and
/// records local search history for indexed runs. Printing, deep scanning, and
/// quarantine stay in the command handlers.
pub fn collect_search(args: &SearchArgs, db: Option<&Path>) -> Result<SearchRun, i32> {
    tracing::info!(pattern = ?args.pattern, "guara search starting");

    // Load config; merge with CLI flags.
    let config = match config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return Err(2);
        }
    };

    let effective = config.effective_search(
        args.max_depth,
        args.follow_symlinks,
        args.ignore_case,
        args.word,
        args.context,
        Vec::new(),
    );

    let roots: Vec<PathBuf> = default_roots(args.roots.clone());

    let walk_opts = WalkOptions {
        max_depth: effective.max_depth,
        follow_symlinks: effective.follow_symlinks,
        threads: effective.threads,
        global_ignore: effective.ignore,
    };

    // Collect patterns: primary positional + additional terms
    let mut patterns = Vec::new();
    if let Some(p) = &args.pattern {
        patterns.push(p.clone());
    }
    patterns.extend(args.terms.iter().cloned());

    // Build file filter
    let filter = guara_core::search::FileFilter {
        extensions: args.ext.clone(),
        min_size: args
            .min_size
            .as_deref()
            .and_then(guara_core::search::parse_size),
        max_size: args
            .max_size
            .as_deref()
            .and_then(guara_core::search::parse_size)
            .or(effective.max_file_size),
        after: args
            .after
            .as_deref()
            .and_then(guara_core::search::parse_date),
        before: args
            .before
            .as_deref()
            .and_then(guara_core::search::parse_date),
        skip_binary: !args.binary,
    };

    let search_opts = SearchOptions {
        patterns,
        regex: args.regex,
        ignore_case: effective.case_insensitive,
        whole_word: effective.whole_word,
        max_count: args.max_count,
        context: effective.context,
        or_mode: args.or,
        security: config.security.clone(),
        filter,
        timeout: args.timeout,
    };

    if let Err(e) = search::build_regexes(&search_opts) {
        eprintln!("invalid pattern: {e}");
        return Err(2);
    }

    let index_store = if args.no_index {
        None
    } else {
        open_index_for(&roots, db)
    };

    let mut walk_errors = 0;
    let mut results;
    let stats;
    if let Some(store) = &index_store {
        let index_query = index_query_for(&search_opts.filter, &roots);
        match search::search_indexed(store, &index_query, &search_opts) {
            Ok((hits, index_stats)) => {
                results = hits;
                stats = index_stats;
                // Index rows use canonical absolute paths; print them the way a
                // walk from the requested roots would.
                rebase_results(&mut results, &roots);
            }
            Err(e) => {
                tracing::debug!(error = %e, "index search failed; falling back to a live walk");
                let walk = fs::walk(&roots, &walk_opts);
                walk_errors = walk.errors.len();
                (results, stats) = search::search_entries(&walk.entries, &search_opts);
            }
        }
        // History is local-only and only recorded for indexed searches.
        let query = search_opts.patterns.join(" ");
        if let Err(e) = store.record_history(&query) {
            tracing::debug!(error = %e, "cannot record search history");
        }
    } else {
        let walk = fs::walk(&roots, &walk_opts);
        walk_errors = walk.errors.len();
        (results, stats) = search::search_entries(&walk.entries, &search_opts);
    }

    Ok(SearchRun {
        results,
        stats,
        walk_errors,
    })
}

/// Entry point for the `search` command.
pub fn run_search(args: SearchArgs, quiet: bool, db: Option<PathBuf>) -> i32 {
    let start = std::time::Instant::now();
    let progress = start_progress(quiet);
    let search_run = collect_search(&args, db.as_deref());
    finish_progress(progress);

    let SearchRun {
        mut results,
        stats,
        walk_errors,
    } = match search_run {
        Ok(run) => run,
        Err(code) => return code,
    };

    // Opt-in deep scan. Never on by default, and never a file mutation.
    let mut deep_scan_errors = false;
    if args.deep_scan {
        let deep_opts = guara_core::deepscan::DeepScanOptions {
            enabled: true,
            clamd_socket: args.clamd_socket.clone(),
            rules_dir: args.rules_dir.clone(),
            hash_db: args.hash_db.clone(),
        };
        match guara_core::deepscan::DeepScanner::build(&deep_opts) {
            Ok(scanner) => {
                if !quiet {
                    for warning in scanner.warnings() {
                        eprintln!("warning: {warning}");
                    }
                    let backends = scanner.backend_names();
                    if !backends.is_empty() {
                        eprintln!("deep scan backends: {}", backends.join(", "));
                    }
                }
                let errors = guara_core::deepscan::apply(&mut results, &scanner);
                for error in &errors {
                    tracing::debug!(error = %error, "deep scan error");
                    if !quiet {
                        eprintln!("deep scan error: {error}");
                    }
                }
                deep_scan_errors = !errors.is_empty();
            }
            Err(e) => {
                eprintln!("{e}");
                return guara_core::deepscan::NO_BACKEND_EXIT_CODE;
            }
        }
    }

    // Explicit, report-only quarantine: move flagged files, write a manifest.
    let mut quarantine_errors = false;
    if args.quarantine {
        let Some(dir) = args.quarantine_dir.clone() else {
            eprintln!("--quarantine requires --quarantine-dir");
            return 2;
        };
        let policy = guara_core::quarantine::QuarantinePolicy::new(dir);
        let outcome = policy.apply(&results);
        if !quiet {
            eprintln!(
                "quarantined {} file(s) into {}",
                outcome.moved.len(),
                policy.dir().display()
            );
            eprintln!("manifest: {}", policy.manifest_path().display());
        }
        for (path, error) in &outcome.errors {
            eprintln!("quarantine error: {}: {error}", path.display());
        }
        quarantine_errors = !outcome.errors.is_empty();
    }

    let elapsed = start.elapsed();

    // Output results to stdout
    if args.json {
        let json = guara_core::output::format_json(&results);
        if !json.is_empty() {
            println!("{json}");
        }
    } else if args.csv {
        print!("{}", guara_core::output::format_csv(&results));
    } else if args.html {
        print!("{}", guara_core::output::format_html(&results));
    } else {
        let color_mode = match args.color.as_str() {
            "always" => guara_core::output::ColorMode::Always,
            "never" => guara_core::output::ColorMode::Never,
            _ => guara_core::output::ColorMode::Auto,
        };
        let out_opts = guara_core::output::OutputOptions {
            color: color_mode,
            compact: args.compact,
            table: args.table,
        };
        print!("{}", guara_core::output::format_human(&results, &out_opts));
    }

    // Stats go to stderr so JSON stdout stays clean
    if !quiet {
        let stats_msg = guara_core::output::format_stats(&stats, elapsed);
        eprintln!("{stats_msg}");
        if walk_errors > 0 {
            eprintln!("{walk_errors} walk errors");
        }
        if let Some(index) = &stats.index {
            if index.missing > 0 {
                eprintln!(
                    "{} indexed file(s) no longer exist; run `guara index` to refresh",
                    index.missing
                );
            }
        }
        if !stats.skipped.is_empty() {
            eprintln!("{} files skipped", stats.skipped.len());
            for s in &stats.skipped {
                eprintln!("  skipped: {} ({})", s.path.display(), s.kind);
            }
        }
        eprintln!("{}", guara_core::output::format_security_summary(&results));
    }

    // Exit codes: 0=hits, 1=no hits, 2=usage error, 3=partial errors.
    // Intentional filtering (extension/size/binary policy) is not an error.
    let has_errors = walk_errors > 0 || stats.has_errors() || deep_scan_errors || quarantine_errors;
    if has_errors {
        3
    } else if results.is_empty() {
        1
    } else {
        0
    }
}

/// Entry point for the `config` command.
pub fn run_config() -> i32 {
    let path = config::config_path();
    match path {
        Some(p) => {
            println!("path: {}", p.display());
            let cfg = config::load().unwrap_or_default();
            let json = serde_json::to_string_pretty(&cfg).unwrap_or_else(|_| "{}".to_string());
            println!("{json}");
            0
        }
        None => {
            eprintln!("could not determine config directory for this OS");
            2
        }
    }
}

/// Entry point for `guara index` and `guara reindex`.
///
/// `force` drops the stored rows for the roots first, so every file is written
/// again.
pub fn run_index(pass: IndexPassArgs, force: bool, quiet: bool, db: Option<PathBuf>) -> i32 {
    let db_path = match resolve_db(db) {
        Ok(path) => path,
        Err(code) => return code,
    };
    let mut store = match IndexStore::open(&db_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    if pass.hash && !cfg!(feature = "security-hash") {
        eprintln!(
            "note: --hash needs a build with --features security-hash; \
             rows are stored without a content hash"
        );
    }

    let roots = default_roots(pass.roots);
    let walk_opts = index_walk_options();
    let options = UpdateOptions {
        force,
        content_hash: pass.hash,
    };

    match store.update(&roots, &walk_opts, &options) {
        Ok(stats) => {
            if !quiet {
                eprintln!("{}", stats.summary());
                eprintln!("db: {}", db_path.display());
            }
            if stats.errors > 0 {
                3
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// Entry point for `guara index status`.
pub fn run_index_status(db: Option<PathBuf>) -> i32 {
    let db_path = match resolve_db(db) {
        Ok(path) => path,
        Err(code) => return code,
    };

    // Do not create a database just to report on it.
    if !db_path.exists() {
        println!("path count: 0");
        println!("db: {}", db_path.display());
        println!("last updated: never");
        eprintln!("no index yet; run `guara index` to build one");
        return 0;
    }

    let store = match IndexStore::open(&db_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    match store.status() {
        Ok(status) => {
            println!("path count: {}", status.path_count);
            println!("db: {}", status.db_path.display());
            match status.last_updated {
                Some(secs) => println!(
                    "last updated: {} ({} unix seconds)",
                    index::format_timestamp(secs),
                    secs
                ),
                None => println!("last updated: never"),
            }
            println!("schema: {}", status.schema_version);
            for root in &status.roots {
                println!("root: {}", root.display());
            }
            0
        }
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// Entry point for `guara history`.
pub fn run_history(limit: usize, db: Option<PathBuf>) -> i32 {
    let db_path = match resolve_db(db) {
        Ok(path) => path,
        Err(code) => return code,
    };
    if !db_path.exists() {
        eprintln!("no index yet; run `guara index` first");
        return 0;
    }
    let store = match IndexStore::open(&db_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    match store.history(limit) {
        Ok(entries) => {
            if entries.is_empty() {
                eprintln!("no search history yet");
                return 0;
            }
            for entry in entries {
                println!(
                    "{}\t{}",
                    index::format_timestamp(entry.created),
                    entry.query
                );
            }
            0
        }
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// Entry point for `guara serve`.
pub fn run_serve(args: ServeArgs, quiet: bool, db: Option<PathBuf>) -> i32 {
    let db_path = match resolve_db(db) {
        Ok(path) => path,
        Err(code) => return code,
    };
    let mut store = match IndexStore::open(&db_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    let roots = default_roots(args.roots);

    // Persist requested terms, then use everything remembered locally.
    for term in &args.watch_terms {
        if let Err(e) = store.add_watched_term(term) {
            eprintln!("{e}");
            return 2;
        }
    }
    let terms: Vec<String> = match store.watched_terms() {
        Ok(terms) => terms.into_iter().map(|term| term.term).collect(),
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    if !args.no_initial_index {
        let walk_opts = index_walk_options();
        match store.update(&roots, &walk_opts, &UpdateOptions::default()) {
            Ok(stats) => {
                if !quiet {
                    eprintln!("initial {}", stats.summary());
                }
            }
            Err(e) => {
                eprintln!("{e}");
                return 2;
            }
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    if let Err(e) = install_shutdown_handler(shutdown.clone()) {
        eprintln!("cannot install signal handler: {e}");
        return 2;
    }

    let mut serve_config = ServeConfig::new(roots);
    serve_config.debounce = Duration::from_millis(args.debounce);

    let mut ipc_thread = None;
    if let Some(requested) = args.socket.clone() {
        if !guara_core::ipc::socket_supported() {
            eprintln!(
                "the IPC socket is Unix-only in this build; the tray app uses the shared library instead"
            );
            return 2;
        }
        let path = if requested.as_os_str().is_empty() {
            guara_core::ipc::default_socket_path()
        } else {
            Some(requested)
        };
        let Some(path) = path else {
            eprintln!("could not determine a socket path for this OS; pass --socket PATH");
            return 2;
        };
        let context = guara_core::ipc::IpcContext::new(
            serve_config.roots.clone(),
            Some(db_path.clone()),
            true,
        );
        let ipc_shutdown = shutdown.clone();
        let display = path.display().to_string();
        ipc_thread = Some(std::thread::spawn(move || {
            if let Err(e) = guara_core::ipc::serve(&path, context, &ipc_shutdown) {
                eprintln!("IPC server stopped: {e}");
            }
        }));
        if !quiet {
            eprintln!("IPC socket: {display}");
        }
    }

    if !quiet {
        eprintln!(
            "watching {} root(s), debounce {} ms, db {}",
            serve_config.roots.len(),
            args.debounce,
            db_path.display()
        );
        if !terms.is_empty() {
            eprintln!("watched terms: {}", terms.join(", "));
        }
        eprintln!("press Ctrl-C to stop");
    }

    let mut server = match Server::new(&mut store, serve_config, terms) {
        Ok(server) => server,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    let result = server.run(&shutdown, |batch, matches| {
        if quiet {
            return;
        }
        eprintln!(
            "index: {} upserted, {} removed, {} renamed, {} skipped",
            batch.upserts, batch.removes, batch.renames, batch.skipped
        );
        for hit in matches {
            eprintln!("watched term {:?} matched {}", hit.term, hit.path.display());
        }
    });

    match result {
        Ok(report) => {
            if !quiet {
                eprintln!(
                    "stopped after {} batch(es), {} change(s); index committed",
                    report.batches, report.changes
                );
                for hit in &report.watched_matches {
                    eprintln!("watched term {:?} matched {}", hit.term, hit.path.display());
                }
            }
            // The IPC thread notices the shutdown flag and removes the socket.
            if let Some(handle) = ipc_thread {
                if let Err(e) = handle.join() {
                    eprintln!("IPC server panicked: {e:?}");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

/// Install a SIGINT/SIGTERM handler that flips `shutdown`.
fn install_shutdown_handler(shutdown: Arc<AtomicBool>) -> Result<(), String> {
    ctrlc::set_handler(move || {
        shutdown.store(true, Ordering::SeqCst);
    })
    .map_err(|e| e.to_string())
}

/// Index roots default to the current directory, like search.
fn default_roots(roots: Vec<PathBuf>) -> Vec<PathBuf> {
    if roots.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        roots
    }
}

/// Resolve `--db`, falling back to the OS data directory.
fn resolve_db(db: Option<PathBuf>) -> Result<PathBuf, i32> {
    match db {
        Some(path) => Ok(path),
        None => match index::default_db_path() {
            Some(path) => Ok(path),
            None => {
                eprintln!(
                    "could not determine a data directory for the index on this OS; pass --db PATH"
                );
                Err(2)
            }
        },
    }
}

/// Walk options for indexing: the same global ignores the search command uses.
fn index_walk_options() -> WalkOptions {
    let config = config::load().unwrap_or_default();
    WalkOptions {
        max_depth: config.search.max_depth,
        follow_symlinks: config.search.follow_symlinks,
        threads: config.search.threads,
        global_ignore: config.search.ignore,
    }
}

/// Open the index for a search without creating it. Returns `None` when there
/// is no database yet, when it cannot be opened, or when its recorded roots do
/// not cover the requested roots; callers then walk live.
fn open_index_for(roots: &[PathBuf], db: Option<&Path>) -> Option<IndexStore> {
    let path = match db {
        Some(path) => path.to_path_buf(),
        None => index::default_db_path()?,
    };
    if !path.exists() {
        return None;
    }
    let store = IndexStore::open(&path).ok()?;
    if !store.covers(roots).unwrap_or(false) {
        return None;
    }
    Some(store)
}

/// Translate a search file filter into SQL-prunable index filters.
fn index_query_for(
    filter: &guara_core::search::FileFilter,
    roots: &[PathBuf],
) -> index::IndexQuery {
    index::IndexQuery {
        extensions: filter.extensions.clone(),
        min_size: filter.min_size,
        max_size: filter.max_size,
        after: filter.after,
        before: filter.before,
        unders: roots.to_vec(),
        limit: None,
    }
}

/// Rewrite indexed (canonical, absolute) result paths into the form the user
/// asked for, so index-backed and live-walk output read the same.
fn rebase_results(results: &mut [guara_core::search::FileResult], roots: &[PathBuf]) {
    for result in results.iter_mut() {
        for root in roots {
            let canonical = index::canonicalize(root);
            if let Ok(rest) = result.path.strip_prefix(&canonical) {
                result.path = if rest.as_os_str().is_empty() {
                    root.clone()
                } else {
                    root.join(rest)
                };
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_disabled_by_quiet_or_a_pipe() {
        assert!(!progress_enabled_for(true, true));
        assert!(!progress_enabled_for(false, false));
        assert!(progress_enabled_for(false, true));
    }
}
