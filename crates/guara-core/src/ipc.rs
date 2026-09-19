//! Local IPC protocol for the tray companion.
//!
//! One newline-delimited JSON [`Request`] per connection, one JSON [`Response`]
//! back. The transport is a Unix domain socket; the tray can also link the
//! shared library and call [`search_names`] / [`IpcContext::dispatch`] directly,
//! so a socket is never required for the app to work.
//!
//! Because the payload is plain JSON, the protocol is unit-testable without a
//! socket: [`handle_line`] parses, dispatches, and serializes in one call.

use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::fs::{self, WalkOptions};
use crate::search::{self, FileResult, SearchOptions};
use crate::security::{self, Assessment, HeuristicConfig, Reason, Verdict};

/// Bumped when the request/response shapes change incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

/// Requests the tray (or any local client) can send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Handshake: version check plus the capabilities this build supports.
    Hello {
        #[serde(default)]
        version: u32,
    },
    /// Name search over one root (default: the first configured root).
    Search {
        query: String,
        #[serde(default)]
        root: Option<PathBuf>,
        #[serde(default)]
        limit: Option<usize>,
    },
    /// Index / daemon status.
    Status,
    /// Recent local queries, newest first.
    Recents,
    /// Remember a scope so it survives restarts.
    PinScope {
        root: PathBuf,
        #[serde(default)]
        label: Option<String>,
    },
    /// Run the always-on heuristics against one path.
    Scan { path: PathBuf },
}

/// Responses, always exactly one per request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    Hello {
        version: u32,
        capabilities: Vec<String>,
    },
    Hits {
        hits: Vec<Hit>,
        stats: HitStats,
    },
    Status(StatusReport),
    Recents {
        queries: Vec<String>,
    },
    Pinned {
        scopes: Vec<Scope>,
    },
    Assessment {
        path: PathBuf,
        verdict: Verdict,
        reasons: Vec<Reason>,
    },
    Error {
        message: String,
    },
}

/// One search hit, trimmed to what a palette shows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hit {
    pub path: PathBuf,
    /// The file name matched, not just its contents.
    pub name_matched: bool,
    pub size: Option<u64>,
    pub modified: Option<u64>,
    pub verdict: Verdict,
}

/// Search counters for the palette footer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HitStats {
    pub files_scanned: usize,
    pub hits: usize,
    pub elapsed_ms: u64,
}

/// Daemon and index state for the tray tooltip.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    pub index_path: Option<PathBuf>,
    pub indexed_paths: u64,
    pub roots: Vec<PathBuf>,
    /// True while a daemon is watching the roots.
    pub watching: bool,
    /// True when `roots` were found by the caller rather than recorded.
    pub socket: bool,
}

/// A scope the user pinned in the tray.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub root: PathBuf,
    pub label: String,
}

/// Server-side state: roots, index location, and the recent-query list.
#[derive(Debug, Clone, Default)]
pub struct IpcContext {
    pub roots: Vec<PathBuf>,
    pub db: Option<PathBuf>,
    pub watching: bool,
    /// Newest first, capped at [`MAX_RECENTS`].
    pub recents: Vec<String>,
    pub pinned_scopes: Vec<Scope>,
    pub heuristics: HeuristicConfig,
}

/// How many recent queries the context keeps.
pub const MAX_RECENTS: usize = 20;

impl IpcContext {
    /// Context over the given roots. Heuristics default to enabled.
    pub fn new(roots: Vec<PathBuf>, db: Option<PathBuf>, watching: bool) -> Self {
        Self {
            roots,
            db,
            watching,
            recents: Vec::new(),
            pinned_scopes: Vec::new(),
            heuristics: HeuristicConfig::default(),
        }
    }

    /// Answer a request. Never panics: bad input becomes [`Response::Error`].
    pub fn dispatch(&mut self, request: Request) -> Response {
        match request {
            Request::Hello { version } => {
                if version != 0 && version != PROTOCOL_VERSION {
                    return Response::Error {
                        message: format!(
                            "unsupported protocol version {version}; this build speaks {PROTOCOL_VERSION}"
                        ),
                    };
                }
                Response::Hello {
                    version: PROTOCOL_VERSION,
                    capabilities: capabilities(),
                }
            }
            Request::Search { query, root, limit } => {
                let root = root.or_else(|| self.roots.first().cloned());
                let Some(root) = root else {
                    return Response::Error {
                        message: "no root configured for search".to_string(),
                    };
                };
                self.remember_query(&query);
                search_names(&root, &query, limit, &self.heuristics)
            }
            Request::Status => Response::Status(self.status()),
            Request::Recents => Response::Recents {
                queries: self.recents.clone(),
            },
            Request::PinScope { root, label } => {
                self.pin_scope(root, label);
                Response::Pinned {
                    scopes: self.pinned_scopes.clone(),
                }
            }
            Request::Scan { path } => {
                let assessment = security::assess_file(&path, &self.heuristics);
                Response::Assessment {
                    path,
                    verdict: assessment.verdict,
                    reasons: assessment.reasons,
                }
            }
        }
    }

    /// Record a query, newest first, without duplicates.
    pub fn remember_query(&mut self, query: &str) {
        let query = query.trim();
        if query.is_empty() {
            return;
        }
        self.recents.retain(|existing| existing != query);
        self.recents.insert(0, query.to_string());
        self.recents.truncate(MAX_RECENTS);
    }

    /// Pin (or re-label) a scope. Pinned scopes keep their insertion order.
    pub fn pin_scope(&mut self, root: PathBuf, label: Option<String>) {
        let label = label.unwrap_or_else(|| {
            root.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| root.display().to_string())
        });
        match self
            .pinned_scopes
            .iter_mut()
            .find(|scope| scope.root == root)
        {
            Some(existing) => existing.label = label,
            None => self.pinned_scopes.push(Scope { root, label }),
        }
    }

    /// Current status snapshot.
    pub fn status(&self) -> StatusReport {
        let (index_path, indexed_paths) = self.index_summary();
        StatusReport {
            index_path,
            indexed_paths,
            roots: self.roots.clone(),
            watching: self.watching,
            socket: false,
        }
    }

    fn index_summary(&self) -> (Option<PathBuf>, u64) {
        let Some(path) = self.db.clone().or_else(crate::index::default_db_path) else {
            return (None, 0);
        };
        if !path.exists() {
            return (Some(path), 0);
        }
        match crate::index::IndexStore::open(&path) {
            Ok(store) => match store.status() {
                Ok(status) => (Some(path), status.path_count as u64),
                Err(_) => (Some(path), 0),
            },
            Err(_) => (Some(path), 0),
        }
    }
}

/// Capabilities advertised in the [`Response::Hello`] handshake.
pub fn capabilities() -> Vec<String> {
    let mut caps = vec![
        "search".to_string(),
        "status".to_string(),
        "recents".to_string(),
        "pin-scope".to_string(),
        "scan".to_string(),
    ];
    if cfg!(unix) {
        caps.push("unix-socket".to_string());
    }
    caps
}

/// Parse, dispatch, and serialize one protocol line. Used by the socket server
/// and directly testable without any transport.
pub fn handle_line(line: &str, ctx: &mut IpcContext) -> String {
    let request = match serde_json::from_str::<Request>(line.trim()) {
        Ok(request) => request,
        Err(e) => {
            return serialize(&Response::Error {
                message: format!("malformed request: {e}"),
            });
        }
    };
    serialize(&ctx.dispatch(request))
}

/// Serialize a response, falling back to an error object if that ever fails.
pub fn serialize(response: &Response) -> String {
    serde_json::to_string(response).unwrap_or_else(|e| {
        format!("{{\"response\":\"error\",\"message\":\"serialization failed: {e}\"}}")
    })
}

/// Name search used by both the palette and the socket: same walker and matcher
/// as `guara search`, capped at `limit` hits.
pub fn search_names(
    root: &Path,
    query: &str,
    limit: Option<usize>,
    heuristics: &HeuristicConfig,
) -> Response {
    let start = Instant::now();
    let walk = fs::walk(&[root.to_path_buf()], &WalkOptions::default());
    let options = SearchOptions {
        patterns: vec![query.to_string()],
        max_count: limit,
        security: heuristics.clone(),
        ..SearchOptions::default()
    };
    let (mut results, stats) = search::search_entries(&walk.entries, &options);
    if let Some(limit) = limit {
        results.truncate(limit);
    }

    let hits = results.iter().map(hit_from_result).collect();
    let stats = HitStats {
        files_scanned: stats.files_scanned,
        hits: count_hits(&results),
        elapsed_ms: start.elapsed().as_millis() as u64,
    };
    Response::Hits { hits, stats }
}

fn hit_from_result(result: &FileResult) -> Hit {
    Hit {
        path: result.path.clone(),
        name_matched: result.filename_matched,
        size: result.metadata.size,
        modified: result.metadata.modified,
        verdict: result.security.verdict,
    }
}

fn count_hits(results: &[FileResult]) -> usize {
    results.iter().map(FileResult::total_hits).sum()
}

/// Assessment of one path, shaped for the tray's one-click scan.
pub fn scan_path(path: &Path, heuristics: &HeuristicConfig) -> Assessment {
    security::assess_file(path, heuristics)
}

/// Default socket path: `<data_dir>/guara.sock` (`guara.ipc` on Windows).
///
/// Returns `None` when the OS has no data directory.
pub fn default_socket_path() -> Option<PathBuf> {
    let base = directories::ProjectDirs::from("", "", "guara")?;
    let name = if cfg!(windows) {
        "guara.ipc"
    } else {
        "guara.sock"
    };
    Some(base.data_dir().join(name))
}

/// Serve requests on a Unix domain socket until `shutdown` is set.
///
/// The socket file is created (replacing a stale one) and removed on exit.
#[cfg(unix)]
pub fn serve(
    socket: &Path,
    ctx: IpcContext,
    shutdown: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::Ordering;

    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A leftover file from a crashed daemon would block the bind.
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    listener.set_nonblocking(true)?;

    let mut ctx = ctx;
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let mut stream = &stream;
                let response = handle_line(&line, &mut ctx);
                let _ = writeln!(stream, "{response}");
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => {
                let _ = std::fs::remove_file(socket);
                return Err(e);
            }
        }
    }

    let _ = std::fs::remove_file(socket);
    Ok(())
}

/// Serve requests on the default socket path.
#[cfg(unix)]
pub fn serve_default(
    ctx: IpcContext,
    shutdown: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    match default_socket_path() {
        Some(path) => serve(&path, ctx, shutdown),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no data directory for the IPC socket; pass --socket PATH",
        )),
    }
}

/// Windows has no Unix domain socket support in this build: the tray links the
/// shared library instead (`search_names`, `IpcContext::dispatch`).
#[cfg(not(unix))]
pub fn serve(
    _socket: &Path,
    _ctx: IpcContext,
    _shutdown: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the socket transport is Unix-only; the tray app uses the shared library instead",
    ))
}

/// Send one request and read one response.
#[cfg(unix)]
pub fn request(socket: &Path, request: &Request) -> std::io::Result<Response> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket)?;
    let line = serde_json::to_string(request)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    writeln!(stream, "{line}")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;
    serde_json::from_str::<Response>(response.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Client stub for platforms without the socket transport.
#[cfg(not(unix))]
pub fn request(_socket: &Path, _request: &Request) -> std::io::Result<Response> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the socket transport is Unix-only; use the shared library instead",
    ))
}

/// True when this build can talk over a local socket.
pub fn socket_supported() -> bool {
    cfg!(unix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn context_with_roots(root: &Path) -> IpcContext {
        IpcContext::new(vec![root.to_path_buf()], Some(root.join("index.db")), false)
    }

    #[test]
    fn hello_reports_version_and_capabilities() {
        let mut ctx = IpcContext::default();
        let response = ctx.dispatch(Request::Hello { version: 0 });
        match response {
            Response::Hello {
                version,
                capabilities,
            } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert!(capabilities.contains(&"search".to_string()));
                assert!(capabilities.contains(&"status".to_string()));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn hello_rejects_a_future_version() {
        let mut ctx = IpcContext::default();
        let response = ctx.dispatch(Request::Hello {
            version: PROTOCOL_VERSION + 1,
        });
        assert!(matches!(response, Response::Error { .. }));
    }

    #[test]
    fn malformed_json_is_an_error_response_not_a_panic() {
        let mut ctx = IpcContext::default();
        let line = handle_line("{not json", &mut ctx);
        assert!(line.contains("malformed request"));
        let parsed: Response = serde_json::from_str(&line).unwrap();
        assert!(matches!(parsed, Response::Error { .. }));
    }

    #[test]
    fn search_finds_a_name_and_records_the_query() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("needle.txt"), "nothing here\n").unwrap();
        std::fs::write(dir.path().join("other.txt"), "haystack\n").unwrap();

        let mut ctx = context_with_roots(dir.path());
        let response = ctx.dispatch(Request::Search {
            query: "needle".to_string(),
            root: None,
            limit: Some(10),
        });

        match response {
            Response::Hits { hits, stats } => {
                assert_eq!(hits.len(), 1);
                assert!(hits[0].path.ends_with("needle.txt"));
                assert!(hits[0].name_matched);
                assert_eq!(stats.hits, 1);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(ctx.recents, vec!["needle".to_string()]);
    }

    #[test]
    fn search_respects_the_limit_and_defaults_to_the_first_root() {
        let dir = tempfile::TempDir::new().unwrap();
        for index in 0..5 {
            std::fs::write(dir.path().join(format!("note{index}.md")), "needle\n").unwrap();
        }
        let mut ctx = context_with_roots(dir.path());
        let response = ctx.dispatch(Request::Search {
            query: "needle".to_string(),
            root: None,
            limit: Some(2),
        });
        match response {
            Response::Hits { hits, .. } => assert_eq!(hits.len(), 2),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn search_without_a_root_is_an_error() {
        let mut ctx = IpcContext::default();
        let response = ctx.dispatch(Request::Search {
            query: "needle".to_string(),
            root: None,
            limit: None,
        });
        assert!(matches!(response, Response::Error { .. }));
    }

    #[test]
    fn status_reports_roots_and_a_missing_index_as_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut ctx = context_with_roots(dir.path());
        let response = ctx.dispatch(Request::Status);
        match response {
            Response::Status(status) => {
                assert_eq!(status.roots, vec![dir.path().to_path_buf()]);
                assert_eq!(status.indexed_paths, 0);
                assert!(!status.watching);
                assert!(!status.socket);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn recents_are_newest_first_and_deduplicated() {
        let mut ctx = IpcContext::default();
        ctx.remember_query("alpha");
        ctx.remember_query("beta");
        ctx.remember_query("alpha");
        assert_eq!(ctx.recents, vec!["alpha".to_string(), "beta".to_string()]);

        for index in 0..(MAX_RECENTS + 5) {
            ctx.remember_query(&format!("query-{index}"));
        }
        assert_eq!(ctx.recents.len(), MAX_RECENTS);
        assert_eq!(ctx.recents[0], format!("query-{}", MAX_RECENTS + 4));
    }

    #[test]
    fn empty_query_is_not_remembered() {
        let mut ctx = IpcContext::default();
        ctx.remember_query("   ");
        assert!(ctx.recents.is_empty());
    }

    #[test]
    fn pinning_a_scope_is_idempotent_and_keeps_the_label() {
        let mut ctx = IpcContext::default();
        let root = PathBuf::from("/tmp/workspace");
        let response = ctx.dispatch(Request::PinScope {
            root: root.clone(),
            label: Some("work".to_string()),
        });
        match response {
            Response::Pinned { scopes } => {
                assert_eq!(scopes.len(), 1);
                assert_eq!(scopes[0].label, "work");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        ctx.dispatch(Request::PinScope {
            root: root.clone(),
            label: Some("clients".to_string()),
        });
        assert_eq!(ctx.pinned_scopes.len(), 1);
        assert_eq!(ctx.pinned_scopes[0].label, "clients");

        ctx.pin_scope(PathBuf::from("/tmp/other"), None);
        assert_eq!(ctx.pinned_scopes.len(), 2);
        assert_eq!(ctx.pinned_scopes[1].label, "other");
    }

    #[test]
    fn scan_returns_the_heuristic_verdict() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("invoice.pdf.exe");
        std::fs::write(&path, b"stub").unwrap();

        let mut ctx = IpcContext::default();
        let response = ctx.dispatch(Request::Scan { path: path.clone() });
        match response {
            Response::Assessment {
                path: reported,
                verdict,
                reasons,
            } => {
                assert_eq!(reported, path);
                assert_eq!(verdict, Verdict::Suspicious);
                assert!(!reasons.is_empty());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn responses_round_trip_through_json() {
        let responses = vec![
            Response::Hello {
                version: PROTOCOL_VERSION,
                capabilities: capabilities(),
            },
            Response::Hits {
                hits: vec![Hit {
                    path: PathBuf::from("/tmp/a.txt"),
                    name_matched: true,
                    size: Some(12),
                    modified: Some(1),
                    verdict: Verdict::Clean,
                }],
                stats: HitStats {
                    files_scanned: 1,
                    hits: 1,
                    elapsed_ms: 3,
                },
            },
            Response::Status(StatusReport::default()),
            Response::Recents {
                queries: vec!["a".to_string()],
            },
            Response::Pinned {
                scopes: vec![Scope {
                    root: PathBuf::from("/tmp"),
                    label: "tmp".to_string(),
                }],
            },
            Response::Assessment {
                path: PathBuf::from("/tmp/a"),
                verdict: Verdict::Clean,
                reasons: Vec::new(),
            },
            Response::Error {
                message: "nope".to_string(),
            },
        ];

        for response in responses {
            let line = serialize(&response);
            assert!(!line.contains('\n'), "responses are one line: {line}");
            assert_eq!(serde_json::from_str::<Response>(&line).unwrap(), response);
        }
    }

    #[test]
    fn requests_round_trip_through_json() {
        let requests = vec![
            Request::Hello { version: 1 },
            Request::Search {
                query: "needle".to_string(),
                root: Some(PathBuf::from("/tmp")),
                limit: Some(5),
            },
            Request::Status,
            Request::Recents,
            Request::PinScope {
                root: PathBuf::from("/tmp"),
                label: None,
            },
            Request::Scan {
                path: PathBuf::from("/tmp/a"),
            },
        ];

        for request in requests {
            let line = serde_json::to_string(&request).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&line).unwrap(), request);
        }
    }

    #[cfg(unix)]
    #[test]
    fn socket_round_trip_serves_a_search() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("needle.txt"), "needle\n").unwrap();
        let socket = dir.path().join("guara.sock");
        let shutdown = AtomicBool::new(false);

        let ctx = context_with_roots(dir.path());
        std::thread::scope(|scope| {
            let server = scope.spawn(|| serve(&socket, ctx, &shutdown));
            // Wait for the socket file to appear.
            for _ in 0..200 {
                if socket.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(socket.exists(), "server never created the socket");

            let hello = request(&socket, &Request::Hello { version: 1 }).unwrap();
            assert!(matches!(hello, Response::Hello { .. }));

            let response = request(
                &socket,
                &Request::Search {
                    query: "needle".to_string(),
                    root: None,
                    limit: None,
                },
            )
            .unwrap();
            match response {
                Response::Hits { hits, .. } => {
                    assert_eq!(hits.len(), 1);
                    assert!(hits[0].path.ends_with("needle.txt"));
                }
                other => panic!("unexpected response: {other:?}"),
            }

            let status = request(&socket, &Request::Status).unwrap();
            assert!(matches!(status, Response::Status(_)));

            shutdown.store(true, Ordering::SeqCst);
            let result = server.join().unwrap();
            assert!(result.is_ok(), "server error: {result:?}");
        });

        assert!(!socket.exists(), "socket file should be cleaned up");
    }

    #[cfg(unix)]
    #[test]
    fn socket_survives_a_malformed_request() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("guara.sock");
        let shutdown = AtomicBool::new(false);
        let ctx = IpcContext::default();

        std::thread::scope(|scope| {
            let server = scope.spawn(|| serve(&socket, ctx, &shutdown));
            for _ in 0..200 {
                if socket.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            use std::io::{BufRead, BufReader, Write};
            use std::os::unix::net::UnixStream;
            let mut stream = UnixStream::connect(&socket).unwrap();
            writeln!(stream, "garbage").unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let response: Response = serde_json::from_str(line.trim()).unwrap();
            assert!(matches!(response, Response::Error { .. }));

            // The server still answers a good request afterwards.
            let hello = request(&socket, &Request::Hello { version: 1 }).unwrap();
            assert!(matches!(hello, Response::Hello { .. }));

            shutdown.store(true, Ordering::SeqCst);
            server.join().unwrap().unwrap();
        });
    }

    #[test]
    fn default_socket_path_is_named_for_the_platform() {
        match default_socket_path() {
            Some(path) => {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                if cfg!(windows) {
                    assert_eq!(name, "guara.ipc");
                } else {
                    assert_eq!(name, "guara.sock");
                }
            }
            None => panic!("expected a data directory on this platform"),
        }
    }
}
