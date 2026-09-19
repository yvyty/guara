//! Core library for the Guará filesystem search tool.

pub mod config;
pub mod deepscan;
pub mod fs;
pub mod index;
pub mod ipc;
pub mod output;
pub mod quarantine;
pub mod search;
pub mod security;
pub mod serve;
pub mod tray;
pub mod tui;
pub mod watch;

/// Returns the library version string (matches the workspace package version).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
