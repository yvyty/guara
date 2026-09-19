//! Guará tray companion.
//!
//! The shell is intentionally thin: tray state, tooltip text, recent queries,
//! pinned scopes, and the auto-start preference all come from
//! [`guara_core::tray`], and every search or scan goes through the shared
//! [`guara_core::ipc`] protocol, so `guara tui`, the daemon socket, and this
//! palette all run the same engine.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use guara_core::ipc::{IpcContext, Request, Response};
use guara_core::security::Assessment;
use guara_core::tray::{default_preferences_path, state_for, Preferences, TrayState};
use guara_core::tui::open_command;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

const TRAY_ID: &str = "main";
const PALETTE: &str = "palette";

/// Shared shell state: the protocol context plus the persisted preferences.
struct TrayApp {
    ctx: Mutex<IpcContext>,
    prefs: Mutex<Preferences>,
    prefs_path: Option<PathBuf>,
    last_assessment: Mutex<Option<Assessment>>,
}

impl TrayApp {
    fn dispatch(&self, request: Request) -> Response {
        match self.ctx.lock() {
            Ok(mut ctx) => ctx.dispatch(request),
            Err(_) => Response::Error {
                message: "the tray context is unavailable".to_string(),
            },
        }
    }

    fn preferences(&self) -> Preferences {
        self.prefs
            .lock()
            .map(|prefs| prefs.clone())
            .unwrap_or_default()
    }

    fn store_preferences(&self, prefs: Preferences) {
        if let Some(path) = &self.prefs_path {
            let _ = prefs.save(path);
        }
        if let Ok(mut guard) = self.prefs.lock() {
            *guard = prefs;
        }
    }

    /// One-click heuristic scan. The verdict is kept so the tray can switch to
    /// the threat icon.
    fn scan(&self, path: &str) -> Response {
        let response = self.dispatch(Request::Scan {
            path: PathBuf::from(path),
        });
        if let Response::Assessment {
            verdict, reasons, ..
        } = &response
        {
            let assessment = Assessment {
                verdict: *verdict,
                reasons: reasons.clone(),
            };
            if let Ok(mut guard) = self.last_assessment.lock() {
                *guard = Some(assessment);
            }
        }
        response
    }

    /// Tray state for the current status and last scan. Used by tests to assert
    /// the icon mapping; `refresh_tray` reads the status directly.
    #[cfg(test)]
    fn tray_state(&self) -> Option<TrayState> {
        let Response::Status(status) = self.dispatch(Request::Status) else {
            return None;
        };
        let assessment = self
            .last_assessment
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        Some(state_for(&status, assessment.as_ref()))
    }
}

#[tauri::command]
fn palette_search(
    app: State<'_, TrayApp>,
    query: String,
    root: Option<String>,
    limit: Option<usize>,
) -> Response {
    app.dispatch(Request::Search {
        query,
        root: root.map(PathBuf::from),
        limit,
    })
}

#[tauri::command]
fn daemon_status(app: State<'_, TrayApp>) -> Response {
    app.dispatch(Request::Status)
}

#[tauri::command]
fn recent_queries(app: State<'_, TrayApp>) -> Response {
    app.dispatch(Request::Recents)
}

#[tauri::command]
fn pin_scope(app: State<'_, TrayApp>, root: String, label: Option<String>) -> Response {
    let mut prefs = app.preferences();
    prefs.pin_scope(PathBuf::from(&root), label);
    prefs.set_last_root(PathBuf::from(&root));
    let scopes = prefs.pinned_scopes.clone();
    app.store_preferences(prefs);
    Response::Pinned { scopes }
}

#[tauri::command]
fn scan_hit(app: State<'_, TrayApp>, path: String) -> Response {
    app.scan(&path)
}

#[tauri::command]
fn open_hit(path: String) {
    open_with_the_os(&path);
}

#[tauri::command]
fn hide_palette(app: AppHandle) {
    if let Some(window) = app.get_webview_window(PALETTE) {
        let _ = window.hide();
    }
    refresh_tray(&app);
}

#[tauri::command]
fn auto_start_enabled(app: State<'_, TrayApp>) -> bool {
    app.preferences().auto_start
}

#[tauri::command]
fn toggle_auto_start(app: AppHandle) -> bool {
    let Some(state) = app.try_state::<TrayApp>() else {
        return false;
    };
    let mut prefs = state.preferences();
    let enabled = prefs.toggle_auto_start();
    state.store_preferences(prefs);

    // Register or remove the real login item, not just the preference.
    let autostart = app.autolaunch();
    let _ = if enabled {
        autostart.enable()
    } else {
        autostart.disable()
    };
    refresh_tray(&app);
    enabled
}

fn main() {
    let prefs_path = default_preferences_path();
    let prefs = prefs_path
        .as_ref()
        .map(|path| Preferences::load(path))
        .transpose()
        .ok()
        .flatten()
        .unwrap_or_default();

    let roots: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    let roots = if roots.is_empty() {
        prefs
            .active_root()
            .map(|root| vec![root])
            .unwrap_or_else(|| vec![PathBuf::from(".")])
    } else {
        roots
    };

    let app_state = TrayApp {
        ctx: Mutex::new(IpcContext::new(roots, None, false)),
        prefs: Mutex::new(prefs),
        prefs_path,
        last_assessment: Mutex::new(None),
    };

    let modifiers = if cfg!(target_os = "macos") {
        Modifiers::SUPER
    } else {
        Modifiers::CONTROL
    };
    let shortcut = Shortcut::new(Some(modifiers | Modifiers::SHIFT), Code::KeyG);

    tauri::Builder::default()
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if event.state == ShortcutState::Pressed {
                        toggle_palette(app);
                    }
                })
                .build(),
        )
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            palette_search,
            daemon_status,
            recent_queries,
            pin_scope,
            scan_hit,
            open_hit,
            hide_palette,
            auto_start_enabled,
            toggle_auto_start
        ])
        .setup(move |app| {
            build_tray(app.handle())?;
            if let Err(e) = app.handle().global_shortcut().register(shortcut) {
                eprintln!("cannot register the quick-search shortcut: {e}");
            }
            refresh_tray(app.handle());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running the Guará tray");
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let auto_start = app
        .try_state::<TrayApp>()
        .map(|state| state.preferences().auto_start)
        .unwrap_or(false);

    let quick_search = MenuItem::with_id(
        app,
        "quick-search",
        "Quick search",
        true,
        Some("CmdOrCtrl+Shift+G"),
    )?;
    let auto_item = CheckMenuItem::with_id(
        app,
        "auto-start",
        "Start at login",
        true,
        auto_start,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit Guará", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&quick_search, &auto_item, &separator, &quit])?;

    let icon = tray_image(TrayState::Idle);
    // Cloned into the menu handler so the check state can follow the toggle.
    let auto_item_handle = auto_item.clone();

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon.expect("the bundled tray icon must decode"))
        .tooltip("Guará")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "quick-search" => toggle_palette(app),
            "auto-start" => {
                let enabled = toggle_auto_start(app.clone());
                let _ = auto_item_handle.set_checked(enabled);
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_palette(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

fn toggle_palette(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(PALETTE) {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
        } else {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
    refresh_tray(app);
}

/// Recompute the tray state and push the matching icon and tooltip.
fn refresh_tray(app: &AppHandle) {
    let Some(state) = app.try_state::<TrayApp>() else {
        return;
    };
    let status = match state.dispatch(Request::Status) {
        Response::Status(report) => report,
        _ => return,
    };
    let assessment = state
        .last_assessment
        .lock()
        .ok()
        .and_then(|guard| guard.clone());
    let tray_state = state_for(&status, assessment.as_ref());

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        if let Some(image) = tray_image(tray_state) {
            let _ = tray.set_icon(Some(image));
        }
        let _ = tray.set_tooltip(Some(tray_state.tooltip(&status)));
    }
}

/// Bundled icon for a tray state. The asset stays valid for the process, so the
/// image can borrow it for `'static`.
fn tray_image(state: TrayState) -> Option<Image<'static>> {
    let bytes: &'static [u8] = match state {
        TrayState::Idle => include_bytes!("../icons/tray-idle.png"),
        TrayState::Indexing => include_bytes!("../icons/tray-indexing.png"),
        TrayState::Threat => include_bytes!("../icons/tray-threat.png"),
    };
    Image::from_bytes(bytes).ok()
}

/// Open a hit with `$EDITOR` / `$VISUAL`, else the OS opener. Shares the
/// binding contract with `guara tui`.
fn open_with_the_os(path: &str) {
    let words = open_command(std::path::Path::new(path));
    let Some((program, args)) = words.split_first() else {
        return;
    };
    if let Err(e) = Command::new(program).args(args).status() {
        eprintln!("cannot open {path}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_over(root: &std::path::Path) -> TrayApp {
        TrayApp {
            ctx: Mutex::new(IpcContext::new(vec![root.to_path_buf()], None, false)),
            prefs: Mutex::new(Preferences::default()),
            prefs_path: None,
            last_assessment: Mutex::new(None),
        }
    }

    #[test]
    fn every_tray_state_has_a_decodable_icon() {
        for state in [TrayState::Idle, TrayState::Indexing, TrayState::Threat] {
            let image = tray_image(state);
            assert!(image.is_some(), "no bundled icon for {state:?}");
        }
    }

    #[test]
    fn palette_search_runs_the_shared_engine() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("needle.txt"), "a needle\n").unwrap();
        let app = app_over(dir.path());

        match app.dispatch(Request::Search {
            query: "needle".to_string(),
            root: None,
            limit: None,
        }) {
            Response::Hits { hits, .. } => {
                assert_eq!(hits.len(), 1);
                assert!(hits[0].path.ends_with("needle.txt"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn scanning_a_flagged_path_switches_the_tray_to_threat() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("invoice.pdf.exe");
        std::fs::write(&path, b"stub").unwrap();
        let app = app_over(dir.path());

        assert_eq!(app.tray_state(), Some(TrayState::Idle));
        let response = app.scan(path.to_str().unwrap());
        assert!(matches!(response, Response::Assessment { .. }));
        assert_eq!(app.tray_state(), Some(TrayState::Threat));
    }

    #[test]
    fn pinned_scopes_are_persisted_by_the_shell() {
        let dir = tempfile::TempDir::new().unwrap();
        let prefs_path = dir.path().join("tray.json");
        let app = TrayApp {
            ctx: Mutex::new(IpcContext::default()),
            prefs: Mutex::new(Preferences::default()),
            prefs_path: Some(prefs_path.clone()),
            last_assessment: Mutex::new(None),
        };

        let mut prefs = app.preferences();
        prefs.pin_scope(PathBuf::from("/tmp/work"), None);
        app.store_preferences(prefs);

        let reloaded = Preferences::load(&prefs_path).unwrap();
        assert_eq!(reloaded.pinned_scopes.len(), 1);
        assert_eq!(reloaded.pinned_scopes[0].label, "work");
    }

    #[test]
    fn open_targets_the_requested_path() {
        let words = open_command(std::path::Path::new("notes.txt"));
        assert!(words.iter().any(|word| word == "notes.txt"));
    }
}
