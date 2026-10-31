//! `guara tui`: a ratatui result browser over the search engine.
//!
//! The state machine lives in [`guara_core::tui`]; this module owns terminal
//! setup, key events, rendering, and launching `$EDITOR` / the OS opener.

use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::Command;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use guara_core::config;
use guara_core::output::{format_human, format_stats, ColorMode, OutputOptions};
use guara_core::search::FileResult;
use guara_core::security::{HeuristicConfig, Verdict};
use guara_core::tui::{open_command, Mode, PreviewKind, TuiState};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::DefaultTerminal;

use crate::cli::{collect_search, finish_progress, start_progress, SearchArgs, SearchRun};

/// Keys shown in the footer so the bindings are discoverable.
const KEY_HINT: &str =
    "q quit  / filter  j/k move  g/G ends  PgDn/PgUp page  o open  s scan  c clear";

/// What the terminal should do after a key press.
enum Action {
    /// Redraw and keep reading events.
    None,
    /// Close the browser; the process exits 0.
    Quit,
    /// Suspend the UI, hand the terminal to an editor or OS opener.
    Open(PathBuf),
}

/// Entry point for `guara tui`.
pub fn run(args: SearchArgs, quiet: bool, db: Option<PathBuf>) -> i32 {
    let start = std::time::Instant::now();
    let progress = start_progress(quiet);
    let search_run = collect_search(&args, db.as_deref());
    finish_progress(progress);

    let SearchRun {
        results,
        stats,
        walk_errors,
    } = match search_run {
        Ok(run) => run,
        Err(code) => return code,
    };

    if results.is_empty() {
        if !quiet {
            eprintln!("{}", format_stats(&stats, start.elapsed()));
        }
        eprintln!("no hits to browse");
        return 1;
    }

    // Without a terminal (a pipe or CI) the browser cannot run. Print results
    // the way `guara search` does so the command stays scriptable.
    if !io::stdout().is_terminal() {
        let opts = OutputOptions {
            color: ColorMode::Auto,
            compact: false,
            table: false,
        };
        print!("{}", format_human(&results, &opts));
        if !quiet {
            eprintln!("{}", format_stats(&stats, start.elapsed()));
            eprintln!("stdout is not a terminal; printed results instead of the browser");
        }
        return if walk_errors > 0 { 3 } else { 0 };
    }

    let code = match interactive(results) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tui error: {e}");
            return 2;
        }
    };

    if walk_errors > 0 {
        eprintln!("{walk_errors} walk errors");
    }
    code
}

/// Own the terminal for the lifetime of the browser and always restore it.
fn interactive(results: Vec<FileResult>) -> io::Result<i32> {
    let security = config::load().unwrap_or_default().security;
    let mut terminal = ratatui::try_init()?;
    let mut state = TuiState::new(results, 0);

    let outcome = event_loop(&mut terminal, &mut state, &security);
    ratatui::try_restore()?;
    outcome
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    state: &mut TuiState,
    security: &HeuristicConfig,
) -> io::Result<i32> {
    loop {
        terminal.draw(|frame| draw(frame, state))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match handle_key(state, key, security) {
            Action::None => {}
            Action::Quit => return Ok(0),
            Action::Open(path) => suspend(terminal, || launch(&path))?,
        }
    }
}

fn handle_key(state: &mut TuiState, key: KeyEvent, security: &HeuristicConfig) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if let KeyCode::Char('c') = key.code {
            return Action::Quit;
        }
    }

    if state.mode() == Mode::Filter {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                state.leave_filter();
                state.clear_status();
            }
            KeyCode::Char(c) => state.push_filter(c),
            KeyCode::Backspace => state.pop_filter(),
            KeyCode::Down => state.move_selection(1),
            KeyCode::Up => state.move_selection(-1),
            _ => {}
        }
        return Action::None;
    }

    state.clear_status();
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
        KeyCode::Char('j') | KeyCode::Down => state.move_selection(1),
        KeyCode::Char('k') | KeyCode::Up => state.move_selection(-1),
        KeyCode::Char('g') | KeyCode::Home => state.select_first(),
        KeyCode::Char('G') | KeyCode::End => state.select_last(),
        KeyCode::PageDown => state.page_down(),
        KeyCode::PageUp => state.page_up(),
        KeyCode::Char('/') => state.enter_filter(),
        KeyCode::Char('c') => {
            state.clear_filter();
            state.set_status("filter cleared");
        }
        KeyCode::Char('s') => {
            state.scan_selected(security);
        }
        KeyCode::Char('o') | KeyCode::Enter => {
            if let Some(path) = state.selected_path() {
                return Action::Open(path.to_path_buf());
            }
        }
        _ => {}
    }
    Action::None
}

/// Leave the alternate screen, run `job` on the real terminal, then re-enter.
fn suspend<F>(terminal: &mut DefaultTerminal, job: F) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    ratatui::try_restore()?;
    let outcome = job();
    *terminal = ratatui::try_init()?;
    outcome
}

/// Open a path with `$EDITOR` / `$VISUAL`, falling back to the OS opener.
fn launch(path: &Path) -> io::Result<()> {
    let words = open_command(path);
    let Some((program, args)) = words.split_first() else {
        return Ok(());
    };
    match Command::new(program).args(args).status() {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("cannot open {}: {e}", path.display());
            Ok(())
        }
    }
}

fn draw(frame: &mut ratatui::Frame, state: &mut TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(frame.area());

    // The list block draws a border, so only the interior shows rows.
    let list_rows = chunks[0].height.saturating_sub(2) as usize;
    state.set_viewport_rows(list_rows.max(1));

    frame.render_widget(list_widget(state), chunks[0]);
    frame.render_widget(preview_widget(state), chunks[1]);
    frame.render_widget(footer_widget(state), chunks[2]);
}

fn list_widget(state: &TuiState) -> Paragraph<'static> {
    let title = if state.filter().is_empty() {
        format!(
            " results {}/{} ",
            state.visible_count(),
            state.result_count()
        )
    } else {
        format!(
            " results {}/{} | filter \"{}\" ",
            state.visible_count(),
            state.result_count(),
            state.filter()
        )
    };

    let selected = state.selected();
    let lines: Vec<Line> = state
        .window()
        .iter()
        .filter_map(|index| {
            let result = state.result(*index)?;
            Some(row_line(result, Some(*index) == selected))
        })
        .collect();

    let lines = if lines.is_empty() {
        vec![Line::from(Span::styled(
            "no result matches the filter",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        lines
    };

    Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title))
}

fn row_line(result: &FileResult, is_selected: bool) -> Line<'static> {
    let selected_style = if is_selected {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    let verdict_style = match result.security.verdict {
        Verdict::Clean => Style::default().fg(Color::DarkGray),
        Verdict::Suspicious => Style::default().fg(Color::Yellow),
        Verdict::HighRisk => Style::default().fg(Color::Red),
    };

    let marker = if is_selected { "> " } else { "  " };
    Line::from(vec![
        Span::styled(marker.to_string(), selected_style),
        Span::styled(result.path.display().to_string(), selected_style),
        Span::styled(
            format!("  {} hit(s)", result.total_hits()),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("  [{}]", result.security.verdict.as_str()),
            verdict_style,
        ),
    ])
}

fn preview_widget(state: &TuiState) -> Paragraph<'static> {
    let lines: Vec<Line> = state
        .preview()
        .into_iter()
        .map(|line| Line::from(Span::styled(line.text, preview_style(line.kind))))
        .collect();

    Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" preview "))
        .wrap(Wrap { trim: false })
}

fn preview_style(kind: PreviewKind) -> Style {
    match kind {
        PreviewKind::Path => Style::default().add_modifier(Modifier::BOLD),
        PreviewKind::Meta => Style::default().fg(Color::Cyan),
        PreviewKind::Match => Style::default().fg(Color::Green),
        PreviewKind::Context => Style::default().fg(Color::DarkGray),
        PreviewKind::Security | PreviewKind::Scan => Style::default().fg(Color::Yellow),
        PreviewKind::Note => Style::default().fg(Color::DarkGray),
    }
}

fn footer_widget(state: &TuiState) -> Paragraph<'static> {
    let line = if state.mode() == Mode::Filter {
        Line::from(vec![
            Span::styled(
                "/",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(state.filter().to_string()),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            Span::styled(
                "  enter/esc back to list  backspace delete",
                Style::default().fg(Color::DarkGray),
            ),
        ])
    } else {
        match state.status() {
            Some(status) => Line::from(vec![
                Span::styled(format!("{status}  "), Style::default().fg(Color::Yellow)),
                Span::styled(KEY_HINT, Style::default().fg(Color::DarkGray)),
            ]),
            None => Line::from(Span::styled(KEY_HINT, Style::default().fg(Color::DarkGray))),
        }
    };

    Paragraph::new(line)
}
