mod cli;
mod tui;

use clap::Parser;
use cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    cli::init_tracing(cli.verbose, cli.quiet);

    let quiet = cli.quiet;
    let db = cli.db.clone();
    let code = match cli.command {
        Some(Command::Search(args)) => cli::run_search(*args, quiet, db),
        Some(Command::Config(_)) => cli::run_config(),
        Some(Command::Index(args)) => match args.action {
            Some(cli::IndexAction::Status) => cli::run_index_status(db),
            None => cli::run_index(args.pass, false, quiet, db),
        },
        Some(Command::Reindex(pass)) => cli::run_index(pass, true, quiet, db),
        Some(Command::History(args)) => cli::run_history(args.limit, db),
        Some(Command::Serve(args)) => cli::run_serve(args, quiet, db),
        Some(Command::Tui(args)) => tui::run(*args, quiet, db),
        // No subcommand: search is the default command.
        None => cli::run_search(cli.search, quiet, db),
    };
    std::process::exit(code);
}
