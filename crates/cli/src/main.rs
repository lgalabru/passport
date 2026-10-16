//! `passport` CLI.

use clap::{CommandFactory, Parser, Subcommand};

mod commands;
mod components;
mod style;

#[derive(Parser, Debug)]
#[command(
    name = "passport",
    version,
    about = "passport",
    propagate_version = true
)]
struct Cli {
    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Write the config, install the agent skill and register the MCP server
    Setup(commands::setup::SetupCommand),
    /// Run the MCP server over stdio
    Mcp(commands::mcp::McpCommand),
    /// Wait for a Flipper to read a document and print what it read
    Scan(commands::scan::ScanCommand),
    /// Generate shell completions
    Completions(commands::completions::CompletionsCommand),
}

fn main() {
    let cli = Cli::parse();
    style::init(!cli.no_color);
    let result = match cli.command {
        Command::Setup(cmd) => cmd.execute(),
        Command::Mcp(cmd) => cmd.execute(),
        Command::Scan(cmd) => cmd.execute(),
        Command::Completions(cmd) => {
            cmd.execute(&mut Cli::command());
            Ok(())
        }
    };
    if let Err(e) = result {
        // First line is the headline; anything after it is detail. An empty
        // message means the command already reported the problem.
        let text = e.to_string();
        if !text.is_empty() {
            let mut lines = text.lines();
            let title = lines.next().unwrap_or("error");
            let body: Vec<&str> = lines.map(str::trim_start).collect();
            components::print_notice(components::NoticeLevel::Error, title, &body.join("\n"));
        }
        std::process::exit(e.exit_code());
    }
}
