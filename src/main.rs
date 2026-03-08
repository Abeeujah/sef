use clap::Parser;

mod cli;
mod commands;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = cli::Cli::parse();
    commands::dispatch(cli.command)
}
