mod chain_info;
mod dist_info;
mod experiment;
mod generate;
mod reconstruct;

use sef::epoch::EpochConfig;

use crate::cli::Commands;

pub fn dispatch(command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::DistInfo { k, c, delta } => {
            dist_info::run(k, c, delta);
        }
        Commands::Generate {
            blocks_dir,
            output,
            k,
            n,
            buffer,
            c,
            delta,
            symbol_size,
        } => {
            let cfg = EpochConfig {
                k,
                n,
                buffer,
                c,
                delta,
                symbol_size,
            };
            generate::run(&blocks_dir, &output, &cfg)?;
        }
        Commands::ChainInfo { blocks_dir } => {
            chain_info::run(&blocks_dir)?;
        }
        Commands::Reconstruct {
            blocks_dir,
            k,
            n,
            buffer,
            c,
            delta,
            epoch,
            symbol_size,
        } => {
            let cfg = EpochConfig {
                k,
                n,
                buffer,
                c,
                delta,
                symbol_size,
            };
            reconstruct::run(&blocks_dir, &cfg, epoch)?;
        }
        Commands::Help => {
            use clap::CommandFactory;
            crate::cli::Cli::command().print_help()?;
            println!();
        }
        Commands::Experiment {
            k,
            c,
            delta,
            pool_size,
            trials,
        } => {
            experiment::run(k, c, delta, pool_size, trials)?;
        }
    }

    Ok(())
}
