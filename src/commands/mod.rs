mod chain_info;
mod decode;
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
            superblock_size,
        } => {
            let cfg = EpochConfig {
                k,
                n,
                buffer,
                c,
                delta,
                symbol_size,
                superblock_size,
            };
            generate::run(&blocks_dir, &output, &cfg)?;
        }
        Commands::Decode {
            input,
            output,
            epoch,
            no_verify,
        } => {
            decode::run(&input, &output, epoch, no_verify)?;
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
            superblock_size,
        } => {
            let cfg = EpochConfig {
                k,
                n,
                buffer,
                c,
                delta,
                symbol_size,
                superblock_size,
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
