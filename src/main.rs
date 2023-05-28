use chat::{init, CliArgs};
use clap::Parser;
use home::home_dir;
use log::*;
use simplelog::*;
use std::{
    error::Error,
    fs::{self, File},
};

fn init_logging() -> Result<(), Box<dyn Error>> {
    let log_file_path = home_dir()
        .ok_or("Failed to get home directory")?
        .join(".local")
        .join("state")
        .join("chat_rs.log");

    fs::create_dir_all(log_file_path.parent().unwrap())?;

    let config = ConfigBuilder::new()
        .set_location_level(LevelFilter::Trace)
        .build();

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Error,
            config.clone(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Trace,
            config.clone(),
            File::create(log_file_path).unwrap(),
        ),
    ])?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging()?;
    info!("chat_rs launched");
    println!("Welcome to LAN chat");
    let args: CliArgs = CliArgs::parse();
    info!("Parsed CLI arguments: {:#?}", args);
    init(args)?;
    Ok(())
}
