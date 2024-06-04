use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "testkit")]
#[command(author = "APIToolkit. <hello@apitoolkit.io>")]
#[command(version = "1.0")]
#[command(about = "Manually and Automated testing starting with APIs and Browser", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Sets the log level to be used. Eg trace, debug, warn, info, error
    #[arg(short, long, default_value = "info")]
    pub log_level: String,
}

#[derive(Subcommand)]
pub enum Commands {
    Test {
        /// Run browser tests
        #[arg(short = 'i', long)]
        api: bool,

        #[arg(short = 'b', long)]
        browser: bool,

        /// Sets the YAML test configuration file
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    App {},
}
