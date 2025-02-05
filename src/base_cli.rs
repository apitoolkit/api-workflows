use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "testkit")]
#[command(author = "APIToolkit. <hello@apitoolkit.io>")]
#[command(version = "1.0")]
#[command(about = "Manually and Automated testing starting with APIs", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Sets the log level (trace, debug, info, warn, error)
    #[arg(short, long, global = true, default_value = "info")]
    pub log_level: String,

    /// Optional filter to only run tests whose title contains this substring.
    #[arg(short = 'q', long, global = true)]
    pub filter: Option<String>,

    /// Output format: plain or json (for CI systems)
    #[arg(short, long, global = true, default_value = "plain")]
    pub output: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run tests from a YAML test configuration file.
    Test {
        /// Path to the YAML test configuration file.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Run the application mode (not implemented yet).
    App {},
}
