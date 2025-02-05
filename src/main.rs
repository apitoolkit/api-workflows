pub mod base_cli;
pub mod base_request;

use anyhow::Ok;
use base_cli::{Cli, Commands};
use base_request::TestContext;
use clap::Parser;
use dotenv::dotenv;
use log::LevelFilter;
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use walkdir::WalkDir;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let cli_instance = Cli::parse();

    let mut builder = env_logger::Builder::from_default_env();
    builder
        .format_timestamp(None)
        .format_target(true)
        .filter_level(LevelFilter::from_str(&cli_instance.log_level).unwrap_or(LevelFilter::Info))
        .init();

    match cli_instance.command {
        None | Some(Commands::App {}) => {
            println!("App mode not implemented. Use the 'test' command to run tests.");
        }
        Some(Commands::Test { file }) => cli(file, &cli_instance.filter, &cli_instance.output)
            .await
            .unwrap(),
    }
}

async fn cli(
    file_op: Option<PathBuf>,
    _filter: &Option<String>,
    output: &str,
) -> Result<(), anyhow::Error> {
    if let Some(file) = file_op {
        let content = fs::read_to_string(file.clone())?;
        let ctx = TestContext {
            file: Arc::new(file.to_str().unwrap().to_string()),
            file_source: Arc::new(content.clone()),
            should_log: true,
            ..Default::default()
        };
        let results = base_request::run(ctx, content)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        output_results(results, output);
        Ok(())
    } else {
        let files = find_tk_yaml_files(Path::new("."));
        for file in files {
            let content = fs::read_to_string(file.clone())?;
            let ctx = TestContext {
                file: Arc::new(file.to_str().unwrap().to_string()),
                file_source: Arc::new(content.clone()),
                should_log: true,
                ..Default::default()
            };
            let results = base_request::run(ctx, content)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            output_results(results, output);
        }
        Ok(())
    }
}

fn find_tk_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Some(extension) = entry.path().extension() {
                if extension == "yaml"
                    && entry
                        .path()
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .contains(".tk")
                {
                    result.push(entry.path().to_path_buf());
                }
            }
        }
    }
    result
}

fn output_results(results: Vec<base_request::RequestResult>, output: &str) {
    match output {
        "json" => {
            // Obtain the colored JSON string.
            let colored_result = colored_json::to_colored_json_auto(&results);
            match colored_result {
                std::result::Result::Ok(colored_str) => {
                    println!("{}", colored_str);
                }
                std::result::Result::Err(_) => {
                    let json =
                        serde_json::to_string_pretty(&results).unwrap_or_else(|_| "{}".into());
                    println!("{}", json);
                }
            }
        }
        _ => {
            // Plain text output using Debug formatting.
            for res in results {
                println!("{:#?}", res);
            }
        }
    }
}
