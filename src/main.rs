#![feature(sync_unsafe_cell)]

mod analyze;
mod config;
mod engine;
mod helpers;
mod load;
mod lua;
mod maps;
mod objects;
mod programs;
mod secret;
mod snippets;
mod unload;

use analyze::analyze;
use anyhow::{anyhow, Context};
use clap::{Args, Parser, Subcommand};
use config::Config;
use engine::generator;
use home::home_dir;
use load::load;
use lua::run_script;
use std::cell::SyncUnsafeCell;
use std::fs;
use std::sync::Mutex;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::LazyLock,
};
use unload::unload;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Options {
    #[command(subcommand)]
    command: Commands,
    /// Config file name [TOML/JSON].
    #[arg(short, long, default_value = "")]
    config: String,
}

#[derive(Args, Debug)]
pub struct Run {
    /// Path of LUA script
    #[arg(short, long, required = true, default_value = None)]
    path: Option<String>,
}

#[derive(Args, Debug)]
pub struct Analyze {}

#[derive(Args, Debug)]
struct Generate {}

#[derive(Args, Debug)]
pub struct Load {
    /// Interface name.
    #[arg(short, long, default_value = "")]
    iface: String,
    /// XdpFlags to pass to XDP framework. Available options: generic, native, offloaded.
    #[arg(long, default_value = "generic")]
    xdp_flags: String,
}

#[derive(Args, Debug)]
pub struct Unload {
    /// Interface name.
    #[arg(short, long, default_value = "")]
    iface: String,
    /// XdpFlags to pass to XDP framework. Available options: generic, native, offloaded.
    #[arg(long, default_value = "generic")]
    xdp_flags: String,
    /// Program ID.
    #[arg(short, long, default_value = "")]
    pid: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generates eBPF program on provided or default config
    Generate(Generate),
    Load(Load),
    Unload(Unload),
    Analyze(Analyze),
    Secret,
    Run(Run),
}

pub static WORKING_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    format!(
        "{}/.hpx",
        home_dir()
            .expect("Error: HOME dir not found or smth")
            .to_str()
            .expect("Error: HOME dir not found or smth")
    )
    .into()
});

// I DONT LIKE THIS BUT IDK OTHER WAY TO DO THIS
static SSH_PASS: SyncUnsafeCell<Mutex<String>> = SyncUnsafeCell::new(Mutex::new(String::new()));

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let working_dir = Path::new(
        WORKING_DIR
            .to_str()
            .with_context(|| format!("Failed to parse HOME directory"))?,
    );

    if !working_dir.exists()
        || !Path::new(format!("{}/out/vmlinux.h", working_dir.display()).as_str()).exists()
        || !Path::new(format!("{}/out/", working_dir.display()).as_str()).exists()
    {
        fs::create_dir_all(format!("{}/out", working_dir.display()))?;
        fs::create_dir(format!("{}/scripts", working_dir.display()))?;
        Command::new("sh")
            .args(&[
                "-c",
                format!(
                    "bpftool btf dump file /sys/kernel/btf/vmlinux format c > {}/out/vmlinux.h",
                    working_dir.display()
                )
                .as_str(),
            ])
            .output()?;
    }

    let options = Options::parse();

    let config_file = Path::new(&options.config);

    let user_config_file;
    let config: Config;

    if !config_file.exists() && !options.config.is_empty() {
        return Err(anyhow!(
            "File does not exist!\nSearched locations: {}",
            config_file.display()
        ));
    }

    match config_file.extension() {
        Some(e) => match e.to_str().unwrap() {
            "json" => {
                user_config_file = fs::read_to_string(config_file)?;
                config = serde_json::from_str(&user_config_file)?;
            }
            "toml" => {
                user_config_file = fs::read_to_string(config_file)?;
                config = toml::from_str(&user_config_file)?;
            }
            _ => {
                return Err(anyhow!(
                    "File type is not supported!\nSuppored file types: JSON, TOML."
                ));
            }
        },
        None => {
            config = Config::default();
        }
    }

    match options.command {
        Commands::Generate(options) => {
            generator(options, config)?;
        }
        Commands::Analyze(options) => {
            analyze(options, config)?;
        }
        Commands::Load(mut options) => {
            load(&mut options, config).await?;
        }
        Commands::Unload(mut options) => unload(&mut options, config)?,
        Commands::Secret => secret::secret(),
        Commands::Run(options) => {
            let result = run_script(
                WORKING_DIR
                    .to_str()
                    .with_context(|| format!("Failed to parse HOME directory"))?,
                options.path.as_deref(),
            )
            .await;
            match result {
                Ok(_) => (),
                Err(e) => return Err(anyhow!("{}", e)),
            };
        }
    }

    Ok(())
}
