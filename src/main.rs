#![feature(sync_unsafe_cell)]

mod analyze;
mod cli;
mod config;
mod engine;
mod get;
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
use clap::Parser;
use cli::{Commands, Get, Options};
use config::Config;
use crossterm::style::Stylize;
use engine::generator;
use get::{
    get_base_config, get_default_config, get_example_config, get_lua_api, get_lua_func_opts,
};
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
            .with_context(|| "Failed to parse HOME directory".to_string())?,
    );

    if !working_dir.exists()
        || !Path::new(format!("{}/out/", working_dir.display()).as_str()).exists()
    {
        fs::create_dir_all(format!("{}/out", working_dir.display()))?;
        fs::create_dir(format!("{}/scripts", working_dir.display()))?;
    }

    // ENSURE CORRECT VMLINUX.H IS USED. DONT LIKE THIS APPROACH BUT UMM YEAH
    if !Path::new(format!("{}/out/vmlinux.h", working_dir.display()).as_str()).exists() {
        Command::new("sh")
            .args([
                "-c",
                format!(
                    "bpftool btf dump file /sys/kernel/btf/vmlinux format c > {}/out/vmlinux.h",
                    working_dir.display()
                )
                .as_str(),
            ])
            .output()?;
    } else {
        Command::new("sh")
            .args([
                "-c",
                format!("bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h",)
                    .as_str(),
            ])
            .output()?;

        let required = fs::read_to_string("/tmp/vmlinux.h")?;
        let actual = fs::read_to_string(format!("{}/out/vmlinux.h", working_dir.display()))?;

        if required.trim() != actual.trim() {
            Command::new("sh")
                .args([
                    "-c",
                    format!(
                        "bpftool btf dump file /sys/kernel/btf/vmlinux format c > {}/out/vmlinux.h",
                        working_dir.display()
                    )
                    .as_str(),
                ])
                .output()?;
        }
    }

    let options = Options::parse();
    let config: Config;

    let config_path = options.config;
    if let Some(c) = config_path {
        let config_file = Path::new(&c);

        let user_config_file;

        if !config_file.exists() && !c.is_empty() {
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
    } else {
        config = Config::default();
    }

    match options.command {
        Commands::Generate(options) => {
            generator(options, config)?;
        }
        Commands::Analyze(options) => {
            analyze(options, config).await?;
        }
        Commands::Load(mut options) => {
            let prog_id = load(&mut options, config).await?;

            if prog_id != 0 {
                println!("{}: Program ID - {prog_id}", "Load".red().bold());
            }
        }
        Commands::Unload(mut options) => unload(&mut options, config)?,
        Commands::Secret => secret::secret().await?,
        Commands::Run(options) => {
            let result = run_script(
                WORKING_DIR
                    .to_str()
                    .with_context(|| "Failed to parse HOME directory".to_string())?,
                options.path.as_deref(),
            )
            .await;
            match result {
                Ok(_) => (),
                Err(e) => return Err(anyhow!("{}", e)),
            };
        }
        Commands::Get(opt) => match opt {
            Get::DefaultConfig(o) => get_default_config(o)?,
            Get::ExampleConfig(o) => get_example_config(o)?,
            Get::BaseConfig(o) => get_base_config(o)?,
            Get::LuaApi => get_lua_api(),
            Get::LuaFuncOpts(o) => get_lua_func_opts(o),
        },
    }

    Ok(())
}
