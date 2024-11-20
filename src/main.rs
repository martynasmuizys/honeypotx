mod analyze;
mod config;
mod engine;
mod helpers;
mod maps;
mod objects;
mod programs;
mod secret;
mod snippets;

use std::{
    fs::{self, File},
    io::{self, stdout, Write},
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use analyze::analyze;
use anyhow::{anyhow, Context};
use clap::{Args, Parser, Subcommand};
use config::{Config, DEFAULT_NET_IFACE};
use crossterm::{
    style::Stylize,
    terminal::{Clear, ClearType},
    ExecutableCommand,
};
use libbpf_rs::{MapCore, MapFlags, ObjectBuilder};
use secret::GOSLING;
use tokio::signal;

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
pub struct Run {}

#[derive(Args, Debug)]
pub struct Analyze {}

#[derive(Args, Debug)]
struct Generate {}

#[derive(Args, Debug)]
pub struct Load {
    /// Interface name.
    #[arg(short, long, default_value = DEFAULT_NET_IFACE)]
    iface: String,
    /// XdpFlags to pass to XDP framework. Available options: generic, native, offloaded.
    #[arg(long, default_value = "generic")]
    xdp_flags: String,
}

#[derive(Args, Debug)]
pub struct Secret {}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generates eBPF program on provided or default config
    Generate(Generate),
    Load(Load),
    Analyze(Analyze),
    Secret(Secret),
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
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
        Commands::Generate(options) => generate(options, config)?,
        Commands::Analyze(options) => analyze(options, config)?,
        Commands::Load(mut options) => load(&mut options, config).await?,
        Commands::Secret(_) => secret::secret(),
    }

    Ok(())
}

fn generate(_options: Generate, config: Config) -> Result<(), anyhow::Error> {
    let path = Path::new("./src/bpf/generated.c");
    let out_file = fs::File::create(path)?;
    engine::generate(config, out_file)?;
    Command::new("clang-format").arg("-i").arg(path).spawn()?;
    Command::new("clang")
        .arg("-O2")
        .arg("-g")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(path)
        .arg("-o")
        .arg("src/bpf/generated.o")
        .spawn()?;
    Ok(())
}

async fn load(options: &mut Load, config: Config) -> Result<(), anyhow::Error> {
    let config_iface = config.init.as_ref().unwrap().iface.as_ref();
    if config_iface.is_some() && *config_iface.unwrap() != options.iface {
        let mut action = String::new();
        print!(
            "{}: Network interface differs from config. Are you sure you want to proceed? [Y/n] ",
            "Load".blue().bold()
        );
        io::stdout().flush()?;
        io::stdin().read_line(&mut action)?;

        let action = action.trim().to_lowercase();

        if action != "y" && action != "yes" && action != "" {
            return Err(anyhow!("Cancelled"));
        }

        options.iface = config_iface.unwrap().to_string();
    }

    //
    //// increase rlimit? sudo cargo automatically does this?.
    ////rlimit::increase_nofile_limit(rlimit::INFINITY)?;
    //clang -O2 -g -target bpf -c src/bpf/xdp.c -o src/bpf/xdp.o
    let path = "./src/bpf/generated.o";
    let mut object_builder = ObjectBuilder::default();
    let object = objects::get_object(&mut object_builder, Path::new(path))?;

    //let map = maps::get_map(&object, "packet_count")
    //    .with_context(|| format!("Map not found!"))?;
    let programs = programs::get_programs(&object).with_context(|| format!("Program not found"))?;

    let name = config.init.unwrap().name.unwrap().clone();
    let program = programs
        .get(&name)
        .with_context(|| format!("Program does not exist"))?;
    let xdp = programs::attach_xdp(&program, &options)?;

    //let should_terminate = Arc::new(Mutex::new(false));
    //let signal_handle = should_terminate.clone();
    //tokio::spawn(async move {
    //    signal::ctrl_c().await.unwrap();
    //    let mut signal_handle = signal_handle.lock().unwrap();
    //    *signal_handle = true;
    //    println!("\rTerminating...");
    //});

    //while !(*should_terminate.lock().unwrap()) {
    //let key: u32 = 127 << 24 | 0 << 16 | 0 << 8 | 1 << 0;
    //let mut total_packets: u64 = 0;
    //// to_be_bytes converts to [127, 0, 0, 1]
    //match map.lookup(&key.to_be_bytes(), MapFlags::ANY) {
    //    Ok(e) => {
    //        let som = e.unwrap_or(Vec::new());
    //        if som.len() != 0 {
    //            let mut shift: u64 = 0;
    //            for b in &som[0..8] {
    //                if *b != 0 {
    //                    let num = *b as u64;
    //                    total_packets += num << shift;
    //                    shift += 8;
    //                }
    //            }
    //            let mut time: u64 = 0;
    //            let mut shift: u64 = 0;
    //            for b in &som[8..16] {
    //                if *b != 0 {
    //                    let num = *b as u64;
    //                    time += num << shift;
    //                    shift += 8;
    //                }
    //            }
    //            println!(
    //                "Last accessed at (secs since boot): {}",
    //                time / 10_u64.pow(9)
    //            );
    //            println!("Total packets: {}", total_packets);
    //            thread::sleep(Duration::from_secs(2));
    //        }
    //    }
    //    Err(_) => panic!(),
    //};
    //}

    signal::ctrl_c().await.unwrap();
    programs::detach_xdp(&xdp, &options)?;
    Ok(())
}
