mod app;
mod helpers;
mod maps;
mod objects;
mod programs;

use std::{
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use app::App;

use anyhow::Context;
use clap::Parser;
use libbpf_rs::{
    MapCore, MapFlags, ObjectBuilder,
};
use tokio::signal;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Options {
    /// Interface name.
    #[arg(short, long, default_value = "eth0")]
    iface: String,
    /// XdpFlags to pass to XDP framework. Available options: generic, native, offloaded.
    #[arg(long, default_value = "generic")]
    xdp_flags: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let options = Options::parse();

    // increase rlimit? sudo cargo automatically does this?.
    //rlimit::increase_nofile_limit(rlimit::INFINITY)?;
    let mut object_builder = ObjectBuilder::default();
    let path = Path::new("./src/bpf/xdp.o");
    let object = objects::get_object(&mut object_builder, path)?;

    let map = maps::get_map(&object, "packet_count").with_context(|| format!("Map not found!"))?;
    let programs = programs::get_programs(&object).with_context(|| format!("Program not found"))?;

    let program = programs
        .get("hello_packets")
        .with_context(|| format!("Program does not exist"))?;
    let xdp = programs::attach_xdp(&program, &options)?;

    // TUI
    //let mut terminal = ratatui::init();
    //terminal.clear()?;
    //
    //let mut app = App::new(map, xdp, options);
    //let app_result = app.run(&mut terminal);
    //ratatui::restore();
    //
    //Ok(app_result?)

    let should_terminate = Arc::new(Mutex::new(false));
    let signal_handle = should_terminate.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        let mut signal_handle = signal_handle.lock().unwrap();
        *signal_handle = true;
        println!("\rTerminating...");
    });

    while !(*should_terminate.lock().unwrap()) {
        let key: u32 = 127 << 24 | 0 << 16 | 0 << 8 | 1 << 0;
        let mut total_packets: u64 = 0;
        // to_be_bytes converts to [127, 0, 0, 1]
        match map.lookup(&key.to_be_bytes(), MapFlags::ANY) {
            Ok(e) => {
                let som = e.unwrap_or(Vec::new());
                if som.len() != 0 {
                    let mut shift: u64 = 0;
                    for b in &som[0..8] {
                        if *b != 0 {
                            let num = *b as u64;
                            total_packets += num << shift;
                            shift += 8;
                        }
                    }
                    let mut time: u64 = 0;
                    let mut shift: u64 = 0;
                    for b in &som[8..16] {
                        if *b != 0 {
                            let num = *b as u64;
                            time += num << shift;
                            shift += 8;
                        }
                    }
                    println!(
                        "Last accessed at (secs since boot): {}",
                        time / 10_u64.pow(9)
                    );
                    println!("Total packets: {}", total_packets);
                    thread::sleep(Duration::from_secs(2));
                }
            }
            Err(_) => panic!(),
        };
    }

    programs::detach_xdp(&xdp, &options)?;
    Ok(())
}
