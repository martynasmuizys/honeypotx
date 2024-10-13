use std::{os::fd::AsFd, path::Path, sync::{Arc, Mutex}, thread, time::Duration};

use anyhow::{anyhow, Context};
use clap::Parser;
use libbpf_rs::{MapCore, MapFlags, ObjectBuilder, Xdp, XdpFlags};
use pnet::datalink::{self, NetworkInterface};
use tokio::signal;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    /// Interface name.
    #[arg(short, long, default_value = "lo")]
    iface: String,
    /// XdpFlags to pass to XDP framework. Available options: generic, native, offloaded.
    #[arg(long, default_value = "generic")]
    xdp_flags: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let should_terminate = Arc::new(Mutex::new(false));
    signal_handler(should_terminate.clone());
    let options = Options::parse();

    // TODO: increase rlimit? sudo cargo automatically does this?.
    //rlimit::increase_nofile_limit(rlimit::INFINITY)?;
    let mut object_builder = ObjectBuilder::default();
    let path = Path::new("./src/bpf/xdp.o");
    let open_object = object_builder
        .open_file(path)
        .with_context(|| format!("Failed to open object file {:?}", path))?;
    let object = open_object
        .load()
        .with_context(|| format!("Failed to load BPF program"))?;

    // this works for now because we only have 1 program and 1 map
    let mut map = object.maps().peekable();
    let map = map.peek().unwrap();
    let mut program = object.progs().peekable();
    let program = program.peek().unwrap();
    let xdp = Xdp::new(program.as_fd());
    xdp.attach(
        iface_to_idx(&options.iface)?,
        get_xdp_flags(&options.xdp_flags)?,
    )
    .with_context(|| format!("Failed to attach BPF program to XDP"))?;

    //this should be different
    while !(*should_terminate.lock().unwrap()) {
        let key: u32 = 127 << 24 | 0 << 16 | 0 << 8 | 1 << 0;
        // to_be_bytes converts to [127, 0, 0, 1]
        println!("{:?}", map.lookup(&key.to_be_bytes(), MapFlags::ANY));
        thread::sleep(Duration::from_secs(5));
    }
    // 1: lo -> ip link show
    xdp.detach(
        iface_to_idx(&options.iface)?,
        get_xdp_flags(&options.xdp_flags)?,
    )
    .with_context(|| format!("Failed to detach BPF program from XDP"))?;
    Ok(())
}

fn signal_handler(signal: Arc<Mutex<bool>>) {
    // what if user presses ctrl-z? xdp program wont be detached or what?
    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        let mut signal = signal.lock().unwrap();
        *signal = true;
        println!("\rTerminating...");
    });
}

/// Turns interface name into corresponding index number.
fn iface_to_idx(iface: &str) -> Result<i32, anyhow::Error> {
    let interfaces: Vec<NetworkInterface> = datalink::interfaces();
    for i in interfaces {
        if iface.to_lowercase() == i.name {
            return Ok(i.index as i32);
        }
    }
    return Err(anyhow!("Interface not found"));
}

/// Turns XDP flag into corresponding type.
fn get_xdp_flags(flags: &str) -> Result<XdpFlags, anyhow::Error> {
    match flags {
        "generic" => return Ok(XdpFlags::SKB_MODE),
        _ => return Err(anyhow!("Flag not found!")),
    }
}
