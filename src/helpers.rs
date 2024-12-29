use anyhow::anyhow;
use libbpf_rs::XdpFlags;
use pnet::datalink::{self, NetworkInterface};

/// Turns interface name into corresponding index number.
pub fn iface_to_idx(iface: &str) -> Result<i32, anyhow::Error> {
    let interfaces: Vec<NetworkInterface> = datalink::interfaces();
    for i in interfaces {
        if iface.to_lowercase() == i.name {
            return Ok(i.index as i32);
        }
    }
    Err(anyhow!("Interface not found"))
}

/// Turns XDP flag into corresponding type.
pub fn get_xdp_flags(flags: &str) -> Result<XdpFlags, anyhow::Error> {
    match flags {
        "generic" => Ok(XdpFlags::SKB_MODE),
        _ => Err(anyhow!("Flag not found!")),
    }
}
