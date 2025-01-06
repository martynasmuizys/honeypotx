use std::fmt::Display;

use crossterm::style::Stylize;
use serde::{Deserialize, Serialize};

pub static DEFAULT_NET_IFACE: &str = "eth0";
pub static DEFAULT_FREQUENCY: u32 = 1000;
pub static DEFAULT_FAST_PACKETS: u32 = 100;

pub static DEFAULT_NAME: &str = "ExampleProgram";
static DEFAULT_MAX_IPS: u32 = 32;
static DEFAULT_WHITELIST_ACTION: &str = "allow";
static DEFAULT_BLACKLIST_ACTION: &str = "deny";
static DEFAULT_GRAYLIST_ACTION: &str = "investigate";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub init: Option<Init>,
    pub data: Option<Data>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Init {
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub iface: Option<String>,
    pub prog_type: Option<String>,
    pub xdp_action: Option<String>,
    pub whitelist: Option<Whitelist>,
    pub blacklist: Option<Blacklist>,
    pub graylist: Option<Graylist>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Data {
    pub whitelist: Option<Vec<String>>,
    pub blacklist: Option<Vec<String>>,
    pub graylist: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Whitelist {
    pub enabled: Option<bool>,
    pub max: Option<u32>,
    pub action: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Blacklist {
    pub enabled: Option<bool>,
    pub max: Option<u32>,
    pub action: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Graylist {
    pub enabled: Option<bool>,
    pub max: Option<u32>,
    pub action: Option<String>,
    pub frequency: Option<u32>,
    pub fast_packet_count: Option<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            init: Some(Init::default()),
            data: None
        }
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "├─ Hostname: {}\n├─ Port: {}\n├─ Username: {}\n├─ Network Interface: {}\n├─ eBPF Program Type: {}\n├─ eBPF Program Type: {} \n├─ eBPF Program Name: {}\n├─ Maps:\n├─── {}: \n{}├─── {}: \n{}└─── {}: \n{}",
            self.init
                .as_ref()
                .unwrap()
                .hostname
                .as_ref()
                .unwrap_or(&"localhost".to_string())
                .as_str()
                .green()
                .bold(),
            self.init
                .as_ref()
                .unwrap()
                .port
                .as_ref()
                .unwrap_or(&22)
                .to_string()
                .green()
                .bold(),
            self.init
                .as_ref()
                .unwrap()
                .username
                .as_ref()
                .unwrap_or(&"-".to_string())
                .as_str()
                .green()
                .bold(),
            self.init
                .as_ref()
                .unwrap()
                .iface
                .as_ref()
                .unwrap_or(&DEFAULT_NET_IFACE.to_string())
                .as_str()
                .green()
                .bold(),
            self.init
                .as_ref()
                .unwrap()
                .prog_type
                .as_ref()
                .unwrap_or(&"ip".to_string())
                .to_uppercase()
                .as_str()
                .green()
                .bold(),
            self.init
                .as_ref()
                .unwrap()
                .xdp_action
                .as_ref()
                .unwrap_or(&"pass".to_string())
                .as_str()
                .green()
                .bold(),
            self.init
                .as_ref()
                .unwrap()
                .name
                .as_ref()
                .unwrap()
                .as_str()
                .green()
                .bold(),
            "Whitelist".on_white().black(),
            self.init
                .as_ref()
                .unwrap()
                .whitelist
                .as_ref()
                .unwrap_or(&Whitelist::default()),
            "Blacklist".on_black().white(),
            self.init
                .as_ref()
                .unwrap()
                .blacklist
                .as_ref()
                .unwrap_or(&Blacklist::default()),
            "Graylist".on_grey().black(),
            self.init
                .as_ref()
                .unwrap()
                .graylist
                .as_ref()
                .unwrap_or(&Graylist::default()),
        )
    }
}

impl Display for Blacklist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "│       ├─ Enabled: {}\n│       ├─ Max IPs: {}\n│       └─ Action: {}\n",
            self.enabled
                .as_ref()
                .unwrap_or(&false)
                .to_string()
                .green()
                .bold(),
            self.max
                .as_ref()
                .unwrap_or(&DEFAULT_MAX_IPS)
                .to_string()
                .green()
                .bold(),
            self.action
                .as_ref()
                .unwrap_or(&DEFAULT_BLACKLIST_ACTION.to_string())
                .as_str()
                .green()
                .bold(),
        )
    }
}

impl Display for Whitelist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "│       ├─ Enabled: {}\n│       ├─ Max IPs: {}\n│       └─ Action: {}\n",
            self.enabled
                .as_ref()
                .unwrap_or(&false)
                .to_string()
                .green()
                .bold(),
            self.max
                .as_ref()
                .unwrap_or(&DEFAULT_MAX_IPS)
                .to_string()
                .green()
                .bold(),
            self.action
                .as_ref()
                .unwrap_or(&DEFAULT_WHITELIST_ACTION.to_string())
                .as_str()
                .green()
                .bold(),
        )
    }
}

impl Display for Graylist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "        ├─ Enabled: {}\n        ├─ Max IPs: {}\n        ├─ Action: {}\n        ├─ Frequency: {}\n        └─ Allowed Fast Packet Count: {}",
            self.enabled
                .as_ref()
                .unwrap_or(&false)
                .to_string()
                .green()
                .bold(),
            self.max
                .as_ref()
                .unwrap_or(&DEFAULT_MAX_IPS)
                .to_string()
                .green()
                .bold(),
            self.action
                .as_ref()
                .unwrap_or(&DEFAULT_GRAYLIST_ACTION.to_string())
                .as_str()
                .green()
                .bold(),
            self.frequency
                .as_ref()
                .unwrap_or(&DEFAULT_FREQUENCY)
                .to_string()
                .green()
                .bold(),
            self.fast_packet_count
                .as_ref()
                .unwrap_or(&DEFAULT_FAST_PACKETS)
                .to_string()
                .green()
                .bold(),
        )
    }
}

impl Default for Init {
    fn default() -> Self {
        Self {
            name: Some(DEFAULT_NAME.to_string()),
            hostname: None,
            port: None,
            iface: Some(DEFAULT_NET_IFACE.to_string()),
            username: None,
            prog_type: Some("ip".to_string()),
            xdp_action: Some("PASS".to_string()),
            whitelist: Some(Whitelist::default()),
            blacklist: Some(Blacklist::default()),
            graylist: Some(Graylist::default()),
        }
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            max: Some(DEFAULT_MAX_IPS),
            action: Some(DEFAULT_WHITELIST_ACTION.to_string()),
        }
    }
}

impl Default for Blacklist {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            max: Some(DEFAULT_MAX_IPS),
            action: Some(DEFAULT_BLACKLIST_ACTION.to_string()),
        }
    }
}

impl Default for Graylist {
    fn default() -> Self {
        Self {
            enabled: Some(true),
            max: Some(DEFAULT_MAX_IPS),
            action: Some(DEFAULT_GRAYLIST_ACTION.to_string()),
            frequency: Some(DEFAULT_FREQUENCY),
            fast_packet_count: Some(DEFAULT_FAST_PACKETS)
        }
    }
}

pub trait List {
    fn get_max(&self) -> u32;
    fn get_action(&self) -> &str;
}

impl List for Whitelist {
    fn get_max(&self) -> u32 {
        self.max.unwrap_or(DEFAULT_MAX_IPS)
    }

    fn get_action(&self) -> &str {
        if let Some(action) = self.action.as_ref() {
            action
        } else {
            DEFAULT_WHITELIST_ACTION
        }
    }
}

impl List for Blacklist {
    fn get_max(&self) -> u32 {
        self.max.unwrap_or(DEFAULT_MAX_IPS)
    }

    fn get_action(&self) -> &str {
        if let Some(action) = self.action.as_ref() {
            action
        } else {
            DEFAULT_BLACKLIST_ACTION
        }
    }
}

impl List for Graylist {
    fn get_max(&self) -> u32 {
        self.max.unwrap_or(DEFAULT_MAX_IPS)
    }

    fn get_action(&self) -> &str {
        if let Some(action) = self.action.as_ref() {
            action
        } else {
            DEFAULT_GRAYLIST_ACTION
        }
    }
}
