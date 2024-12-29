use clap::{Args, Parser, Subcommand};

// Main command options
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Options {
    #[command(subcommand)]
    pub command: Commands,
    /// Config file name [TOML/JSON].
    #[arg(short, long, default_value = "")]
    pub config: String,
}

// Subcommands
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Generates eBPF program on provided or default config
    Generate(Generate),
    Load(Load),
    Unload(Unload),
    Analyze(Analyze),
    #[command(subcommand)]
    Get(Get),
    Secret,
    Run(Run),
}

// Commands
#[derive(Args, Debug)]
pub struct Run {
    /// Path of LUA script
    #[arg(short, long, required = true, default_value = None)]
    pub path: Option<String>,
}

#[derive(Args, Debug)]
pub struct Analyze {}

#[derive(Args, Debug)]
pub struct Generate {}

#[derive(Args, Debug)]
pub struct Load {
    /// Interface name.
    #[arg(short, long, default_value = "")]
    pub iface: String,
    /// XdpFlags to pass to XDP framework. Available options: generic, native, offloaded.
    #[arg(long, default_value = "generic")]
    pub xdp_flags: String,
}

#[derive(Args, Debug)]
pub struct Unload {
    /// Interface name.
    #[arg(short, long, default_value = "")]
    pub iface: String,
    /// XdpFlags to pass to XDP framework. Available options: generic, native, offloaded.
    #[arg(long, default_value = "generic")]
    pub xdp_flags: String,
    /// Program ID.
    #[arg(short, long, default_value = "")]
    pub pid: String,
}

#[derive(Subcommand, Debug)]
pub enum Get {
    /// Get default configuration
    DefaultConfig(ConfOutputType),
    /// Get example configuration
    ExampleConfig(ConfOutputType),
    /// Get starter configuration
    BaseConfig(ConfOutputType),
}

#[derive(Args, Debug)]
pub struct ConfOutputType {
    /// Format to raw JSON format
    #[arg(short, long, default_missing_value = "", num_args = 0)]
    pub json: Option<String>,
    /// Format to pretty JSON format
    #[arg(short, long, default_missing_value = "", num_args = 0)]
    pub pretty: Option<String>,
    /// Visualize configuration
    #[arg(short, long, default_missing_value = "", num_args = 0)]
    pub formatted: Option<String>,
}
