use clap::{arg, Args, Parser, Subcommand};

// Main command options
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Options {
    #[command(subcommand)]
    pub command: Commands,
    /// Config file name in TOML/JSON format.
    #[arg(short, long, global = true)]
    pub config: Option<String>,
}

// Subcommands
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Generates eBPF program on provided or default config
    Generate(Generate),
    /// Loads eBPF program on a network interface
    Load(Load),
    /// Unloads eBPF program
    Unload(Unload),
    /// Analyzes OS compatibility with eBPF
    Analyze(Analyze),
    /// Get some data
    #[command(subcommand)]
    Get(Get),
    /// SECRET!!! DO NOT RUN THIS!!! VERY DANGEROUS!!!
    Secret,
    /// Embed and run Lua script
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
pub struct Analyze {
    /// Skip confirmation of the configuration, package installation.
    #[arg(long, default_missing_value = "", num_args = 0)]
    pub noconfirm: Option<String>,
}

#[derive(Args, Debug)]
pub struct Generate {
    /// Skip confirmation of the configuration
    #[arg(long, default_missing_value = "", num_args = 0)]
    pub noconfirm: Option<String>,
}

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
    /// Get available Lua API
    LuaApi,
    #[command(subcommand, subcommand_help_heading = "Functions", subcommand_value_name = "FUNCTION")]
    LuaFuncOpts(LuaFunc)
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

#[derive(Subcommand, Debug)]
pub enum LuaFunc {
    Analyze,
    Generate,
    #[command(name = "pload")]
    PLoad,
    #[command(name = "punload")]
    PUnload,
    #[allow(non_camel_case_types)]
    #[command(name = "get_map_data")]
    Get_map_data,
}
