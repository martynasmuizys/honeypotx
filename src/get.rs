use crossterm::style::Stylize;

use crate::{
    cli::{ConfOutputType, LuaFunc},
    config::{Blacklist, Config, Data, Graylist, Init, Whitelist},
};

pub fn get_default_config(o: ConfOutputType) -> Result<(), anyhow::Error> {
    if o.formatted.is_some() {
        println!("{}", Config::default());
    } else if o.pretty.is_some() {
        println!("{}", serde_json::to_string_pretty(&Config::default())?);
    } else if o.json.is_some() {
        println!("{}", serde_json::to_string(&Config::default())?);
    } else {
        println!("{}", Config::default());
    }

    Ok(())
}

pub fn get_example_config(o: ConfOutputType) -> Result<(), anyhow::Error> {
    let config = Config {
        init: Some(Init {
            name: Some(String::from("Example")),
            hostname: Some(String::from("100.0.0.10")),
            port: Some(22),
            username: Some(String::from("bobthebuilder")),
            iface: Some(String::from("eth0")),
            prog_type: Some(String::from("ip")),
            xdp_action: Some(String::from("PASS")),
            whitelist: Some(Whitelist {
                enabled: Some(true),
                max: Some(32),
                action: Some(String::from("allow")),
            }),
            blacklist: Some(Blacklist {
                enabled: Some(true),
                max: Some(32),
                action: Some(String::from("deny")),
            }),
            graylist: Some(Graylist {
                enabled: Some(true),
                max: Some(32),
                action: Some(String::from("investigate")),
                frequency: Some(1000),
                fast_packet_count: Some(10),
            }),
        }),
        data: Some(Data {
            whitelist: Some(vec![String::from("192.168.1.103")]),
            blacklist: Some(vec![String::from("192.168.1.203")]),
            graylist: Some(Vec::new()),
        }),
    };

    if o.pretty.is_some() {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else if o.json.is_some() {
        println!("{}", serde_json::to_string(&config)?);
    } else if o.formatted.is_some() {
        println!("{}", &config);
    } else {
        println!("{}", serde_json::to_string_pretty(&config)?);
    }

    Ok(())
}

pub fn get_base_config(o: ConfOutputType) -> Result<(), anyhow::Error> {
    let config = Config {
        init: Some(Init {
            name: Some(String::from("MyFirstProgram")),
            hostname: None,
            port: None,
            username: None,
            iface: Some(String::from("lo")),
            prog_type: Some(String::from("ip")),
            xdp_action: Some(String::from("PASS")),
            whitelist: Some(Whitelist {
                enabled: Some(true),
                max: Some(32),
                action: Some(String::from("allow")),
            }),
            blacklist: Some(Blacklist {
                enabled: Some(true),
                max: Some(32),
                action: Some(String::from("deny")),
            }),
            graylist: None,
        }),
        data: Some(Data {
            whitelist: Some(vec![]),
            blacklist: Some(vec![]),
            graylist: None,
        }),
    };

    if o.pretty.is_some() {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else if o.json.is_some() {
        println!("{}", serde_json::to_string(&config)?);
    } else if o.formatted.is_some() {
        println!("{}", &config);
    } else {
        println!("{}", serde_json::to_string_pretty(&config)?);
    }

    Ok(())
}

pub fn get_lua_api() {
    println!(
        "{}(opts) - analyzes systems compatibility with eBPF",
        "analyze".bold().blue()
    );
    println!(
        "{}(opts) - generates eBPF program on provided config",
        "generate".bold().blue()
    );
    println!(
        "{}(opts) - loads eBPF program to kernel",
        "pload".bold().blue()
    );
    println!(
        "{}(opts) - unloads eBPF program from kernel",
        "punload".bold().blue()
    );
    println!(
        "{}(opts) - gets map data of loaded eBPF program",
        "get_map_data".bold().blue()
    );
}

pub fn get_lua_func_opts(o: LuaFunc) {
    match o {
        LuaFunc::Analyze => println!("opts = {{\n    config\n}}"),
        LuaFunc::Generate => println!("opts = {{\n    config\n}}"),
        LuaFunc::PLoad => println!("opts = {{\n    config,\n    iface,\n    xdp_flags\n}}"),
        LuaFunc::PUnload => {
            println!("opts = {{\n    config,\n    iface,\n    xdp_flags,\n    prog_id\n}}")
        }
        LuaFunc::Get_map_data => println!("opts = {{\n    config,\n    map_name\n}}"),
    }
}
