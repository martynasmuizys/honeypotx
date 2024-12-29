use serde_json::json;

use crate::{cli::ConfOutputType, config::Config};

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
    let json_example = json!({
        "init": {
            "name": "Example",
            "hostname": "100.0.0.10",
            "port": 22,
            "username": "bobthebuilder",
            "iface": "eth0",
            "prog_type": "ip",
            "whitelist": {
                "enabled": false,
                "max": 32,
                "action": "allow"
            },
            "blacklist": {
                "enabled": false,
                "max": 32,
                "action": "deny"
            },
            "graylist": {
                "enabled": false,
                "max": 32,
                "action": "investigate",
                "frequency": 1000,
                "fast_packet_count": 10
            }
        },
        "data": {
            "whitelist": ["192.168.1.103"],
            "blacklist": ["192.168.1.203"],
            "graylist": []
        }
    }
    );
    if o.pretty.is_some() {
        println!("{}", Config::default());
    } else if o.json.is_some() {
        println!("{}", serde_json::to_string(&json_example)?);
    } else if o.formatted.is_some() {
        println!(
            "{}",
            serde_json::from_str::<Config>(&json_example.to_string())?
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&json_example)?);
    }

    Ok(())
}

pub fn get_base_config(o: ConfOutputType) -> Result<(), anyhow::Error> {
    let json_base = json!({
        "init": {
            "name": "MyFirstProgram",
            "iface": "lo",
            "prog_type": "ip",
            "whitelist": {
                "enabled": false,
                "max": 32,
                "action": "allow"
            },
            "blacklist": {
                "enabled": true,
                "max": 32,
                "action": "deny"
            },
        },
        "data": {
            "whitelist": [],
            "blacklist": [],
        }
    }
    );
    if o.pretty.is_some() {
        println!("{}", Config::default());
    } else if o.json.is_some() {
        println!("{}", serde_json::to_string(&json_base)?);
    } else if o.formatted.is_some() {
        println!(
            "{}",
            serde_json::from_str::<Config>(&json_base.to_string())?
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&json_base)?);
    }

    Ok(())
}
