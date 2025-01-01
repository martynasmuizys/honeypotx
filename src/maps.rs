use std::{
    io::{self, Read, Write},
    net::TcpStream,
    process::Command,
    sync::Mutex,
};

use anyhow::anyhow;
use crossterm::style::Stylize;
use libbpf_rs::{MapCore, MapFlags, MapImpl, Object};
use serde_json::Value;
use ssh2::Session;

use crate::{config::Config, SSH_PASS};

pub fn get_map<'a>(object: &'a Object, name: &'a str) -> Option<MapImpl<'a>> {
    let mut maps = object.maps();

    maps.find(|m| m.name() == name)

}

pub fn load_map_data_local_temp(map: &MapImpl, data: &Vec<String>) -> Result<(), anyhow::Error> {
    if data.is_empty() {
        return Ok(());
    }

    for address in data {
        let key: Vec<u8> = address.split(".").map(|n| n.parse().unwrap_or(0)).collect();
        let mut value = key.clone();
        let mut empty_data: Vec<u8> = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        value.append(&mut empty_data);
        map.update(&key, &value, MapFlags::NO_EXIST)?;
    }

    Ok(())
}

pub fn load_map_data_local(map_id: u64, data: &Vec<String>) -> Result<(), anyhow::Error> {
    for address in data {
        let key: Vec<&str> = address.trim().split(".").collect();
        let mut value = key.clone();
        let mut empty_data: Vec<&str> = vec![
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        ];
        value.append(&mut empty_data);

        Command::new("sh")
            .args([
                "-c",
                format!(
                    "bpftool map update id {} key {} value {}",
                    map_id,
                    key.join(" "),
                    value.join(" ")
                )
                .as_str(),
            ])
            .output()?;
    }

    Ok(())
}

pub fn load_map_data_remote(
    map_id: u64,
    data: &Vec<String>,
    session: &Session,
    password: &str,
) -> Result<(), anyhow::Error> {
    for address in data {
        let key: Vec<&str> = address.trim().split(".").collect();
        let mut value = key.clone();
        let mut empty_data: Vec<&str> = vec![
            "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "0",
        ];
        value.append(&mut empty_data);

        let mut channel = session.channel_session().unwrap();
        channel.exec(
            format!(
                "echo {} | sudo -S bpftool map update id {} key {} value {}",
                password,
                map_id,
                key.join(" "),
                value.join(" ")
            )
            .as_str(),
        )?;

        channel.send_eof()?;
        channel.wait_eof()?;
        channel.close()?;
        channel.wait_close()?;
    }
    Ok(())
}

pub fn get_map_data(config: &Config, map_name: &str) -> Result<String, anyhow::Error> {
    let hostname = config.init.as_ref().unwrap().hostname.as_ref();
    let port = config.init.as_ref().unwrap().port.as_ref();

    if hostname.is_none()
        || *hostname.as_ref().unwrap() == "localhost"
        || *hostname.as_ref().unwrap() == "127.0.0.1"
    {
        let output = String::from_utf8(
            Command::new("bpftool")
                .arg("map")
                .arg("show")
                .arg("-j")
                .output()
                .unwrap()
                .stdout,
        )?;
        let maps: Value = serde_json::from_str(&output)?;

        if let Some(maps) = maps.as_array() {
            for m in maps {
                if map_name == m["name"] {
                    let output = String::from_utf8(
                        Command::new("bpftool")
                            .arg("map")
                            .arg("dump")
                            .arg("id")
                            .arg(m["id"].to_string())
                            .arg("-j")
                            .output()
                            .unwrap()
                            .stdout,
                    )?;
                    return Ok(output);
                }
            }
        } else {
            return Err(anyhow!("Map {} was not found", &map_name));
        }
    } else if hostname.is_some() {
        let tcp = TcpStream::connect(format!(
            "{}:{}",
            hostname.unwrap(),
            port.unwrap_or(&22)
        ))
        .unwrap();
        let mut session = Session::new().unwrap();
        session.set_tcp_stream(tcp);
        session.handshake().unwrap();

        let mut username: String = String::new();
        if config.init.as_ref().unwrap().username.is_none() {
            print!("Username: ");
            io::stdout().flush()?;
            io::stdin().read_line(&mut username)?;
        } else {
            username = config
                .init
                .as_ref()
                .unwrap()
                .username
                .as_ref()
                .unwrap()
                .to_string();
            println!("{}: Using username \"{}\"", "Load".red().bold(), &username);
        }

        let password: String;
        unsafe {
            let pass = (*SSH_PASS.get()).lock().unwrap();
            if !pass.is_empty() {
                password = (*pass).clone();
            } else {
                password = rpassword::prompt_password("Password: ")?;
            }
        }

        session.userauth_password(username.trim(), password.trim())?;

        unsafe {
            let pass = (*SSH_PASS.get()).lock().unwrap();
            if pass.is_empty() {
                let new = SSH_PASS.get().as_mut().unwrap();
                *new = Mutex::new(password.clone());
            }
        }

        session
            .userauth_password(username.trim(), password.trim())
            .unwrap();
        println!(
            "{}: Connected to {}\n",
            "Load".red().bold(),
            hostname.unwrap()
        );

        let mut output: String = String::new();
        let mut channel = session.channel_session()?;
        channel.exec(format!("echo {} | sudo -S bpftool map show -j", password).as_str())?;
        channel.read_to_string(&mut output)?;

        let maps: Value = serde_json::from_str(&output)?;

        if let Some(maps) = maps.as_array() {
            for m in maps {
                if map_name == m["name"] {
                    output.clear();
                    channel = session.channel_session()?;
                    channel.exec(
                        format!(
                            "echo {} | sudo -S bpftool map dump id {} -j",
                            password, m["id"]
                        )
                        .as_str(),
                    )?;
                    channel.read_to_string(&mut output)?;
                    return Ok(output);
                }
            }
        } else {
            return Err(anyhow!("Map {} was not found", &map_name));
        }
    }

    Ok(String::new())
}
