use std::{
    fs::{self, create_dir_all, File},
    io::{self, stdout, Read, Write},
    net::TcpStream,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{anyhow, Context};
use crossterm::{
    style::Stylize,
    terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use libbpf_rs::{MapCore, MapFlags, ObjectBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssh2::Session;
use tokio::signal;

use crate::{
    cli::Load,
    config::{DEFAULT_NAME, DEFAULT_NET_IFACE},
    maps::{self, load_map_data_local, load_map_data_local_temp, load_map_data_remote},
    objects, programs, Config, SSH_PASS, WORKING_DIR,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct Progs {
    ids: Vec<usize>,
    progs: Vec<Prog>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Prog {
    id: usize,
    data: Vec<Maps>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Maps {
    whitelist: Option<ProgData>,
    blacklist: Option<ProgData>,
    graylist: Option<ProgData>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProgData {
    key: Vec<String>,
    value: Vec<String>,
}

pub async fn load(options: &mut Load, config: Config) -> Result<usize, anyhow::Error> {
    let hostname = config.init.as_ref().unwrap().hostname.as_ref();
    let port = config.init.as_ref().unwrap().port.as_ref();
    let path = format!(
        "{}/out/generated.o",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory".to_string())?
    );

    if hostname.is_none()
        || *hostname.as_ref().unwrap() == "localhost"
        || *hostname.as_ref().unwrap() == "127.0.0.1"
    {
        match sudo::check() {
            sudo::RunningAs::Root => (),
            sudo::RunningAs::User => {
                println!("{}: Requesting sudo privileges", "Load".red().bold());
                let _ = sudo::with_env(&["HOME"]);
            }
            sudo::RunningAs::Suid => todo!(),
        }
    }

    let config_iface = config.init.as_ref().unwrap().iface.as_ref();

    if config_iface.is_some()
        && !options.iface.is_empty()
        && *config_iface.unwrap() != options.iface
    {
        let mut action = String::new();
        print!(
            "{}: Network interface differs from config. Are you sure you want to proceed? [Y/n] ",
            "Load".red().bold()
        );
        io::stdout().flush()?;
        io::stdin().read_line(&mut action)?;

        let action = action.trim().to_lowercase();

        if action != "y" && action != "yes" && !action.is_empty() {
            return Err(anyhow!("Cancelled"));
        }
    } else if config_iface.is_some() && options.iface.is_empty() {
        println!(
            "{}: Using network interface from config: {}...",
            "Load".red().bold(),
            config_iface.unwrap().as_str()
        );
        options.iface = config_iface.unwrap().to_string();
    } else if config_iface.is_none() && options.iface.is_empty() {
        println!(
            "{}: No network interface provided. Using default: eth0...",
            "Load".red().bold()
        );
        options.iface = String::from(DEFAULT_NET_IFACE);
    }

    if hostname.is_none()
        || *hostname.as_ref().unwrap() == "localhost"
        || *hostname.as_ref().unwrap() == "127.0.0.1"
    {
        let mut action = String::new();

        print!(
            "{}: Load eBPF program temporary or as a seperate process? (Default: 1)\n - 1 - Temporary (for debugging)\n - 2 - Seperate process\n",
            "Load".red().bold()
        );
        print!("{} -> ", "Load".red().bold());
        io::stdout().flush()?;
        io::stdin().read_line(&mut action)?;

        let action = action.trim().to_lowercase();

        if action == "1" || action.is_empty() {
            load_local_temp(options, config, &path).await?;
            return Ok(0);
        } else if action == "2" {
            return load_local(options, config, &path);
        }

        return Err(anyhow!("Cancelled"));
    } else if hostname.is_some() {
        let tcp =
            TcpStream::connect(format!("{}:{}", hostname.unwrap(), port.unwrap_or(&22))).unwrap();
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

        println!(
            "{}: Connected to {}\n",
            "Load".red().bold(),
            hostname.unwrap()
        );
        send_file(&config, &path, &session, &password)?;
        return load_remote(options, config, &session, &password);
    }
    Ok(0)
}

async fn load_local_temp(
    options: &mut Load,
    config: Config,
    path: &str,
) -> Result<(), anyhow::Error> {
    let mut object_builder = ObjectBuilder::default();
    let object = objects::get_object(&mut object_builder, Path::new(&path))?;

    let whitelist = maps::get_map(&object, "whitelist");
    let blacklist = maps::get_map(&object, "blacklist");
    let graylist = maps::get_map(&object, "graylist");
    let programs =
        programs::get_programs(&object).with_context(|| "Program not found".to_string())?;

    let name = config.init.as_ref().unwrap().name.as_ref();
    let program = programs
        .get(name.unwrap_or(&DEFAULT_NAME.to_string()))
        .with_context(|| "Program does not exist".to_string())?;
    let xdp = programs::attach_xdp(program, options)?;

    let should_terminate = Arc::new(Mutex::new(false));
    let signal_handle = should_terminate.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        let mut signal_handle = signal_handle.lock().unwrap();
        *signal_handle = true;
        println!("\rTerminating...");
    });

    let mut bl_ip_arr: Vec<String> = Vec::new();
    let mut bl_last_arr_len: usize = 0;
    stdout().execute(EnterAlternateScreen)?;

    if let Some(wl) = &whitelist {
        load_map_data_local_temp(
            wl,
            &config
                .data
                .as_ref()
                .unwrap()
                .whitelist
                .clone()
                .unwrap_or_default(),
        )?
    }
    if let Some(bl) = &blacklist {
        load_map_data_local_temp(
            bl,
            &config
                .data
                .as_ref()
                .unwrap()
                .blacklist
                .clone()
                .unwrap_or_default(),
        )?
    }
    if let Some(gl) = &graylist {
        load_map_data_local_temp(
            gl,
            &config
                .data
                .as_ref()
                .unwrap()
                .graylist
                .clone()
                .unwrap_or_default(),
        )?
    }

    while !(*should_terminate.lock().unwrap()) {
        // to_be_bytes converts to [127, 0, 0, 1]
        if let Some(bl) = &blacklist {
            for k in bl.keys() {
                let mut ip: String = String::new();
                let _rx_packets: u64 = 0;
                let _last_access_time: u64 = 0;
                let data = bl.lookup(&k, MapFlags::ANY)?.unwrap();
                for (i, b) in data[0..4].iter().enumerate() {
                    if i > 0 {
                        ip.push_str(format!(".{}", &b.to_string()).as_str());
                        continue;
                    }
                    ip.push_str((b.to_string()).to_string().as_str());
                }

                if !bl_ip_arr.contains(&ip) {
                    bl_ip_arr.push(ip);
                }
            }
        }

        let last_blaclisted_ip: &str = if !bl_ip_arr.is_empty() {
            bl_ip_arr.last().unwrap()
        } else {
            "No blacklisted IPs."
        };

        if bl_last_arr_len != bl_ip_arr.len() {
            stdout().execute(Clear(ClearType::All))?;
            println!(
                "├────────────── {} ───────────────┤",
                "WHITELIST".to_string().bold().white()
            );
            println!("├───────────────────────┬────────────────┤");
            println!(
                " Total whitelisted IPs  │ {}",
                &config
                    .data
                    .as_ref()
                    .unwrap()
                    .whitelist
                    .as_ref()
                    .unwrap_or(&Vec::new())
                    .len()
                    .to_string()
                    .bold(),
            );
            println!("└───────────────────────┴────────────────┘\n");
            println!(
                "├────────────── {} ───────────────┤",
                "BLACKLIST".to_string().bold().black()
            );
            println!("├───────────────────────┬────────────────┤");
            println!(
                " Total blacklisted IPs  │ {}",
                bl_ip_arr.len().to_string().bold(),
            );
            println!("├───────────────────────┼────────────────┤");
            println!(" Last banned IP         │ {} ", last_blaclisted_ip.bold());
            println!("└───────────────────────┴────────────────┘");
            bl_last_arr_len = bl_ip_arr.len();
        }
        thread::sleep(Duration::from_secs(5));
    }

    stdout().execute(LeaveAlternateScreen)?;
    programs::detach_xdp(&xdp, options)?;
    Ok(())
}

fn load_local(options: &mut Load, config: Config, path: &str) -> Result<usize, anyhow::Error> {
    let name = config.init.as_ref().unwrap().name.as_ref().unwrap();
    let xdp_flag = match options.xdp_flags.as_ref() {
        "generic" => "xdpgeneric",
        "native" => "xdpdrv",
        "offloaded" => "xdpoffload",
        _ => "xdpgeneric",
    };
    let mut prog_id: u64 = 0;

    Command::new("bpftool")
        .arg("prog")
        .arg("load")
        .arg(path)
        .arg(format!("/sys/fs/bpf/{}", name))
        .output()?;

    let output = String::from_utf8(
        Command::new("bpftool")
            .arg("prog")
            .arg("show")
            .arg("-j")
            .output()
            .unwrap()
            .stdout,
    )?;

    let progs: Value = serde_json::from_str(&output)?;
    if let Some(progs) = progs.as_array() {
        for p in progs {
            if *name == p["name"] {
                prog_id = p["id"]
                    .as_u64()
                    .with_context(|| format!("Program {} was not loaded", &name))?;
                break;
            }
        }
    } else {
        return Err(anyhow!("Program {} was not loaded", &name));
    }

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

    // Load map data if needed
    let mut data: Vec<Maps> = vec![];
    if let Some(maps) = maps.as_array() {
        for m in maps {
            if "whitelist" == m["name"]
                && config.data.as_ref().unwrap().whitelist.as_ref().is_some()
            {
                let wid = m["id"]
                    .as_u64()
                    .with_context(|| "Map 'whitelist' was not created".to_string())?;
                load_map_data_local(
                    wid,
                    config.data.as_ref().unwrap().whitelist.as_ref().unwrap(),
                )?;
                data.push(Maps {
                    whitelist: Some(ProgData {
                        key: config.data.as_ref().unwrap().whitelist.clone().unwrap(),
                        value: Vec::new(),
                    }),
                    blacklist: None,
                    graylist: None,
                });
                continue;
            }
            if "blacklist" == m["name"]
                && config.data.as_ref().unwrap().blacklist.as_ref().is_some()
            {
                let bid = m["id"]
                    .as_u64()
                    .with_context(|| "Map 'blacklist' was not created".to_string())?;
                load_map_data_local(
                    bid,
                    config.data.as_ref().unwrap().blacklist.as_ref().unwrap(),
                )?;
                data.push(Maps {
                    whitelist: None,
                    blacklist: Some(ProgData {
                        key: config.data.as_ref().unwrap().blacklist.clone().unwrap(),
                        value: Vec::new(),
                    }),
                    graylist: None,
                });
                continue;
            }
            if "graylist" == m["name"] && config.data.as_ref().unwrap().graylist.as_ref().is_some()
            {
                let gid = m["id"]
                    .as_u64()
                    .with_context(|| "Map 'graylist' was not created".to_string())?;
                load_map_data_local(
                    gid,
                    config.data.as_ref().unwrap().graylist.as_ref().unwrap(),
                )?;
                data.push(Maps {
                    whitelist: None,
                    blacklist: None,
                    graylist: Some(ProgData {
                        key: config.data.as_ref().unwrap().graylist.clone().unwrap(),
                        value: Vec::new(),
                    }),
                });
                continue;
            }
        }
    } else {
        return Err(anyhow!("Program {} was not loaded", &name));
    }

    Command::new("bpftool")
        .arg("net")
        .arg("attach")
        .arg(xdp_flag)
        .arg("id")
        .arg(prog_id.to_string())
        .arg("dev")
        .arg(&options.iface)
        .output()?;

    let p = format!(
        "{}/data",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory".to_string())?,
    );
    let path = Path::new(&p);

    if !path.exists() {
        create_dir_all(path)?;
    }

    let mut loaded_progs;

    let p = format!(
        "{}/data/progs.json",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory".to_string())?,
    );
    let path = Path::new(&p);

    loaded_progs = File::create(path)?;
    let progs: Progs = Progs {
        ids: vec![prog_id as usize],
        progs: vec![Prog {
            id: prog_id as usize,
            data,
        }],
    };
    let json_data = serde_json::to_string(&progs)?;
    loaded_progs.write_all(json_data.as_bytes())?;

    Ok(prog_id as usize)
}

fn send_file(
    config: &Config,
    path: &str,
    session: &Session,
    password: &str,
) -> Result<(), anyhow::Error> {
    let name = config.init.as_ref().unwrap().name.as_ref().unwrap();
    let size = File::open(path)?.metadata()?.size();
    let file_contents = fs::read(path)?;

    println!("{}: Sending compiled eBPF program...", "Load".red().bold());
    let mut channel = session
        .scp_send(Path::new(&path), 0o644, size, None)
        .unwrap();
    channel.write_all(&file_contents)?;
    channel.send_eof()?;
    channel.wait_eof()?;
    channel.close()?;
    channel.wait_close()?;

    println!("{}: Loading eBPF program...", "Load".red().bold());
    let mut channel = session.channel_session().unwrap();
    channel.exec(
        format!(
            "echo {} | sudo -S bpftool prog load {} /sys/fs/bpf/{}",
            password, path, name
        )
        .as_str(),
    )?;
    Ok(())
}
fn load_remote(
    options: &mut Load,
    config: Config,
    session: &Session,
    password: &str,
) -> Result<usize, anyhow::Error> {
    let mut prog_id: u64 = 0;
    let name = config.init.as_ref().unwrap().name.as_ref().unwrap();
    let xdp_flag = match options.xdp_flags.as_ref() {
        "generic" => "xdpgeneric",
        "native" => "xdpdrv",
        "offloaded" => "xdpoffload",
        _ => "xdpgeneric",
    };

    let mut output = String::new();
    let mut channel = session.channel_session()?;
    channel.exec(format!("echo {} | sudo -S bpftool prog show -j", password).as_str())?;
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;

    let progs: Value = serde_json::from_str(&output)?;
    if let Some(progs) = progs.as_array() {
        for p in progs {
            if *name == p["name"] {
                prog_id = p["id"]
                    .as_u64()
                    .with_context(|| format!("Program {} was not loaded", &name))?;
                break;
            }
        }
    } else {
        return Err(anyhow!("Program {} was not loaded", &name));
    }

    output.clear();

    channel = session.channel_session()?;
    channel.exec(format!("echo {} | sudo -S bpftool map show -j", password).as_str())?;
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;
    let maps: Value = serde_json::from_str(&output)?;

    println!("{}: Loading map data...", "Load".red().bold());
    // Load map data if needed
    let mut data: Vec<Maps> = vec![];
    if let Some(maps) = maps.as_array() {
        for m in maps {
            if "whitelist" == m["name"]
                && config.data.as_ref().unwrap().whitelist.as_ref().is_some()
            {
                let wid = m["id"]
                    .as_u64()
                    .with_context(|| "Map 'whitelist' was not created".to_string())?;
                load_map_data_remote(
                    wid,
                    config.data.as_ref().unwrap().whitelist.as_ref().unwrap(),
                    session,
                    password,
                )?;
                data.push(Maps {
                    whitelist: Some(ProgData {
                        key: config.data.as_ref().unwrap().whitelist.clone().unwrap(),
                        value: Vec::new(),
                    }),
                    blacklist: None,
                    graylist: None,
                });
                continue;
            }
            if "blacklist" == m["name"]
                && config.data.as_ref().unwrap().blacklist.as_ref().is_some()
            {
                let bid = m["id"]
                    .as_u64()
                    .with_context(|| "Map 'blacklist' was not created".to_string())?;
                load_map_data_remote(
                    bid,
                    config.data.as_ref().unwrap().blacklist.as_ref().unwrap(),
                    session,
                    password,
                )?;
                data.push(Maps {
                    whitelist: None,
                    blacklist: Some(ProgData {
                        key: config.data.as_ref().unwrap().blacklist.clone().unwrap(),
                        value: Vec::new(),
                    }),
                    graylist: None,
                });
                continue;
            }
            if "graylist" == m["name"] && config.data.as_ref().unwrap().graylist.as_ref().is_some()
            {
                let gid = m["id"]
                    .as_u64()
                    .with_context(|| "Map 'graylist' was not created".to_string())?;
                load_map_data_remote(
                    gid,
                    config.data.as_ref().unwrap().graylist.as_ref().unwrap(),
                    session,
                    password,
                )?;
                data.push(Maps {
                    whitelist: None,
                    blacklist: None,
                    graylist: Some(ProgData {
                        key: config.data.as_ref().unwrap().graylist.clone().unwrap(),
                        value: Vec::new(),
                    }),
                });
                continue;
            }
        }
    } else {
        return Err(anyhow!("Program {} was not loaded", &name));
    }

    channel = session.channel_session().unwrap();
    channel.exec(
        format!(
            "echo {} | sudo -S bpftool net attach {} id {} dev {}",
            password, xdp_flag, prog_id, &options.iface
        )
        .as_str(),
    )?;
    channel.read_to_string(&mut output).unwrap();
    channel.wait_close()?;

    let p = format!(
        "{}/data",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory".to_string())?,
    );
    let path = Path::new(&p);

    if !path.exists() {
        create_dir_all(path)?;
    }

    let mut loaded_progs;

    let p = format!(
        "{}/data/progs.json",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory".to_string())?,
    );
    let path = Path::new(&p);

    loaded_progs = File::create(path)?;
    let progs: Progs = Progs {
        ids: vec![prog_id as usize],
        progs: vec![Prog {
            id: prog_id as usize,
            data,
        }],
    };
    let json_data = serde_json::to_string(&progs)?;
    loaded_progs.write_all(json_data.as_bytes())?;

    Ok(prog_id as usize)
}
