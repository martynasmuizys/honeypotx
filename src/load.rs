use std::{
    fs::{create_dir_all, File},
    io::{self, stdout, Write},
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
use tokio::signal;

use crate::{
    maps::{self, load_map_data_local, load_map_data_local_temp},
    objects, programs, Config, Load, WORKING_DIR,
};

#[derive(Debug, Deserialize, Serialize)]
struct Progs {
    ids: Vec<usize>,
    progs: Vec<Prog>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Prog {
    id: usize,
    data: Vec<Maps>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Maps {
    whitelist: Option<ProgData>,
    blacklist: Option<ProgData>,
    graylist: Option<ProgData>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProgData {
    key: Vec<String>,
    value: Vec<String>,
}

pub async fn load(options: &mut Load, config: Config) -> Result<(), anyhow::Error> {
    let hostname = config.init.as_ref().unwrap().hostname.as_ref();
    let path = "/tmp/generated.o";
    if hostname.is_none()
        || *hostname.as_ref().unwrap() == "localhost"
        || *hostname.as_ref().unwrap() == "127.0.0.1"
    {
        match sudo::check() {
            sudo::RunningAs::Root => println!("{}: Running as sudo ✔︎", "Load".red().bold()),
            sudo::RunningAs::User => {
                println!("{}: Requesting sudo privileges", "Load".red().bold());
                let _ = sudo::with_env(&["HOME"]);
            }
            sudo::RunningAs::Suid => todo!(),
        }

        let config_iface = config.init.as_ref().unwrap().iface.as_ref();

        if config_iface.is_some() && *config_iface.unwrap() != options.iface {
            let mut action = String::new();
            print!(
            "{}: Network interface differs from config. Are you sure you want to proceed? [Y/n] ",
            "Load".red().bold()
        );
            io::stdout().flush()?;
            io::stdin().read_line(&mut action)?;

            let action = action.trim().to_lowercase();

            if action != "y" && action != "yes" && action != "" {
                return Err(anyhow!("Cancelled"));
            }

            //options.iface = config_iface.unwrap().to_string();
        }

        let mut action = String::new();

        print!(
            "{}: Load eBPF program temporary or as a seperate process? (Default: 1)\n - 1 - Temporary (for debugging)\n - 2 - Seperate process\n",
            "Load".red().bold()
        );
        print!("{} -> ", "Load".red().bold());
        io::stdout().flush()?;
        io::stdin().read_line(&mut action)?;

        let action = action.trim().to_lowercase();

        if action == "1" || action == "" {
            load_local_temp(options, config, &path).await?;
            return Ok(());
        } else if action == "2" {
            load_local(options, config, &path)?;
            return Ok(());
        }

        return Err(anyhow!("Cancelled"));
    }
    Ok(())
}

async fn load_local_temp(
    options: &mut Load,
    config: Config,
    path: &str,
) -> Result<(), anyhow::Error> {
    dbg!(&config);
    //// increase rlimit? sudo cargo automatically does this?.
    ////rlimit::increase_nofile_limit(rlimit::INFINITY)?;
    //clang -O2 -g -target bpf -c src/bpf/xdp.c -o src/bpf/xdp.o
    let mut object_builder = ObjectBuilder::default();
    let object = objects::get_object(&mut object_builder, Path::new(&path))?;

    let whitelist = maps::get_map(&object, "whitelist");
    let blacklist = maps::get_map(&object, "blacklist");
    let graylist = maps::get_map(&object, "graylist");
    let programs = programs::get_programs(&object).with_context(|| format!("Program not found"))?;
    dbg!(&programs);

    let name = config.init.as_ref().unwrap().name.as_ref().unwrap();
    dbg!(&name);
    let program = programs
        .get(name)
        .with_context(|| format!("Program does not exist"))?;
    let xdp = programs::attach_xdp(&program, &options)?;

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

    //let key = &[127, 0, 0, 1];
    //let value = &[
    //    127, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
    //];
    //map.update(key, value, MapFlags::NO_EXIST)?;

    if let Some(wl) = &whitelist {
        load_map_data_local_temp(wl, &config.whitelist.clone().unwrap_or(Vec::new()))?
    }
    if let Some(bl) = &blacklist {
        load_map_data_local_temp(bl, &config.blacklist.unwrap_or(Vec::new()))?
    }
    if let Some(gl) = &graylist {
        load_map_data_local_temp(gl, &config.graylist.unwrap_or(Vec::new()))?
    }

    while !(*should_terminate.lock().unwrap()) {
        // to_be_bytes converts to [127, 0, 0, 1]
        if let Some(bl) = &blacklist {
            for k in bl.keys() {
                let mut ip: String = String::new();
                let _rx_packets: u64 = 0;
                let _last_access_time: u64 = 0;
                let data = bl.lookup(&k, MapFlags::ANY)?.unwrap();
                for (i, b) in data[0..4].into_iter().enumerate() {
                    if i > 0 {
                        ip.push_str(format!(".{}", &b.to_string()).as_str());
                        continue;
                    }
                    ip.push_str(format!("{}", &b.to_string()).as_str());
                }

                if !bl_ip_arr.contains(&ip) {
                    bl_ip_arr.push(ip);
                }
            }
        }

        let last_blaclisted_ip: &str = if bl_ip_arr.len() != 0 {
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
    programs::detach_xdp(&xdp, &options)?;
    Ok(())
}

fn load_local(options: &mut Load, config: Config, path: &str) -> Result<(), anyhow::Error> {
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
            if "whitelist" == m["name"] && config.whitelist.as_ref().is_some() {
                let wid = m["id"]
                    .as_u64()
                    .with_context(|| format!("Map 'whitelist' was not created"))?;
                load_map_data_local(wid, config.whitelist.as_ref().unwrap())?;
                data.push(Maps {
                    whitelist: Some(ProgData {
                        key: config.whitelist.clone().unwrap(),
                        value: Vec::new(),
                    }),
                    blacklist: None,
                    graylist: None,
                });
                continue;
            }
            if "blacklist" == m["name"] && config.blacklist.as_ref().is_some() {
                let bid = m["id"]
                    .as_u64()
                    .with_context(|| format!("Map 'blacklist' was not created"))?;
                load_map_data_local(bid, config.blacklist.as_ref().unwrap())?;
                data.push(Maps {
                    whitelist: None,
                    blacklist: Some(ProgData {
                        key: config.blacklist.clone().unwrap(),
                        value: Vec::new(),
                    }),
                    graylist: None,
                });
                continue;
            }
            if "graylist" == m["name"] && config.graylist.as_ref().is_some() {
                let gid = m["id"]
                    .as_u64()
                    .with_context(|| format!("Map 'graylist' was not created"))?;
                load_map_data_local(gid, config.graylist.as_ref().unwrap())?;
                data.push(Maps {
                    whitelist: None,
                    blacklist: None,
                    graylist: Some(ProgData {
                        key: config.graylist.clone().unwrap(),
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

    let p = format!("{}/data",
                WORKING_DIR
                    .to_str()
                    .with_context(|| format!("Failed to parse HOME directory"))?,
    );
    let path = Path::new(&p);
    create_dir_all(&path)?;

    let mut loaded_progs;
    let progs: Progs;
    let p = format!("{}/data/progs.json",
                WORKING_DIR
                    .to_str()
                    .with_context(|| format!("Failed to parse HOME directory"))?,
    );
    let path = Path::new(&p);

    loaded_progs = File::create(&path)?;
    progs = Progs {
        ids: vec![prog_id as usize],
        progs: vec![Prog {
            id: prog_id as usize,
            data: data,
        }],
    };
    let json_data = serde_json::to_string(&progs)?;
    loaded_progs.write_all(json_data.as_bytes())?;

    Ok(())
}
