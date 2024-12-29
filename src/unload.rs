use std::io;
use std::net::TcpStream;
use std::sync::Mutex;
use std::{fs::File, io::Write, path::Path, process::Command};

use anyhow::{anyhow, Context};
use crossterm::style::Stylize;
use ssh2::Session;

use crate::cli::Unload;
use crate::config::DEFAULT_NET_IFACE;
use crate::{Config, SSH_PASS, WORKING_DIR};

pub fn unload(options: &mut Unload, config: Config) -> Result<(), anyhow::Error> {
    let hostname = config.init.as_ref().unwrap().hostname.as_ref();
    let port = config.init.as_ref().unwrap().port.as_ref();

    let config_iface = config.init.as_ref().unwrap().iface.as_ref();

    if config_iface.is_some()
        && !options.iface.is_empty()
        && *config_iface.unwrap() != options.iface
    {
        let mut action = String::new();
        print!(
            "{}: Network interface differs from config. Are you sure you want to proceed? [Y/n] ",
            "Unload".red().bold()
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
            "Unload".red().bold(),
            config_iface.unwrap().as_str()
        );
        options.iface = config_iface.unwrap().to_string();
    } else if config_iface.is_none() && options.iface.is_empty() {
        println!(
            "{}: No network interface provided. Using default: eth0...",
            "Unload".red().bold()
        );
        options.iface = String::from(DEFAULT_NET_IFACE);
    }

    if hostname.is_none()
        || *hostname.as_ref().unwrap() == "localhost"
        || *hostname.as_ref().unwrap() == "127.0.0.1"
    {
        match sudo::check() {
            sudo::RunningAs::Root => (),
            sudo::RunningAs::User => {
                println!("{}: Requesting sudo privileges", "Unload".red().bold());
                let _ = sudo::with_env(&["HOME"]);
            }
            sudo::RunningAs::Suid => todo!(),
        }

        unload_local(options, config)?;
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
            println!("{}: Using username \"{}\"", "Unload".red().bold(), &username);
        }

        let password: String;
        unsafe {
            let pass = (*SSH_PASS.get()).lock().unwrap();
            if pass.is_empty() {
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
            "Unload".red().bold(),
            hostname.unwrap()
        );

        unload_remote(options, config, &mut session, &password)?;
    }
    Ok(())
}

fn unload_local(options: &mut Unload, config: Config) -> Result<(), anyhow::Error> {
    let name = config.init.as_ref().unwrap().name.as_ref().unwrap();
    let xdp_flag = match options.xdp_flags.as_ref() {
        "generic" => "xdpgeneric",
        "native" => "xdpdrv",
        "offloaded" => "xdpoffload",
        _ => "xdpgeneric",
    };

    Command::new("bpftool")
        .arg("net")
        .arg("detach")
        .arg(xdp_flag)
        .arg("dev")
        .arg(&options.iface)
        .output()?;

    Command::new("rm")
        .arg(format!("/sys/fs/bpf/{}", &name).as_str())
        .output()?;

    let p = format!(
        "{}/data",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory")?,
    );
    let path = Path::new(&p);

    if !path.exists() {
        return Err(anyhow!("No programs loaded"));
    }

    let mut loaded_progs;
    let p = format!(
        "{}/data/progs.json",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory")?,
    );
    let path = Path::new(&p);

    loaded_progs = File::create(path)?;
    let json_data = serde_json::to_string("{}")?;
    loaded_progs.write_all(json_data.as_bytes())?;

    Ok(())
}

fn unload_remote(
    options: &mut Unload,
    config: Config,
    session: &mut Session,
    password: &str,
) -> Result<(), anyhow::Error> {
    let name = config.init.as_ref().unwrap().name.as_ref().unwrap();
    let xdp_flag = match options.xdp_flags.as_ref() {
        "generic" => "xdpgeneric",
        "native" => "xdpdrv",
        "offloaded" => "xdpoffload",
        _ => "xdpgeneric",
    };

    println!("{}: Detaching program...", "Unload".red().bold());
    let mut channel = session.channel_session()?;
    channel.exec(
        format!(
            "echo {} | sudo -S bpftool net detach {} dev {}",
            password, xdp_flag, options.iface
        )
        .as_str(),
    )?;

    println!("{}: Unloading the program...", "Unload".red().bold());
    channel = session.channel_session()?;
    channel.exec(
        format!(
            "echo {} | sudo -S rm /sys/fs/bpf/{}",
            password, name
        )
        .as_str(),
    )?;

    Ok(())
}
