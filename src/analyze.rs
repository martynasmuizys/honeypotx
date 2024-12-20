use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::Command;

use anyhow::anyhow;
use crossterm::style::Stylize;
use ssh2::Session;

use crate::config::Config;
use crate::Analyze;

static MIN_KERNEL_VERSION: &str = "5.16.0";
static UBUNTU_PACKAGES: [&str; 4] = [
    "linux-tools-common",
    "linux-tools-generic",
    "linux-cloud-tools-generic",
    "ripgrep",
];
static ARCH_PACKAGES: [&str; 4] = ["bpf", "base", "base-devel", "ripgrep"];

pub fn analyze(_options: Analyze, config: Config) -> Result<(), anyhow::Error> {
    println!("{}\n", "- CONFIG -".on_blue().black());
    let mut action = String::new();

    println!("{}", config);

    print!(
        "{}: Using config above. Proceed? [Y/n] ",
        "Load".blue().bold()
    );
    io::stdout().flush()?;
    io::stdin().read_line(&mut action)?;

    let action = action.trim().to_lowercase();

    if action != "y" && action != "yes" && action != "" {
        println!("here");
        return Err(anyhow!("Cancelled"));
    }

    let hostname = config.init.as_ref().unwrap().hostname.as_ref();
    let port = config.init.as_ref().unwrap().port.as_ref();

    if hostname.is_none()
        || *hostname.as_ref().unwrap() == "localhost"
        || *hostname.as_ref().unwrap() == "127.0.0.1"
    {
        let mut output =
            String::from_utf8(Command::new("uname").arg("-r").output().unwrap().stdout)?;
        println!("{}", "- Kernel Version Check -".on_blue().black());
        println!(
            "{}: Kernel version: {}",
            "Analyze".blue().bold(),
            &output.trim()
        );
        check_kernel_version(&output)?;

        println!("{}", "- Required Packages Check -".on_blue().black());
        output = String::from_utf8(Command::new("uname").arg("-n").output().unwrap().stdout)?;
        check_packages(&output.trim())?;

        println!("{}", "- Kernel Flags Check -".on_blue().black());
        output = String::from_utf8(
            Command::new("sh")
                .args(&["-c", "sudo bpftool feature | rg -w 'CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_BPF_JIT|CONFIG_BPF_EVENTS'"])
                .output()
                .unwrap()
                .stdout,
        )?;
        check_bpf_enabled(output.trim().split("\n").collect())?;

        println!("{}", "- Network Interface Check -".on_blue().black());
        output = String::from_utf8(
            Command::new("sh")
                .args(&["-c", "ip -o link show | awk -F': ' '{{print $2}}'"])
                .output()
                .unwrap()
                .stdout,
        )?;
        check_net_iface(
            config.init.as_ref().unwrap().iface.as_ref().unwrap(),
            output.split("\n").collect(),
        )?;

        return Ok(());
    }

    if hostname.is_some() {
        let tcp = TcpStream::connect(format!(
            "{}:{}",
            hostname.unwrap(),
            port.unwrap_or(&22).to_string()
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
            println!(
                "{}: Using username \"{}\"",
                "Analyze".blue().bold(),
                &username
            );
        }

        let password = rpassword::prompt_password("Password: ").unwrap();
        session
            .userauth_password(&username.trim(), &password.trim())
            .unwrap();
        println!(
            "{}: Connected to {}\n",
            "Analyze".blue().bold(),
            hostname.unwrap()
        );

        println!("{}", "- Kernel Version Check -".on_blue().black());
        check_kernel_version_remote(&mut session)?;

        println!("{}", "- Required Packages Check -".on_blue().black());
        check_packages_remote(&mut session, &password)?;

        println!("{}", "- Kernel Flags Check -".on_blue().black());
        check_bpf_enabled_remote(&mut session, &password)?;

        println!("{}", "- Network Interface Check -".on_blue().black());
        check_net_iface_remote(
            &mut session,
            config.init.as_ref().unwrap().iface.as_ref().unwrap(),
        )?;
    }

    Ok(())
}

fn check_kernel_version(version: &str) -> Result<(), anyhow::Error> {
    let version: Vec<&str> = version.splitn(2, "-").collect();
    let version: Vec<&str> = version[0].split(".").collect();

    let min_version: Vec<&str> = MIN_KERNEL_VERSION.split(".").collect();

    for i in 0..3 {
        let ver_num: u32 = version[i].parse().unwrap();
        let min_ver_num: u32 = min_version[i].parse().unwrap();
        let incompatible;

        match i {
            0 => {
                if ver_num > min_ver_num {
                    break;
                }
                if ver_num == min_ver_num {
                    continue;
                }
                incompatible = true;
            }
            1 => {
                if ver_num > min_ver_num {
                    break;
                }
                if ver_num == min_ver_num {
                    continue;
                }
                incompatible = true;
            }
            2 => {
                if ver_num > min_ver_num {
                    break;
                }
                if ver_num == min_ver_num {
                    continue;
                }
                incompatible = true;
            }
            _ => unreachable!("Should not be reached!"),
        }
        if incompatible {
            return Err(anyhow!(
                "Incompatible kernel version!\nMinimal compatible version: {}",
                MIN_KERNEL_VERSION
            ));
        }
    }
    println!("{}: Kernel version compatible ✔︎\n", "Analyze".blue().bold());
    Ok(())
}

fn check_kernel_version_remote(session: &mut Session) -> Result<(), anyhow::Error> {
    let mut channel = session.channel_session().unwrap();
    channel.exec("uname -r").unwrap();
    let mut output = String::new();
    channel.read_to_string(&mut output).unwrap();

    println!(
        "{}: Kernel version: {}",
        "Analyze".blue().bold(),
        &output.trim()
    );
    check_kernel_version(&output)?;
    channel.wait_close()?;
    Ok(())
}

fn check_packages(nodename: &str) -> Result<(), anyhow::Error> {
    let mut missing_pgks: Vec<&str> = Vec::new();
    let mut output = String::new();

    match nodename {
        "ubuntu" => {
            for pkg in UBUNTU_PACKAGES {
                output = String::from_utf8(
                    Command::new("apt")
                        .arg("-qq")
                        .arg("list")
                        .arg(pkg)
                        .output()
                        .unwrap()
                        .stdout,
                )?;

                if !output.contains("[installed]") {
                    missing_pgks.push(pkg);
                } else {
                    println!(
                        "{}: Package \"{}\" is installed.",
                        "Analyze".blue().bold(),
                        pkg.bold()
                    );
                }
            }
        }
        "archlinux" => {
            output = String::from_utf8(
                Command::new("sh")
                    .args(&[
                        "-c",
                        format!("pacman -Qqen | grep -wE '{}'", ARCH_PACKAGES.join("|")).as_str(),
                    ])
                    .output()
                    .unwrap()
                    .stdout,
            )?;

            for pkg in ARCH_PACKAGES {
                if !output.contains(&pkg) {
                    missing_pgks.push(pkg);
                } else {
                    println!(
                        "{}: Package \"{}\" is installed.",
                        "Analyze".blue().bold(),
                        pkg.bold()
                    );
                }
            }
        }
        _ => return Err(anyhow!("Unsupported OS: {}", output)),
    }

    if missing_pgks.len() > 0 {
        let mut action = String::new();
        println!(
            "{}: Missing packages:\n - {}",
            "Analyze".blue(),
            missing_pgks.join("\n - ")
        );
        print!(
            "{}: Attempt to install missing packages? [Y/n] ",
            "Analyze".blue().bold()
        );
        io::stdout().flush()?;
        io::stdin().read_line(&mut action)?;

        let action = action.trim().to_lowercase();

        if action != "y" && action != "yes" && action != "" {
            return Err(anyhow!("Cannot proceed with missing packages!"));
        }
        let password = rpassword::prompt_password("Password: ").unwrap();
        match nodename {
            "ubuntu" => {
                Command::new("echo")
                    .arg(password)
                    .arg("| sudo")
                    .arg("-S")
                    .arg("apt install --assume-yes")
                    .arg(missing_pgks.join(" "))
                    .output()?;
            }
            "archlinux" => {
                Command::new("echo")
                    .arg(password)
                    .arg("| sudo")
                    .arg("-S")
                    .arg("pacman --noconfirm -S")
                    .arg(missing_pgks.join(" "))
                    .output()?;
            }
            _ => return Err(anyhow!("Unsupported OS: {}", output)),
        }
        println!(
            "{}: Missing packages installed succefully ✔︎",
            "Analyze".blue().bold()
        );
    } else {
        println!("{}: All packages installed ✔︎\n", "Analyze".blue().bold());
    }
    Ok(())
}

fn check_packages_remote(session: &mut Session, password: &str) -> Result<(), anyhow::Error> {
    let mut channel = session.channel_session().unwrap();
    channel.exec("uname -n").unwrap();
    let mut output = String::new();
    channel.read_to_string(&mut output).unwrap();
    let mut missing_pgks: Vec<&str> = Vec::new();

    let nodename = output.clone().trim().to_string();

    match nodename.as_str() {
        "ubuntu" => {
            for pkg in UBUNTU_PACKAGES {
                output = String::new();
                let mut channel = session.channel_session().unwrap();
                channel
                    .exec(format!("apt -qq list {}", pkg).as_str())
                    .unwrap();
                channel.read_to_string(&mut output).unwrap();

                if !output.contains("[installed]") {
                    missing_pgks.push(pkg);
                } else {
                    println!(
                        "{}: Package \"{}\" is installed.",
                        "Analyze".blue().bold(),
                        pkg.bold()
                    );
                }

                channel.wait_close()?;
            }
        }
        "archlinux" => {
            let mut channel = session.channel_session().unwrap();
            channel
                .exec(format!("pacman -Qqen | grep {}", ARCH_PACKAGES.join(" ")).as_str())
                .unwrap();
            channel.read_to_string(&mut output).unwrap();
            channel.wait_close()?;

            for pkg in ARCH_PACKAGES {
                if !output.contains(pkg) {
                    missing_pgks.push(pkg);
                } else {
                    println!(
                        "{}: Package \"{}\" is installed.",
                        "Analyze".blue().bold(),
                        pkg.bold()
                    );
                }
            }
        }
        _ => return Err(anyhow!("Unsupported OS: {}", output)),
    }

    if missing_pgks.len() > 0 {
        let mut action = String::new();
        println!(
            "{}: Missing packages:\n - {}",
            "Analyze".blue(),
            missing_pgks.join("\n - ")
        );
        print!(
            "{}: Attempt to install missing packages? [Y/n] ",
            "Analyze".blue().bold()
        );
        io::stdout().flush()?;
        io::stdin().read_line(&mut action)?;

        let action = action.trim().to_lowercase();

        if action != "y" && action != "yes" && action != "" {
            return Err(anyhow!("Cannot proceed with missing packages!"));
        }
        match nodename.as_str() {
            "ubuntu" => {
                output = String::new();
                channel = session.channel_session().unwrap();
                channel
                    .exec(
                        format!(
                            "echo {} | sudo -S apt install --assume-yes {}",
                            password,
                            missing_pgks.join(" ")
                        )
                        .as_str(),
                    )
                    .unwrap();
                channel.read_to_string(&mut output).unwrap();

                channel.wait_close()?;
            }
            "archlinux" => {
                output = String::new();
                channel = session.channel_session().unwrap();
                channel
                    .exec(
                        format!(
                            "echo {} | sudo -S pacman --noconfirm -S {}",
                            password,
                            missing_pgks.join(" ")
                        )
                        .as_str(),
                    )
                    .unwrap();
                channel.read_to_string(&mut output).unwrap();

                channel.wait_close()?;
            }
            _ => return Err(anyhow!("Unsupported OS: {}", output)),
        }
        println!(
            "{}: Missing packages installed succefully ✔︎",
            "Analyze".blue().bold()
        );
    } else {
        println!("{}: All packages installed ✔︎\n", "Analyze".blue().bold());
    }
    channel.wait_close()?;
    Ok(())
}

fn check_bpf_enabled(flags: Vec<&str>) -> Result<(), anyhow::Error> {
    let mut missing_flags: Vec<&str> = Vec::new();

    for f in flags {
        if !f.trim().contains("is set to y") {
            missing_flags.push(f);
        }
    }

    if missing_flags.len() != 0 {
        return Err(anyhow!(
            "Missing kernel flags:\n - {}",
            missing_flags.join("\n - ")
        ));
    }

    println!(
        "{}: Required kernel flags enabled ✔︎\n",
        "Analyze".blue().bold()
    );

    Ok(())
}
fn check_bpf_enabled_remote(session: &mut Session, password: &str) -> Result<(), anyhow::Error> {
    println!(
        "{}: Checking required kernel flags",
        "Analyze".blue().bold()
    );
    let mut channel = session.channel_session().unwrap();
    channel
        .exec( format!(
            "echo {} | (sudo bpftool feature | rg -w 'CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_BPF_JIT|CONFIG_BPF_EVENTS')",
            password
        )
            .as_str(),
        )
        .unwrap();
    let mut output = String::new();
    channel.read_to_string(&mut output).unwrap();
    channel.wait_close()?;

    channel = session.channel_session().unwrap();
    channel
        .exec(
            format!(
                "echo {} | (sudo -S bpftool feature | rg -w 'CONFIG_HAVE_EBPF_JIT|CONFIG_HAVE_BPF_JIT')",
                password
            )
            .as_str(),
        )
        .unwrap();
    channel.read_to_string(&mut output).unwrap();
    channel.wait_close()?;

    let flags: Vec<&str> = output.trim().split("\n").collect();
    check_bpf_enabled(flags)?;

    Ok(())
}

fn check_net_iface(iface: &str, ifaces: Vec<&str>) -> Result<(), anyhow::Error> {
    if ifaces.contains(&iface) {
        println!(
            "{}: Interface \"{}\" is available ✔︎\n",
            "Analyze".blue().bold(),
            iface.bold()
        );
    } else {
        return Err(anyhow!("Interface \"{}\" is not available", iface.bold()));
    }

    Ok(())
}

fn check_net_iface_remote(session: &mut Session, iface: &str) -> Result<(), anyhow::Error> {
    println!("{}: Checking network interfaces", "Analyze".blue().bold());
    let mut channel = session.channel_session().unwrap();
    channel
        .exec(format!("ip -o link show | awk -F': ' '{{print $2}}'",).as_str())
        .unwrap();
    let mut output = String::new();
    channel.read_to_string(&mut output).unwrap();
    channel.wait_close()?;

    let ifaces: Vec<&str> = output.split("\n").collect();
    check_net_iface(iface, ifaces)?;

    Ok(())
}
