use core::panic;
use std::{
    fs::File,
    io::{self, Write},
    path::Path,
    process::Command,
};

use anyhow::{anyhow, Context};
use crossterm::style::Stylize;

use crate::{
    cli::Generate,
    config::{Config, Init, List, DEFAULT_FAST_PACKETS, DEFAULT_FREQUENCY, DEFAULT_NAME},
    snippets::{ACTION, BASE_DNS, BASE_IP, GET_DATA_DNS, GET_DATA_IP, GRAYLIST, MAP},
    WORKING_DIR,
};

pub fn generator(options: Generate, config: Config) -> Result<(bool, String), anyhow::Error> {
    let out = format!(
        "{}/out/generated.c",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory".to_string())?
    );
    let path = Path::new(&out);
    let out_file = File::create(path)?;

    if options.noconfirm.is_none() {
        println!("{}\n", "- CONFIG -".on_blue().black());
        let mut action = String::new();

        println!("{}", config);

        print!(
            "{}: Using config above. Proceed? [Y/n] ",
            "Analyze".blue().bold()
        );
        io::stdout().flush()?;
        io::stdin().read_line(&mut action)?;

        let action = action.trim().to_lowercase();

        if action != "y" && action != "yes" && !action.is_empty() {
            return Err(anyhow!("Cancelled"));
        }
    }

    println!("{}: Generating eBPF program...", "Generate".yellow().bold(),);
    generate(config, out_file)?;
    println!(
        "{}: Generated eBPF program at: {}",
        "Generate".yellow().bold(),
        path.display()
    );

    let out = format!(
        "{}/out/generated.o",
        WORKING_DIR
            .to_str()
            .with_context(|| "Failed to parse HOME directory".to_string())?
    );
    let compile_out = Path::new(&out);
    println!("{}: Compiling eBPF program...", "Generate".yellow().bold(),);
    Command::new("clang")
        .arg("-O2")
        .arg("-g")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(path)
        .arg("-o")
        .arg(compile_out)
        .output()?;
    println!(
        "{}: Compiled eBPF program at: {}",
        "Generate".yellow().bold(),
        compile_out.display()
    );

    Ok((true, out))
}

// should have written a library to do most of this stuff... like finding patters and changing
// them... idk future work maybe. also unwraping then taking as ref then unwraping again is so
// messy its crazy
// seperate generator functions, f.e. frequency, dns(? wip), other that would allow more
// features/configuration
pub fn generate(config: Config, out_file: File) -> Result<(), anyhow::Error> {
    match config.init.as_ref().unwrap().prog_type.as_ref() {
        Some(t) => match t.as_str() {
            "ip" => {
                generate_program(config, out_file, BASE_IP)?;
            }
            "dns" => {
                generate_program(config, out_file, BASE_DNS)?;
            }
            _ => return Err(anyhow!("Unknown program type")),
        },
        None => generate_program(config, out_file, BASE_IP)?,
    }
    Ok(())
}

fn generate_program(config: Config, out: File, prog_base: &str) -> Result<(), anyhow::Error> {
    let mut writer = io::BufWriter::new(out);

    for line in prog_base.lines() {
        match line.find("{{") {
            Some(start) => match line.find("}}") {
                Some(end) => {
                    let block = &line[start + 2..end];
                    let parsed_line: String = match block {
                        "name" => replace_name(&config, start, end, line),
                        "whitelist_map" => {
                            if config.init.as_ref().unwrap().whitelist.is_none()
                                || !config
                                    .init
                                    .as_ref()
                                    .unwrap()
                                    .whitelist
                                    .as_ref()
                                    .unwrap()
                                    .enabled
                                    .unwrap()
                            {
                                continue;
                            }
                            replace_map(
                                config.init.as_ref().unwrap().whitelist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "whitelist",
                            )
                        }
                        "blacklist_map" => {
                            if config.init.as_ref().unwrap().blacklist.is_none()
                                || !config
                                    .init
                                    .as_ref()
                                    .unwrap()
                                    .blacklist
                                    .as_ref()
                                    .unwrap()
                                    .enabled
                                    .unwrap()
                            {
                                continue;
                            }
                            replace_map(
                                config.init.as_ref().unwrap().blacklist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "blacklist",
                            )
                        }
                        "graylist_map" => {
                            if config.init.as_ref().unwrap().graylist.is_none()
                                || !config
                                    .init
                                    .as_ref()
                                    .unwrap()
                                    .graylist
                                    .as_ref()
                                    .unwrap()
                                    .enabled
                                    .unwrap()
                            {
                                continue;
                            }
                            replace_map(
                                config.init.as_ref().unwrap().graylist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "graylist",
                            )
                        }
                        "whitelist_action" => {
                            if config.init.as_ref().unwrap().whitelist.is_none()
                                || !config
                                    .init
                                    .as_ref()
                                    .unwrap()
                                    .whitelist
                                    .as_ref()
                                    .unwrap()
                                    .enabled
                                    .unwrap()
                            {
                                continue;
                            }
                            replace_wb_action(
                                config
                                    .init
                                    .as_ref()
                                    .unwrap()
                                    .prog_type
                                    .as_ref()
                                    .unwrap_or(&"ip".to_string()),
                                config.init.as_ref().unwrap().whitelist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "whitelist",
                            )
                        }
                        "blacklist_action" => {
                            if config.init.as_ref().unwrap().blacklist.is_none()
                                || !config
                                    .init
                                    .as_ref()
                                    .unwrap()
                                    .blacklist
                                    .as_ref()
                                    .unwrap()
                                    .enabled
                                    .unwrap()
                            {
                                continue;
                            }
                            replace_wb_action(
                                config
                                    .init
                                    .as_ref()
                                    .unwrap()
                                    .prog_type
                                    .as_ref()
                                    .unwrap_or(&"ip".to_string()),
                                config.init.as_ref().unwrap().blacklist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "blacklist",
                            )
                        }
                        "graylist_action" => {
                            if config.init.as_ref().unwrap().graylist.is_none()
                                || !config
                                    .init
                                    .as_ref()
                                    .unwrap()
                                    .graylist
                                    .as_ref()
                                    .unwrap()
                                    .enabled
                                    .unwrap()
                            {
                                continue;
                            }
                            replace_g_action(
                                config.init.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "graylist",
                            )
                        }
                        "default_action" => replace_default_action(&config, start, end, line),
                        _ => {
                            writer.write_all((line.to_string() + "\n").as_bytes())?;
                            continue;
                        }
                    };

                    writer.write((parsed_line + "\n").as_bytes())?
                }
                None => continue,
            },
            None => writer.write((line.to_string() + "\n").as_bytes())?,
        };
    }
    Ok(())
}

fn replace_name(config: &Config, start: usize, end: usize, line: &str) -> String {
    let name = config
        .init
        .as_ref()
        .unwrap()
        .name
        .as_ref()
        .unwrap_or(&DEFAULT_NAME.to_string())
        .as_str()
        .replace(" ", "");
    line.replace(&line[start..end + 2], &name)
}

fn replace_map(config: &impl List, start: usize, end: usize, line: &str, name: &str) -> String {
    let mut parsed: Vec<String> = Vec::new();

    for l in MAP.lines() {
        match l.find("{{") {
            Some(start) => match l.find("}}") {
                Some(end) => {
                    let block = &l[start + 2..end];
                    match block {
                        "max" => {
                            let s = l.replace(&l[start..end + 2], &config.get_max().to_string());
                            parsed.push(s + "\n");
                        }
                        "name" => {
                            let s = l.replace(&l[start..end + 2], name);
                            parsed.push(s + "\n");
                        }
                        _ => continue,
                    }
                }
                None => parsed.push(l.to_string() + "\n"),
            },
            None => parsed.push(l.to_string() + "\n"),
        }
    }
    line.replace(&line[start..end + 2], &parsed.concat())
}

fn replace_wb_action(
    prog_type: &str,
    config: &impl List,
    start: usize,
    end: usize,
    line: &str,
    list: &str,
) -> String {
    let mut parsed: Vec<String> = Vec::new();
    let actions: &str = match prog_type.to_lowercase().as_str() {
        "ip" => &(GET_DATA_IP.to_owned() + ACTION),
        "dns" => &(GET_DATA_DNS.to_owned() + ACTION),
        _ => panic!("Generate: Unsupported program type"),
    };

    for l in actions.lines() {
        let mut curr_line = l;
        let mut l = l.to_string();

        let mut s: String = String::new();

        let mut found = false;
        while curr_line.contains("{{") && curr_line.contains("}}") {
            if !found {
                found = true;
            }
            match curr_line.find("{{") {
                Some(start) => match curr_line.find("}}") {
                    Some(end) => {
                        let block = &curr_line[start + 2..end];
                        match block {
                            "action" => match config.get_action() {
                                "allow" => {
                                    s = l.replace(
                                        &curr_line[start..end + 2],
                                        &curr_line[start..end + 2]
                                            .replace(&curr_line[start..end + 2], "XDP_PASS"),
                                    );
                                    l = s.clone();
                                }
                                "deny" => {
                                    s = l.replace(
                                        &curr_line[start..end + 2],
                                        &curr_line[start..end + 2]
                                            .replace(&curr_line[start..end + 2], "XDP_DROP"),
                                    );
                                    l = s.clone();
                                }
                                _ => {
                                    s = l.replace(
                                        &curr_line[start..end + 2],
                                        &curr_line[start..end + 2]
                                            .replace(&curr_line[start..end + 2], "XDP_DROP"),
                                    );
                                    l = s.clone();
                                }
                            },
                            "list" => {
                                s = l.replace(
                                    &curr_line[start..end + 2],
                                    &curr_line[start..end + 2]
                                        .replace(&curr_line[start..end + 2], list),
                                );
                                l = s.clone();
                            }
                            _ => continue,
                        }
                        curr_line = &curr_line[end + 2..curr_line.len()];
                    }
                    None => unreachable!("Should not be reached!"),
                },
                None => unreachable!("Should not be reached!"),
            }
        }
        parsed.push(s + "\n");
        if !found {
            parsed.push(l.to_string() + "\n");
        }
    }
    line.replace(&line[start..end + 2], &parsed.concat())
}

fn replace_g_action(config: &Init, start: usize, end: usize, line: &str, list: &str) -> String {
    let mut parsed: Vec<String> = Vec::new();
    let action = match config.graylist.as_ref().unwrap().get_action() {
        "allow" | "deny" => {
            return replace_wb_action(
                "ip",
                config.graylist.as_ref().unwrap(),
                start,
                end,
                line,
                list,
            );
        }
        _ => GRAYLIST,
    };
    let actions: &str = &(GET_DATA_IP.to_owned() + action);

    for l in actions.lines() {
        let mut curr_line = l;
        let mut l = l.to_string();

        let mut s: String = String::new();

        let mut found = false;
        while curr_line.contains("{{") && curr_line.contains("}}") {
            if !found {
                found = true;
            }
            match curr_line.find("{{") {
                Some(start) => match curr_line.find("}}") {
                    Some(end) => {
                        let block = &curr_line[start + 2..end];
                        match block {
                            "frequency" => {
                                s = l.replace(
                                    &curr_line[start..end + 2],
                                    &curr_line[start..end + 2].replace(
                                        &curr_line[start..end + 2],
                                        &config
                                            .graylist
                                            .as_ref()
                                            .unwrap()
                                            .frequency
                                            .unwrap_or(DEFAULT_FREQUENCY)
                                            .to_string(),
                                    ),
                                );
                                l = s.clone();
                            }
                            "fast_packet_count" => {
                                s = l.replace(
                                    &curr_line[start..end + 2],
                                    &curr_line[start..end + 2].replace(
                                        &curr_line[start..end + 2],
                                        &config
                                            .graylist
                                            .as_ref()
                                            .unwrap()
                                            .fast_packet_count
                                            .unwrap_or(DEFAULT_FAST_PACKETS)
                                            .to_string(),
                                    ),
                                );
                                l = s.clone();
                            }
                            "list" => {
                                s = l.replace(
                                    &curr_line[start..end + 2],
                                    &curr_line[start..end + 2]
                                        .replace(&curr_line[start..end + 2], list),
                                );
                                l = s.clone();
                            }
                            _ => continue,
                        }
                        curr_line = &curr_line[end + 2..curr_line.len()];
                    }
                    None => unreachable!("Cannot be reached!"),
                },
                None => unreachable!("Should not be reached!"),
            }
        }
        parsed.push(s + "\n");
        if !found {
            parsed.push(l.to_string() + "\n");
        }
    }
    line.replace(&line[start..end + 2], &parsed.concat())
}

fn replace_default_action(config: &Config, start: usize, end: usize, line: &str) -> String {
    let default_action = config
        .init
        .as_ref()
        .unwrap()
        .xdp_action
        .as_ref()
        .unwrap_or(&"PASS".to_string())
        .as_str()
        .replace(" ", "");
    match default_action.to_uppercase().as_str() {
        "PASS" | "DROP" => line.replace(
            &line[start..end + 2],
            &("XDP_".to_string() + &default_action.to_uppercase()),
        ),
        _ => {
            println!(
                "INFO: Unsupported XDP action: {}. Using default: PASS",
                &default_action
            );
            line.replace(&line[start..end + 2], &("XDP_".to_string() + "PASS"))
        }
    }
}
