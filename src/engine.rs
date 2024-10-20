use std::{
    fs::File,
    io::{self, Write},
    thread,
    time::Duration,
};

use crate::{
    config::{Config, List},
    snippets::{ACTION, BASE, MAP},
};

pub fn generate(config: Config, out_file: File) -> Result<(), anyhow::Error> {
    let mut writer = io::BufWriter::new(out_file);

    for line in BASE.lines() {
        match line.find("{{") {
            Some(start) => match line.find("}}") {
                Some(end) => {
                    let block = &line[start + 2..end];
                    let mut parsed_line: String = String::new();
                    match block {
                        "name" => {
                            parsed_line = replace_name(&config, start, end, line);
                        }
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
                            parsed_line = replace_map(
                                config.init.as_ref().unwrap().whitelist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "whitelist",
                            );
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
                            parsed_line = replace_map(
                                config.init.as_ref().unwrap().blacklist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "blacklist",
                            );
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
                            parsed_line = replace_map(
                                config.init.as_ref().unwrap().graylist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "graylist",
                            );
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
                            parsed_line = replace_action(
                                config.init.as_ref().unwrap().whitelist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "whitelist",
                            );
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
                            parsed_line = replace_action(
                                config.init.as_ref().unwrap().blacklist.as_ref().unwrap(),
                                start,
                                end,
                                line,
                                "blacklist",
                            );
                        }
                        "greylist_action" => {}
                        _ => {
                            writer.write((line.to_string() + "\n").as_bytes())?;
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
        .unwrap()
        .as_str();
    line.replace(&line[start..end + 2], name)
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

fn replace_action(config: &impl List, start: usize, end: usize, line: &str, list: &str) -> String {
    let mut parsed: Vec<String> = Vec::new();

    for l in ACTION.lines() {
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
