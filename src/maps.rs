use std::process::Command;

use libbpf_rs::{MapCore, MapFlags, MapImpl, Object};

pub fn get_map<'a>(object: &'a Object, name: &'a str) -> Option<MapImpl<'a>> {
    let maps = object.maps();

    for m in maps {
        if m.name() == name {
            return Some(m);
        }
    }

    None
}

pub fn load_map_data_local_temp(map: &MapImpl, data: &Vec<String>) -> Result<(), anyhow::Error> {
    if data.len() == 0 {
        return Ok(());
    }

    for address in data {
        let key: Vec<u8> = address.split(".").map(|n| n.parse().unwrap_or(0)).collect();
        let mut value = key.clone();
        let mut empty_data: Vec<u8> =
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
            "0", "0", "0",
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
            .arg(format!("key {} value {}", key.join(" "), value.join(" ")))
            .output()?;
    }

    Ok(())
}
