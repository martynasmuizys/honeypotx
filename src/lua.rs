use std::{fs, path::Path};

use crossterm::style::Stylize;
use mlua::{ExternalResult, Lua, LuaSerdeExt};
use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::{
    analyze,
    cli::{Analyze, Generate, Load, Unload},
    config::Config,
    engine::generator,
    load::load,
    maps::get_map_data,
    unload::unload,
};

pub async fn run_script(work_dir: &str, script_path: Option<&str>) -> mlua::Result<()> {
    let default_path = format!("{}/scripts/run.lua", work_dir);
    let mut curr_path = std::env::current_dir().expect("Error: Failed to get current directory");
    let mut path = Path::new(&default_path);

    if let Some(p) = script_path {
        path = Path::new(p)
    }

    if script_path.is_some() {
        curr_path.push(script_path.unwrap());
        path = curr_path.as_path();
    }

    if path.exists() {
        let lua = Lua::new();

        let analyze_func = lua.create_function(|lua, opts: mlua::Table| -> mlua::Result<bool> {
            let cfg: mlua::Table = opts.get(1)?;
            if std::env::var("HPX_ANALYZED").unwrap_or("0".to_string()) == "1" {
                return Ok(true);
            }
            let val = cfg.serialize(mlua::serde::Serializer::new(lua))?;
            let json_data = serde_json::to_string(&val).map_err(mlua::Error::external)?;
            let config: Config = serde_json::from_str(&json_data).map_err(mlua::Error::external)?;
            match analyze(Analyze {noconfirm: Some("".to_string())}, config) {
                Ok(ret) => {
                    std::env::set_var("HPX_ANALYZED", "1");
                    Ok(ret)
                }
                Err(e) => Err(mlua::Error::runtime(e)),
            }
        })?;

        let generate_func =
            lua.create_function(|lua, opts: mlua::Table| -> mlua::Result<(bool, String)> {
                let cfg: mlua::Table = opts.get(1)?;
                if std::env::var("HPX_GENERATED").unwrap_or("0".to_string()) == "1" {
                    return Ok((false, "".to_string()));
                }
                let val = cfg.serialize(mlua::serde::Serializer::new(lua))?;
                let json_data = serde_json::to_string(&val).map_err(mlua::Error::external)?;
                let config: Config =
                    serde_json::from_str(&json_data).map_err(mlua::Error::external)?;
                match generator(Generate {noconfirm: Some("".to_string())}, config) {
                    Ok(ret) => {
                        std::env::set_var("HPX_GENERATED", "1");
                        Ok(ret)
                    }
                    Err(e) => Err(mlua::Error::runtime(e)),
                }
            })?;

        let load_func = lua.create_async_function(|lua, opts: mlua::Table| async move {
            let cfg: mlua::Table = opts.get(1)?;
            let iface: mlua::String = opts.get(2)?;
            let xdp_flags: mlua::String = opts.get(3)?;

            let val = cfg.serialize(mlua::serde::Serializer::new(&lua))?;
            let json_data = serde_json::to_string(&val).map_err(mlua::Error::external)?;
            let config: Config = serde_json::from_str(&json_data).map_err(mlua::Error::external)?;

            check_sudo();

            match load(
                &mut Load {
                    iface: iface.to_string_lossy(),
                    xdp_flags: xdp_flags.to_string_lossy(),
                },
                config,
            )
            .await
            .into_lua_err()
            {
                Ok(ret) => Ok(ret),
                Err(e) => Err(mlua::Error::runtime(e)),
            }
        })?;

        let unload_func = lua.create_function(|lua, opts: mlua::Table| {
            let cfg: mlua::Table = opts.get(1)?;
            let iface: mlua::String = opts.get(2)?;
            let xdp_flags: mlua::String = opts.get(3)?;
            let prog_id: mlua::Integer = opts.get(4)?;

            let val = cfg.serialize(mlua::serde::Serializer::new(lua))?;
            let json_data = serde_json::to_string(&val).map_err(mlua::Error::external)?;
            let config: Config = serde_json::from_str(&json_data).map_err(mlua::Error::external)?;

            check_sudo();

            match unload(
                &mut Unload {
                    iface: iface.to_string_lossy(),
                    xdp_flags: xdp_flags.to_string_lossy(),
                    pid: prog_id.to_string(),
                },
                config,
            )
            .into_lua_err()
            {
                Ok(ret) => Ok(ret),
                Err(e) => Err(mlua::Error::runtime(e)),
            }
        })?;

        let get_map_data_func = lua.create_function(|lua, opts: mlua::Table| {
            let cfg: mlua::Table = opts.get(1)?;
            let map_name: mlua::String = opts.get(2)?;

            let val = cfg.serialize(mlua::serde::Serializer::new(lua))?;
            let json_data = serde_json::to_string(&val).map_err(mlua::Error::external)?;
            let config: Config = serde_json::from_str(&json_data).map_err(mlua::Error::external)?;

            check_sudo();

            match get_map_data(&config, &map_name.to_string_lossy()) {
                Ok(ret) => {
                    let json: JsonValue =
                        serde_json::from_str(&ret).map_err(mlua::Error::external)?;
                    Ok(lua.to_value(&json)?)
                }
                Err(e) => Err(mlua::Error::runtime(e)),
            }
        })?;

        lua.globals().set("analyze", analyze_func)?;
        lua.globals().set("generate", generate_func)?;
        lua.globals().set("pload", load_func)?;
        lua.globals().set("punload", unload_func)?;
        lua.globals().set("get_map_data", get_map_data_func)?;

        let run = fs::read_to_string(path)?;
        lua.load(run).eval_async::<()>().await?;
        std::env::remove_var("HPX_ANALYZED");
        std::env::remove_var("HPX_GENERATED");
    }

    Ok(())
}

fn check_sudo() {
    match sudo::check() {
        sudo::RunningAs::Root => (),
        sudo::RunningAs::User => {
            println!("{}: Requesting sudo privileges", "Unload".red().bold());
            let _ = sudo::with_env(&["HOME", "HPX_ANALYZED", "HPX_GENERATED"]);
        }
        sudo::RunningAs::Suid => (),
    }
}
