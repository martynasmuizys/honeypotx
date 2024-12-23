use std::{fs, path::Path};

use crossterm::style::Stylize;
use mlua::{ExternalResult, Lua};
use serde::Serialize;

use crate::{analyze, config::Config, engine::generator, load::load, Analyze, Generate, Load};

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
        dbg!(&path);
    }

    if path.exists() {
        let lua = Lua::new();

        let analyze_func = lua.create_function(|lua, cfg: mlua::Table| -> mlua::Result<bool> {
            let val = cfg.serialize(mlua::serde::Serializer::new(lua))?;
            let json_data = serde_json::to_string(&val).map_err(mlua::Error::external)?;
            let config: Config = serde_json::from_str(&json_data).map_err(mlua::Error::external)?;
            match analyze(Analyze {}, config) {
                Ok(ret) => Ok(ret),
                Err(e) => Err(mlua::Error::runtime(e)),
            }
        })?;

        let generate_func =
            lua.create_function(|lua, cfg: mlua::Table| -> mlua::Result<(bool, String)> {
                let val = cfg.serialize(mlua::serde::Serializer::new(lua))?;
                let json_data = serde_json::to_string(&val).map_err(mlua::Error::external)?;
                let config: Config =
                    serde_json::from_str(&json_data).map_err(mlua::Error::external)?;
                match generator(Generate {}, config) {
                    Ok(ret) => Ok(ret),
                    Err(e) => Err(mlua::Error::runtime(e)),
                }
            })?;

        let load_func = lua.create_async_function(
            |lua, (cfg, iface, xdp_flags): (mlua::Table, mlua::String, mlua::String)| async move {
                let val = cfg.serialize(mlua::serde::Serializer::new(&lua))?;
                let json_data = serde_json::to_string(&val).map_err(mlua::Error::external)?;
                let config: Config =
                    serde_json::from_str(&json_data).map_err(mlua::Error::external)?;

                match sudo::check() {
                    sudo::RunningAs::Root => (),
                    sudo::RunningAs::User => {
                        println!("{}: Requesting sudo privileges", "Load".red().bold());
                        let _ = sudo::with_env(&["HOME"]);
                    }
                    sudo::RunningAs::Suid => (),
                }

                load(
                    &mut Load {
                        iface: iface.to_string_lossy(),
                        xdp_flags: xdp_flags.to_string_lossy(),
                    },
                    config,
                )
                .await
                .into_lua_err()
            },
        )?;

        lua.globals().set("analyze", analyze_func)?;
        lua.globals().set("generate", generate_func)?;
        lua.globals().set("load_prog", load_func)?;

        let run = fs::read_to_string(path)?;
        lua.load(run).eval_async::<()>().await?;
    }

    Ok(())
}
