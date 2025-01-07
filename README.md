# HoneypotX
HoneypotX is a highly configurable new generation type of honeypot generator tool which adopts eBPF technology.

![Gosling](https://media.tenor.com/Vlr5ep-dRXMAAAAM/ryan-gosling-blade-runner2049.gif)

## Table of Contents
- [Installation](#-installation)
  - [Cargo](#-cargo)
  - [Usage](#-usage)
- [Configuration](#-configuration)

## Installation
### Cargo
First make sure [Rust](https://github.com/rust-lang/rust) toolchain is installed (it is recommened to use [rustup](https://rustup.rs/) installation method). For now installation uses Nightly toolchain.
```bash
cargo +nightly install --git https://github.com/martynasmuizys/honeypotx.git
```
### Manually
```bash
git clone https://github.com/martynasmuizys/honeypotx.git
cd hpx
make install
```

## Usage
The binary is named `hpx`. You can run `hpx help` to list all possible commands.

Here is some examples:
```
hpx analyze -c path/to/config # Analyzes system's compatibility with eBPF

hpx generate -c path/to/config # Generates eBPF program based on the configuration

hpx get base-config # Get starter config

hpx get example-config # Get example config

hpx secret # THIS IS SECRET! DO NOT RUN THIS!
```

## Configuration
A path to the configuration file can be provided using `-c` flag. Only JSON and TOML configuration formats are supported.

The following is a sample config.json file:
```json
{
    "init": {
        "name": "Example",
        "hostname": "100.0.0.10",
        "port": 22,
        "username": "bobthebuilder",
        "iface": "eth0",
        "prog_type": "ip",
        "whitelist": {
            "enabled": false,
            "max": 32,
            "action": "allow"
        },
        "blacklist": {
            "enabled": false,
            "max": 32,
            "action": "deny"
        },
        "graylist": {
            "enabled": false,
            "max": 32,
            "action": "investigate",
            "frequency": 1000,
            "fast_packet_count": 10
        }
    },
    "data": {
        "whitelist": ["192.168.1.103"],
        "blacklist": ["192.168.1.203"],
        "graylist": []
    }
}
```

## Scripting
You can use Lua to automate programs execution. Only part of API is availabl with Lua scripting:
| Function | Input | Output | Description |
| ---| --- | --- | --- |
| `analyze(opts)` | <pre>opts = {<br>&nbsp;config<br>}</pre> | `boolean` | Analyze system's compatibility with eBPF |
| `generate(opts)` | <pre>opts = {<br>&nbsp;config<br>}</pre> | `(boolean, string)` | Generate eBPF program |
| `pload(opts)` | <pre>opts = {<br>&nbsp;config,<br>&nbsp;iface,<br>&nbsp;xdp_flags<br>}</pre> | `number` | Load eBPF program |
| `punload(opts)` | <pre>opts = {<br>&nbsp;config,<br>&nbsp;iface,<br>&nbsp;xdp_flags,<br>&nbsp;prog_id<br>}</pre> | `nil` | Unload eBPF program |
| `get_map_data(opts)` | <pre>opts = {<br>&nbsp;config,<br>&nbsp;map_name<br>}</pre> | `table` | Get map data |

To run Lua script with HPX:
```bash
hpx run -p path/to/script
```

Here is an example of run.lua script:
```lua
local config = {
    init = {
        name = "hpx",
        iface = "lo",
        prog_type = "ip",
        whitelist = {
            enabled = true,
        },
        blacklist = {
            enabled = true,
        },
        graylist = {
            action = "investigate",
            enabled = true,
            frequency = 2000
        }
    },
    data = {
        blacklist = { "127.0.0.1", "127.0.0.2", "128.0.1.2" }
    }
}

analyze(config)

local handle = io.popen("ls /home/martis/.hpx/out/generated.o 2> /dev/null")
local result
if handle ~= nil then
    result = handle:read("*a")
end

if result == "" then
    local done, out = generate(config)
    if done then
        print("──────────────────────────")
        print("eBPF program generated at:", out)
        print("──────────────────────────\n")
    end
end


local id = pload(config, "lo", "generic")
print("Program id:", id)
local data = get_map_data(config, "blacklist")
local last_ip = ""
for k, v in pairs(data[#data]["key"]) do
    if k == #data[#data]["key"] then
        last_ip = last_ip .. tonumber(v)
    else
        last_ip = last_ip .. tonumber(v) .. "."
    end
end
print("Random banned IP:", last_ip)
punload(config, "lo", "generic", id)
```

