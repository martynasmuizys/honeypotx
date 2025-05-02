local config = {
    init = {
        name = "hpx",
        iface = "lo",
        prog_type = "dns",
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
        blacklist = { "127.0.0.4", "127.0.0.2", "128.0.1.2" }
    }
}

-- analyze({config})

local done, out = generate({config})
-- if done then
--     print("──────────────────────────")
--     print("eBPF program generated at:", out)
--     print("──────────────────────────\n")
-- end
--
local opts = {config, "lo", "generic"};
local id = pload(opts)
local json = require 'json'
local data = json.encode(get_map_data({config, "blacklist"}))

local cmd = "curl -X POST -d '" .. tostring(data) .. "' http://localhost:8080/log"

os.execute(cmd)

punload({config, "lo", "generic", id})
