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
        blacklist = { "127.0.0.1", "127.0.0.2" }
    }
}

-- analyze(config)
--
-- local done, out = generate(config)
-- if done then
--     print("──────────────────────────")
--     print("eBPF program generated at:", out)
--     print("──────────────────────────\n")
-- end

local id = pload(config, "lo", "generic")
print("Program id:", id)
local data = get_map_data(config, "blacklist")
print("Program data:", data)
punload(config, "lo", "generic", id)
