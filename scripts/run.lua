local config = {
    init = {
        name = "hpx",
        hostname = "193.219.91.103",
        port = 10033,
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

analyze({config})

-- local done, out = generate({config})
-- if done then
--     print("──────────────────────────")
--     print("eBPF program generated at:", out)
--     print("──────────────────────────\n")
-- end
--
-- local opts = {config, "lo", "generic"};
-- local id = pload(opts)
-- print("Program id:", id)
-- local data = get_map_data({config, "blacklist"})
-- local last_ip = ""
-- for k, v in pairs(data[#data]["key"]) do
--     if k == #data[#data]["key"] then
--         last_ip = last_ip .. tonumber(v)
--     else
--         last_ip = last_ip .. tonumber(v) .. "."
--     end
-- end
-- print("Random banned IP:", last_ip)
-- punload({config, "lo", "generic", id})
