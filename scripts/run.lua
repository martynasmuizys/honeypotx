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

-- analyze(config)
--

local handle = io.popen("ls /tmp/generated.o 2> /dev/null")
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
