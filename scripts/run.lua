local config = {
    init = {
        name = "hpx",
        iface = "lo",
        prog_type = "ip",
        data = {
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
        }
    },
    blacklist = { "127.0.0.1", "127.0.0.2" }
}

local done
done = analyze(config)
if done then
    os.execute("notify-send Analyze: Completed")
end

local out
done, out = generate(config)
if done then
    local cmd = "notify-send 'Generate: Completed.\nProgram generated at:\n" .. out .. "'"
    os.execute(cmd)
end

local http_request = require "http.request"
local headers, stream = assert(http_request.new_from_uri("http://google.com"):go())
headers.append(":method", "GET")
local body = assert(stream:get_body_as_string())
if headers:get ":status" ~= "200" then
    error(body)
end
print(body)

-- load_prog(config, "wlan0","generic")
print("Logging some data here")
