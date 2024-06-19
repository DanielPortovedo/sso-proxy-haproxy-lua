local log = require("lua-scripts.logs")
local utils = require("lua-scripts.utils")
local debug = {}

local debug_mode = false
local total_sessions = 0
local total_authenticated_sessions = 0

local all_configurations

function debug.initialize_debug(configurations)
    debug_mode = true
    all_configurations = configurations
end

local function build_string_display_request_information(request)
    local request_information = ""
    local cookie = utils.cookie_to_dict(request["cookie"][0])
    
    request_information = request_information .. "<h3><u>Headers</u></h3>"

    for k1,v1 in pairs(request) do
        if(type(v1) == "table") then
            request_information = request_information .. "<b>" .. k1 .. ":</b> " .. utils.dump_table(v1) .."</br>"
        else
            request_information = request_information .. "<b>" .. k1 .. ":</b> " .. tostring(v1) .."</br>"
        end
    end

    if(cookie ~= nil) then
        request_information = request_information .. "<h3><u>Cookies</u></h3>"
        for k, v in pairs(cookie) do
            request_information = request_information .. "<b>" .. k .. ":</b> " .. tostring(v) .."</br>"
        end
    end

    return request_information
end

local function build_string_user_sessions_information()
    local information = string.format([[
        <b>Number of existing sessions:</b> %d</br>
        <b>Number of existing authenticated sessions:</b> %d</br>
        <b>Lua memory usage:</b> %s</br>
    ]], total_sessions, total_authenticated_sessions, string.format("%.2f ", collectgarbage("count")/1024) .. " MB; " .. string.format("%.2f ", collectgarbage("count")) .. " KB;")

    return information
end

function debug.dump(txn)
    if debug_mode then

        local reply = txn:reply{
            status  = 200,
            reason  = "Debug Mode",
            headers = {
                ["content-type"]  = { "text/html" },
                ["cache-control"] = {"no-cache", "no-store" },
            }
        }

        local content = string.format([[
            <html>
            <head><title>Debug Mode</title></head>
                <body>
                    <pre style="font-size: 1.1rem;"><h1>Displaying Information from Request</h1></pre>
                        %s
                    <pre style="font-size: 1.1rem;"><h1>Displaying Information from User Sessions</h1></pre>
                        %s
                </body>
            </html>
        ]], build_string_display_request_information(txn.http:req_get_headers()),
            build_string_user_sessions_information())

        reply:add_header("Content-Length", string.len(content))
        reply:set_body(content)
        txn:done(reply)
    end
end

function debug.add_user_authenticated_session()
    total_authenticated_sessions = total_authenticated_sessions + 1
end

function debug.remove_user_authenticated_session()
    total_authenticated_sessions = total_authenticated_sessions - 1
end

function debug.add_user_session()
    total_sessions = total_sessions + 1
end

function debug.remove_user_session()
    total_sessions = total_sessions - 1
end

return debug