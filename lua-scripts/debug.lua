local log = require("lua-scripts.logs")
local utils = require("lua-scripts.utils")
local debug = {}

local debug_mode = false
local total_sessions = 0
local total_authenticated_sessions = 0

function debug.initialize_debug()
    debug_mode = true
end

local function build_string_display_incoming_request_information(txn)
    local request_information = ""

    -- Display all headers from incoming request
    request_information = request_information .. "<h3><u>Headers</u></h3>"

    for k,v in pairs(txn:get_priv()) do
        if(type(v) == "table") then
            request_information = request_information .. "<b>" .. k .. ":</b> " .. v[0] .."</br>"
        else
            request_information = request_information .. "<b>" .. k .. ":</b> " .. tostring(v) .."</br>"
        end
    end

    -- Display all cookies from incoming request
    local cookie = utils.cookie_to_dict(txn:get_priv()["cookie"][0])

    request_information = request_information .. "<h3><u>Cookies</u></h3>"
    if(cookie ~= nil) then
        for k, v in pairs(cookie) do
            request_information = request_information .. "<b>" .. k .. ":</b> " .. tostring(v) .."</br>"
        end
    end

    return request_information
end

local function build_string_display_outgoing_request_information(request_headers)
    local request_information = ""

    -- Display all headers for outgoing request
    request_information = request_information .. "<h3><u>Headers</u></h3>"
    for k,v in pairs(request_headers) do
        if(type(v) == "table") then
            request_information = request_information .. "<b>" .. k .. ":</b> " .. v[0] .."</br>"
        else
            request_information = request_information .. "<b>" .. k .. ":</b> " .. tostring(v) .."</br>"
        end
    end

    -- Display all cookies for outgoing request
    local cookie = utils.cookie_to_dict(request_headers["cookie"][0])
    if(cookie ~= nil) then
        request_information = request_information .. "<h3><u>Cookies</u></h3>"
        for k, v in pairs(cookie) do
            request_information = request_information .. "<b>" .. k .. ":</b> " .. tostring(v) .."</br>"
        end
    end

    return request_information
end

--- This function displays:
--- 1. Number of session that didn't went throught the authentication
--- 2. Number of fully authenticated sessions (User authenticated against the idP)
--- 3. Total memory usage by Lua
local function build_string_user_sessions_information()
    local information = string.format([[
        <b>Number of existing sessions:</b> %d</br>
        <b>Number of existing authenticated sessions:</b> %d</br>
        <b>Lua memory usage:</b> %s</br>
    ]], total_sessions, total_authenticated_sessions, string.format("%.2f ", collectgarbage("count")/1024) .. " MB; " .. string.format("%.2f ", collectgarbage("count")) .. " KB;")

    return information
end

--- Displays all the stored information in a user session
local function build_string_user_session_details(user_info)
    local user_info_str = ""

    for k,v in pairs(user_info) do
        if type(v) == "table" then
            if #v > 0 then
                user_info_str = user_info_str .. "<b>" .. k .. " = </b>" .. v[1]

                for i=2,#v do
                    user_info_str = user_info_str .. "," .. v[i]
                end

                user_info_str = user_info_str .. "</br>"
            end
        else
            if v then
                user_info_str = user_info_str .. "<b>" .. k .. " = </b>" .. v .. "</br>"
            end
        end
    end

    return user_info_str
end

function debug.dump(txn, user_info)
    if debug_mode then

        local reply = txn:reply{
            status  = 200,
            reason  = "Debug Mode",
            headers = {
                ["content-type"]  = { "text/html" },
                ["cache-control"] = {"no-cache", "no-store" },
            }
        }

        local content = string.format(
            [[
                <html>
                <head><title>Debug Mode</title></head>
                    <body>
                        <pre style="font-size: 1.1rem;"><h1>Incoming Request</h1></pre>
                            %s
                        <pre style="font-size: 1.1rem;"><h1>Outgoing Request</h1></pre>
                            %s
                        <pre style="font-size: 1.1rem;"><h1>User Sessions</h1></pre>
                            %s
                        <pre style="font-size: 1.1rem;"><h1>User Session Details</h1></pre>
                            %s
                    </body>
                </html>
            ]], build_string_display_incoming_request_information(txn),
                build_string_display_outgoing_request_information(txn.http:req_get_headers()),
                build_string_user_sessions_information(),
                build_string_user_session_details(user_info)
        )

        reply:add_header("Content-Length", string.len(content))
        reply:set_body(content)
        txn:done(reply)
    end
end

function debug.add_user_authenticated_session(amount)
    total_authenticated_sessions = total_authenticated_sessions + amount
end

function debug.remove_user_authenticated_session(amount)
    total_authenticated_sessions = total_authenticated_sessions - amount
end

function debug.add_user_session(amount)
    total_sessions = total_sessions + amount
end

function debug.remove_user_session(amount)
    total_sessions = total_sessions - amount
end

return debug