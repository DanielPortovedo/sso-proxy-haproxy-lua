-- SPDX-FileCopyrightText: 2024 CERN
--
-- SPDX-License-Identifier: Apache-2.0

local logs = {}

---Logs a INFO message in current application context (if specified)
---@param msg string
---@param current_context string|nil Current application context
function logs.log_info(msg, current_context)
    local final = "[INFO]  " .. os.date('%Y-%m-%d %H:%M:%S')

    if (current_context ~= nil) then
        final = final .. " : [" .. current_context .. "]"
    end

    print(final .. " : " .. msg)
end

---Logs a WARN message in current application context (if specified)
---@param msg string
---@param current_context string|nil Current application context
---@param func_name string|nil Function where event happened
function logs.log_warning(msg, func_name, current_context)
    local final = "[WARN]  " .. os.date('%Y-%m-%d %H:%M:%S')
    
    if (func_name ~= nil) then
        final = final .. " : Func[ " .. func_name .. " ]"
    end

    if (current_context ~= nil) then
        final = final .. " : [" .. current_context .. "]"
    end

    print(final .. " : " .. msg)
end

---Logs a ERROR message in current application context (if specified)
---@param msg string
---@param current_context string|nil Current application context
---@param func_name string|nil Function where event happened
function logs.log_error(msg, func_name, current_context)
    local final = "[ERROR] " .. os.date('%Y-%m-%d %H:%M:%S')
    
    if (func_name ~= nil) then
        final = final .. " : Func[ " .. func_name .. " ]"
    end

    if (current_context ~= nil) then
        final = final .. " : [" .. current_context .. "]"
    end

    print(final .. " : " .. msg)
end

---Logs a request in current application context (if specified)
---@param request string URL
---@param method string Http method (GET, POST, ...)
---@param current_context string|nil Current application context
function logs.log_request(request, method, current_context)
    if(current_context == nil) then
        print("[REQ]   " .. os.date('%Y-%m-%d %H:%M:%S') .. " : "  ..  "[" .. method .. "] " .. request)
    else
        print("[REQ]   " .. os.date('%Y-%m-%d %H:%M:%S') .. " : [" .. current_context .. "] : [" .. method .. "] " .. request)
    end
end

return logs