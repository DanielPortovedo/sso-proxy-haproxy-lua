-- SPDX-FileCopyrightText: 2024 CERN
--
-- SPDX-License-Identifier: Apache-2.0

local log = require("lua-scripts.logs")
local error = {}

local function exit_program()
    log.log_info("Terminating program.")
    os.exit()
end

---Logs error message and sends error applet response
---@param msg string
---@param applet AppletHTTP 
function error.throw_applet_error_redirect(msg, applet, redirect_uri)
    log.log_error(msg)
    applet:set_status(302)
    applet:add_header("Location", redirect_uri)
    applet:start_response()
    applet:send(msg)
end

---This function logs a error message and will exit the program.
---@param msg string Error message
---@param func_name string|nil Function and line where error happened 
function error.throw_error_and_exit(msg, func_name)
    log.log_error(msg, func_name)
    exit_program()
end

---Logs error message and does os.exit()
---@param str_boolean any
function error.throw_wrong_format_boolean(key, str_boolean)
    log.log_error("Error while reading boolean value for key: " .. key ..  ". Invalid is value: " .. str_boolean)
    exit_program()
end

---Logs error message and does os.exit()
---@param str_number any
function error.throw_wrong_format_number(key, str_number)
    log.log_error("Error while reading number value for key " .. key .. ". Invalid is value: " .. str_number)
    exit_program()
end

---Logs error message and sets txn var to redirect user to authentication.
---@param msg string
---@param txn txn
function error.throw_txn_error(msg, txn)
    log.log_error(msg)
    txn:set_var("txn.not_authorized", "invalid-token")
end

return error