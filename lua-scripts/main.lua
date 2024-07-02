package.path = package.path .. ";/usr/share/lua/lua5.4/?.so" .. ";/usr/local/share/lua/5.4/?.lua"

local utils = require("lua-scripts.utils")
local log = require("lua-scripts.logs")
local error = require("lua-scripts.errors")
local constants = require("lua-scripts.constants")
local debug = require("lua-scripts.debug")
local json = require("lunajson")

local provider

local confs = {
    ["provider"] = {},
    ["global"] = {},
    ["web_apps"] = {}
}

local current_context = ""
local contextsApplicationsPaths = {}

local user_sessions = {}

local function read_configuration_file()
    log.log_info("Extracting current working directory")
    -- Extract configuration files name
    local handle = io.popen('pwd')
    local pwd

    if(handle ~= nil) then
        pwd = string.sub(handle:read('*a'), 1, -2) -- Get everything except the '\n'
        handle:close()
    else
        error.throwErrorAndExit("Failed to extract current working directory")
    end

    log.log_info("Current working directory is \'" .. pwd .. "\'")

    log.log_info("Reading configuration file in '" .. pwd .. "/configs.json'")
    local f = utils.read_file(pwd .. "/configs.json")

    log.log_info("Parsing configuration file")
    confs = json.decode(f)
end

---This function validates the global configurations.
local function validate_global_configurations()
    if confs["global"] == nil then
        error.throw_error_and_exit("Configuration file doesn't have 'global' section.")
    end

    local s_confs = confs["global"]

    -- Validate types and replace with defaults if needed
    s_confs["root_uri"] = utils.validate_type("root_uri", s_confs["root_uri"], "string")
    s_confs["public_uris"] = utils.validate_type("public_uris", s_confs["public_uris"], "table", {})
    s_confs["debug_mode_enabled"] = utils.validate_type("debug_mode_enabled", s_confs["debug_mode_enabled"], "boolean", false)

    -- Ensure that root_uri doesn't end with /
    if utils.is_last_char_equal(s_confs["root_uri"], "/") then
        s_confs["root_uri"] = string.sub(s_confs["root_uri"], 1, -2)
    end

    -- Update configurations
    confs["global"] = s_confs
end

local function validate_applications_configurations()
    if confs["web_apps"] == nil then
        error.throw_error_and_exit("Configuration file doesn't have 'web_apps' section.")
    end

    -- web_application configurations
    local wa_confs = confs["web_apps"]

    for c, _ in pairs(wa_confs) do
        table.insert(contextsApplicationsPaths, c)

        wa_confs[c]["home_page_uri"] = utils.validate_type("home_page_uri", wa_confs[c]["home_page_uri"], "string", confs["global"]["root_uri"])
        wa_confs[c]["error_page_uri"] = utils.validate_type("error_page_uri", wa_confs[c]["error_page_uri"], "string")
        wa_confs[c]["callback_uri"] = utils.validate_type("callback_uri", wa_confs[c]["callback_uri"], "string")
        wa_confs[c]["logout_uri"] = utils.validate_type("logout_uri", wa_confs[c]["logout_uri"], "string")
        wa_confs[c]["scope"] = utils.validate_type("scope", wa_confs[c]["scope"], "table")
        wa_confs[c]["headers_to_be_removed"] = utils.validate_type("headers_to_be_removed", wa_confs[c]["headers_to_be_removed"], "table", {})
        wa_confs[c]["require_authentication"] = utils.validate_type("require_authentication", wa_confs[c]["require_authentication"], "boolean", true)
        wa_confs[c]["session_cookie_name"] = utils.validate_type("session_cookie_name", wa_confs[c]["session_cookie_name"], "string", "ha-session-id" .. wa_confs[c]["callback_uri"]:gsub("/", "-"))
        wa_confs[c]["session_cookie_httponly"] = utils.validate_type("session_cookie_httponly", wa_confs[c]["session_cookie_httponly"], "boolean", true)
        wa_confs[c]["session_cookie_secure"] = utils.validate_type("session_cookie_secure", wa_confs[c]["session_cookie_secure"], "boolean", true)
        wa_confs[c]["session_cookie_samesite"] = utils.validate_type("session_cookie_samesite", wa_confs[c]["session_cookie_samesite"], "string", "Lax")
        wa_confs[c]["session_validity"] = utils.validate_type("session_validity", wa_confs[c]["session_validity"], "number", 3600)
        wa_confs[c]["custom_cookies"] = utils.validate_type("custom_cookies", wa_confs[c]["custom_cookies"], "table", {})
        wa_confs[c]["custom_headers"] = utils.validate_type("custom_headers", wa_confs[c]["custom_headers"], "table", {})
    end

    confs["web_apps"] = wa_confs
    current_context = contextsApplicationsPaths[1]
end

local function validate_provider()
    if confs["provider"] == nil then
        error.throw_error_and_exit("Configuration file doesn't have 'provider' section.")
    end

    -- Provider configurations
    local p_conf = confs["provider"]

    p_conf["name"] = utils.validate_type("name", p_conf["name"], "string")

    if p_conf["name"] == constants.GOOGLE then
        provider = require("providers.google-utils")
    elseif p_conf["name"] == constants.LINKEDIN then
        provider = require("providers.linkedin-utils")
    else
        error.throwErrorAndExit("Invalid 'name' value. Please select one of the following: 'google'")
    end

    confs["provider"] = provider.initialize(p_conf)
end

local function init()
    log.log_info("Application initializing")

    math.randomseed(os.time(), math.floor(os.clock() * 1000000))

    log.log_info("Reading configuration file")
    read_configuration_file()

    log.log_info("Validating global configurations")
    validate_global_configurations()

    log.log_info("Validating applications configurations")
    validate_applications_configurations()

    log.log_info("Validating provider")
    validate_provider()

    --TODO: finish debug
    if confs["global"]["debug_mode_enabled"] then
        debug.initialize_debug({})
    end

    log.log_info("Current application paths are:" ..  utils.dump_table(contextsApplicationsPaths))
    log.log_info("Successfully inialized application")
end

local function extract_uris(txn)
    local current_path = txn.f:path()

    current_context = utils.validate_if_context_path_exists(utils.get_array_of_possible_contexts(current_path), contextsApplicationsPaths)
    if(current_context == "") then
        error.throwTxnError("Given context application path doesn't exist.", txn)
        return
    end

    local contextCallback = confs["web_apps"][current_context]["callback_uri"]
    local contextLogout = confs["web_apps"][current_context]["logout_uri"]

    txn:set_var("txn.context", current_context)
    txn:set_var("txn.context_callback", contextCallback)
    txn:set_var("txn.context_logout", contextLogout)

end

local function is_public_path(txn)
    local current_path = txn.f:path()

    if utils.table_contains_string(confs["global"]["public_uris"], current_path) then
        txn:set_var("txn.is_public_path", 1)
    end
end

local function callback(applet)
    log.log_info("Callback request received", current_context)

    current_context = applet:get_var("txn.context")

    log.log_info("Extracting user session code", current_context)
    local extractedParams = utils.extract_parameters(applet.qs)

    local code = extractedParams.code
    local state = extractedParams.state

    if user_sessions[state] == nil then
        error.throw_applet_error_redirect("State doesn't match. Please try again.", applet, confs["web_apps"][current_context]["error_page_uri"])
        return
    end

    local redirect_uri = user_sessions[state]["persist_request"]

    local response_code, response_body = provider.get_tokens(current_context, confs["global"], confs["web_apps"][current_context], code)

    if response_code == 200 then
        log.log_info("Request was sucessful, extracting tokens", current_context)
        local json_body = json.decode(table.concat(response_body))

        -- Kill previous session
        user_sessions[state] = nil

        -- Create new session with updated information
        local session_id = utils.generate_session_id(32)

        -- Populate session with user information
        user_sessions[session_id] = provider.populate_session(
            confs["web_apps"][current_context]["session_validity"], confs["provider"], json_body, confs["web_apps"][current_context], current_context
        )

        if not user_sessions[session_id] then
            error.throw_applet_error_redirect("Failed populating user session", applet, confs["web_apps"][current_context]["error_page_uri"])
            return
        end

        -- Redirect user to previous request before starting authentication and add cookie session
        local set_cookie = confs["web_apps"][current_context]["session_cookie_name"] .. "=" .. session_id ..
        "; SameSite=" .. confs["web_apps"][current_context]["session_cookie_samesite"] ..
        "; Path=" .. current_context

        if confs["web_apps"][current_context]["session_cookie_httponly"] then
            set_cookie = set_cookie .. "; HttpOnly"
        end

        if confs["web_apps"][current_context]["session_cookie_secure"] then
            set_cookie = set_cookie .. "; Secure"
        end

        applet:add_header("Set-Cookie", set_cookie)

        applet:set_status(302)
        applet:add_header("Location", redirect_uri)
        applet:start_response()
        applet:send("Redirecting...")
        return
    end

    error.throw_applet_error_redirect("Failed to obtain tokens from the identity provider", applet, confs["web_apps"][current_context]["error_page_uri"])
end

---Is called when receives a requests. 
---It will validate the session
local function validate_cookie(txn)
    current_context = txn:get_var("txn.context")

    -- Extract cookie
    local cookie_raw = txn.http:req_get_headers()["cookie"]

    -- Cookie not found user will be redirected to obtain one
    if cookie_raw == nil then
        error.throw_txn_error("Cookie not found while trying to validate it.", txn)
        return
    end

    -- Parse cookie string to a dictionary
    local cookie_dict = utils.cookie_to_dict(cookie_raw[0])

    -- If error while parsing cookie to dict
    if cookie_dict == nil then
        error.throw_txn_error("Failed to parse cookie into dictionary.", txn)
        return
    end

    -- Extract cookie authorization value
    local session_id = cookie_dict[confs["web_apps"][current_context]["session_cookie_name"]]

    -- Validate if Authorization cookie exists
    if session_id == nil then
        error.throw_txn_error("Authentication cookie not found when trying to validate it.", txn)
        return
    end

    -- Extract user info
    local user_info = user_sessions[session_id]

    -- If userInfo doesnt exists means user isn't logged in
    if user_info == nil then
        error.throw_txn_error("User doesn't have a session.", txn)
        return
    end

    if user_info["exp"] == nil or utils.expiration_is_valid(user_info["exp"]) == false then
        error.throw_txn_error("Session is expired.", txn)
        return
    end

    log.log_info("Token validated", current_context)

    -- Add/sanitize cookies/headers for the request
    utils.drop_cookies(txn, confs["web_apps"][current_context])
    utils.add_cookies(txn, user_info, confs["web_apps"][current_context])
    utils.add_headers(txn, user_info, confs["web_apps"][current_context])

    -- Dump request information into logs
    --[[ if confs["global"]["debug_mode_enabled"] then
        --debug.dump_headers()
    end ]]
end

---Is called when receives a logout request.
---It will remove session from lua memory and redirect user to homePage.
local function logout(applet)
    current_context = applet:get_var("txn.context")

    -- Extract cookie
    local cookie_raw = applet.headers["cookie"]

    -- Cookie not found user will be redirected to obtain one
    if(cookie_raw == nil) then
        error.throw_applet_error_redirect("Cookie not found for logout", applet, confs["web_apps"][current_context]["in_case_of_error_redirect_path"])
        return
    end

    -- Parse cookie string to a dictionary
    local cookie_dict = utils.cookie_to_dict(cookie_raw[0])

    -- If error while parsing cookie to dict
    if(cookie_dict == nil) then 
        error.throw_applet_error_redirect("Some error happened while parsing cookie while loging out", applet, confs["web_apps"][current_context]["in_case_of_error_redirect_path"])
        return
    end

    -- Extract cookie authorization value
    local session_id = cookie_dict[confs["web_apps"][current_context]["session_cookie_name"]]

    -- Validate if Authorization cookie exists
    if(session_id == nil) then
        error.throw_applet_error_redirect("Authentication cookie not found when trying to validate it", applet, confs["web_apps"][current_context]["in_case_of_error_redirect_path"])
        return
    end

    -- Validate if user exists
    if(user_sessions[session_id] == nil) then
        error.throw_applet_error_redirect("User doesn't have a session", applet, confs["web_apps"][current_context]["in_case_of_error_redirect_path"])
        return
    end

    -- TO DO
    --provider.logout(user_sessions[session_id], current_context)

    log.log_info("Deleted user session with id: " .. session_id, current_context)

    user_sessions[session_id] = nil

    log.log_info("Redirecting user to SSO to be logged out", current_context)

    applet:set_status(302)
    applet:add_header("Location", confs["web_apps"][current_context]["home_page_uri"])
    applet:start_response()
    applet:send("Redirecting...")

    log.log_info("Local session ended", current_context)
end

--- Requests a authentication code for the current context.
--- If context doesn't exist throws error.
--- Creates a cookie to persist the current path of the user.
local function auth_redirect(applet)
    current_context = applet:get_var("txn.context")

    log.log_info("Detected user without authentication cookie", current_context)

    -- Generate the session for the user
    local session_id = utils.generate_session_id(32)
    log.log_info("New session created", current_context)

    -- Store the current request to persist it
    local persist_request_str = confs["global"]["root_uri"] .. applet.path

    -- Store the parameters of the request if they exist
    if(string.len(applet.qs) > 0) then
        persist_request_str = persist_request_str .. "?" .. applet.qs
    end

    user_sessions[session_id] = {
        persist_request = persist_request_str
    }

    provider.auth(current_context, confs["global"], confs["web_apps"][current_context], applet, session_id)
end

local function need_authentication(txn)
    -- Least privilege rule (assume that always needs authentication)
    txn:set_var("txn.need_authentication", 1)

    current_context = txn:get_var("txn.context")

    if(confs["web_apps"][current_context]["require_authentication"] == false) then
        txn:set_var("txn.need_authentication", 0)
    end
end

local function remove_headers(txn)
    current_context = txn:get_var("txn.context")

    -- Remove defined headers
    if current_context ~= nil then
        for _,v in pairs(confs["web_apps"][current_context]["headers_to_be_removed"]) do
            txn.http:req_del_header(v)
        end
    end
end

core.register_init(init)
core.register_action("extract_uris", {"http-req"}, extract_uris)
core.register_action("is_public_path", {"http-req"}, is_public_path)
core.register_action("need_authentication", {"http-req"}, need_authentication)
core.register_service("callback", "http", callback)
core.register_action("validate_cookie", {"http-req"}, validate_cookie)
core.register_service("logout", "http", logout)
core.register_service("auth_redirect", "http", auth_redirect)
core.register_action("remove_headers", {"http-req"}, remove_headers)
core.register_action("debug", {"http-req"}, debug.dump)