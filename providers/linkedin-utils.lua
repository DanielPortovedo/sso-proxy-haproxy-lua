local log = require("lua-scripts.logs")
local json = require("lunajson")
local error = require("lua-scripts.errors")
local utils = require("lua-scripts.utils")
local ltn12 = require("ltn12")
local http = require("socket.http")

local Linkedin = {}

local conf = {}

--- Initializes provider
---@param p_conf any Json object with provider configurations 
function Linkedin.initialize(p_conf)
    -- Read configurations
    log.log_info("Initializing google configurations")

    p_conf["client_id"] = utils.validate_type("client_id", p_conf["client_id"], "string")
    p_conf["client_secret"] = utils.validate_type("client_secret", p_conf["client_secret"], "string")
    p_conf["issuer"] = utils.validate_type("issuer", p_conf["issuer"], "string")
    p_conf["auth_uri"] = utils.validate_type("auth_uri", p_conf["auth_uri"], "string")
    p_conf["token_uri"] = utils.validate_type("token_uri", p_conf["token_uri"], "string")
    p_conf["public_key_uri"] = utils.validate_type("public_key_uri", p_conf["public_key_uri"], "string")

    log.log_info("Requesting google public key")
    log.log_request(p_conf["public_key_uri"], "GET")

    local response_body = {}
    local response, response_code, response_headers, response_status = http.request {
        url = p_conf["public_key_uri"],
        method = "GET",
        sink = ltn12.sink.table(response_body)
    }

    -- Check the response status code (200 for success)
    log.log_info("Validating response")
    if(response_code == 200) then
        local jsonBody = json.decode(table.concat(response_body))

        log.log_info("Request was sucessful. Loading information into memory")

        for _,v in pairs(jsonBody) do
            p_conf["public_key"] = v
        end

    else
        error.throw_error_and_exit("Request failed with status code: " .. response_code)
    end

    conf = p_conf
    return conf
end

function Linkedin.auth(current_context, global, web_app, applet, session_id)
    log.log_info("Building authentication request", current_context)

    local scope = web_app["scope"][1]

    for i=2,#web_app["scope"] do
        scope = scope .. " " .. web_app["scope"][i] 
    end

    local params = {
        client_id = conf["client_id"],
        redirect_uri = global["root_uri"] .. web_app["callback_uri"],
        response_type = "code",
        scope = scope,
        access_type = "online",
        state = session_id
    }

    log.log_info("Redirecting user to SSO", current_context)

    local urlAuth = conf["authorization_endpoint"] .. "?" .. utils.build_parameters(params)
    applet:set_status(302) -- Redirect code
    applet:add_header("Location", urlAuth)

    applet:start_response()
    applet:send("Redirecting to SSO")
end

function Linkedin.get_tokens(current_context, global, web_app, code)
    local params = {
        grant_type = "authorization_code",
        client_id = conf["client_id"],
        client_secret = conf["client_secret"],
        code = code,
        redirect_uri = global["root_uri"] .. web_app["callback_uri"]
    }

    local url_token = conf["token_endpoint"]
    local headers = {
        ['Content-Type'] = "application/x-www-form-urlencoded"
    }

    -- Perform the POST request
    local response_body = {}
    log.log_info("Performing request to obtaining access token ...", current_context)
    log.log_request(url_token, "POST", current_context)

    local response, response_code, response_headers, response_status = http.request {
        url = url_token,
        method = "POST",
        headers = headers,
        source = ltn12.source.string(utils.build_parameters(params)),
        sink = ltn12.sink.table(response_body)
    }

    return response_code, response_body
end

function Linkedin.populate_session(session_validity, confs_provider, json_body)
    local decoded_id_token

    local session = {
        ["exp"] = os.time() + session_validity,
        ["access_token"] = json_body["access_token"]
    }

    -- Validate id_token
    if json_body["id_token"] then
        decoded_id_token = utils.validate_jwt_token(json_body["id_token"], confs_provider)["payloaddecoded"]

        if not decoded_id_token then
            return false
        end

        session["name"] = decoded_id_token["name"]
        session["email"] = decoded_id_token["email"]
    end

    return session
end

-- Doesn't exist
function Linkedin.logout()
end

return Linkedin