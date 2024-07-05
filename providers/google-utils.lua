-- SPDX-FileCopyrightText: 2024 CERN
--
-- SPDX-License-Identifier: Apache-2.0

-- Follow this guide to create a app within google https://developers.google.com/identity/protocols/oauth2/web-server
local log = require("lua-scripts.logs")
local json = require("lunajson")
local error = require("lua-scripts.errors")
local utils = require("lua-scripts.utils")
local ltn12 = require("ltn12")
local http = require("socket.http")

local Google = {}

local conf = {}

--- Initializes provider
---@param p_conf any Json object with provider configurations 
function Google.initialize(p_conf)
    -- Read configurations
    log.log_info("Initializing google configurations")

    p_conf["client_id"] = utils.validate_type("client_id", p_conf["client_id"], "string")
    p_conf["client_secret"] = utils.validate_type("client_secret", p_conf["client_secret"], "string")
    p_conf["issuer"] = utils.validate_type("issuer", p_conf["issuer"], "string")
    p_conf["auth_uri"] = utils.validate_type("auth_uri", p_conf["auth_uri"], "string")
    p_conf["token_uri"] = utils.validate_type("token_uri", p_conf["token_uri"], "string")
    p_conf["public_key_uri"] = utils.validate_type("public_key_uri", p_conf["public_key_uri"], "string")
    --p_conf["logout_uri"] = utils.validate_type("logout_uri", p_conf["logout_uri"], "string")

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

function Google.auth(current_context, global, web_app, applet, session_id)
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

    local urlAuth = conf["auth_uri"] .. "?" .. utils.build_parameters(params)
    applet:set_status(302) -- Redirect code
    applet:add_header("Location", urlAuth)

    applet:start_response()
    applet:send("Redirecting to SSO")
end

function Google.get_tokens(current_context, global, web_app, code)
    local params = {
        grant_type = "authorization_code",
        client_id = conf["client_id"],
        client_secret = conf["client_secret"],
        code = code,
        redirect_uri = global["root_uri"] .. web_app["callback_uri"]
    }

    local urlToken = conf["token_uri"]
    local headers = {
        ['Content-Type'] = "application/x-www-form-urlencoded"
    }

    -- Perform the POST request
    local response_body = {}
    log.log_info("Performing request to obtaining access token ...", current_context)
    log.log_request(urlToken, "POST", current_context)

    local response, response_code, response_headers, response_status = http.request {
        url = urlToken,
        method = "POST",
        headers = headers,
        source = ltn12.source.string(utils.build_parameters(params)),
        sink = ltn12.sink.table(response_body)
    }

    return response_code, response_body
end

function Google.populate_session(session_validity, confs_provider, json_body, confs_webapp, current_context)
    local decoded_id_token

    local session = {
        ["exp"] = os.time() + session_validity,
        ["access_token"] = json_body["access_token"]
    }

    -- Validate id_token
    if json_body["id_token"] then
        session["id_token"] = json_body["id_token"]

        decoded_id_token = utils.validate_jwt_token(json_body["id_token"], confs_provider)["payloaddecoded"]

        if not decoded_id_token then
            return false
        end

        -- Save all claim names for cookies
        -- Loop through custom cookies
        for _,custom_cookie in pairs(confs_webapp["custom_cookies"]) do
            -- Extract claim
            local val = decoded_id_token[custom_cookie["claim_name"]]

            -- If claim exists, store it
            if val ~= nil then
                session[custom_cookie["claim_name"]] = val
            else
                log.log_warning("Claim '" .. custom_cookie["claim_name"] .. "' not found in id_token while populating user session", "Google.populate_session", current_context)
            end
        end
    end

    return session
end

function Google.logout(session, current_context)
    local response_body = {}

    local params = {
        token = session["access_token"]
    }
    local headers = {
        ['Content-Type'] = "application/x-www-form-urlencoded"
    }

    local response, response_code, response_headers, response_status = http.request {
        url = conf["logout_uri"] .. "?" .. utils.build_parameters(params),
        method = "GET",
        headers = headers,
        sink = ltn12.sink.table(response_body)
    }

    -- For some reason gooogle is not finding the access token
    -- To be checked
    if response_code == 200 then
        log.log_info("Google Access Token revoked", current_context)
    else
        log.log_error("Failed to revoke google access token", current_context)
    end
end

return Google