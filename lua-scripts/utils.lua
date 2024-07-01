local error = require("lua-scripts.errors")
local log = require("lua-scripts.logs")
local url = require("socket.url")
local json = require("lunajson")
local mime = require("mime")
local constants = require("lua-scripts.constants")
local openssl = {
    pkey = require("openssl.pkey"),
    digest = require("openssl.digest")
}


local utils = {}

---This function checks whether the last char of a string is equal to another char.
---@param str string String to be evaluated 
---@param char string Char to be compared
---@return boolean
function utils.is_last_char_equal(str, char)
    if (str == nil or str == "") then
        return false
    end

    if (string.len(char) ~= 1) then
        error.throwErrorAndExit("Detected a str and not a char", "utils.is_last_char_equal:25")
        return false
    end

    return string.sub(str, string.len(str)) == char
end

---Dumps everything inside a table and prints as dictionary. Debug feature.
---@param o table
---@return unknown #Recursive return or nothing
function utils.dump_dictionary(o)
    if type(o) == 'table' then
       local s = '{ '
       for k,v in pairs(o) do
          if type(k) ~= 'number' then k = '"'..k..'"' end
          s = s .. '['..k..'] = ' .. utils.dump_dictionary(v) .. ','
       end
       return s .. '} '
    else
       return tostring(o)
    end
end

---This function will parse contents of a table total the following format:
--- ["content1", "content2", "content3"], Debug feature.
---@param table any
function utils.dump_table(table) 
    local s = "["
    for _,v in pairs(table) do
        s = s .. "\"" .. v .. "\"" .. ", "
    end
    s = string.gsub(s, ', $', ']')
    return s
end

---Reads a file
---@param file string Path to the file
---@return string # File content
function utils.read_file(file)
    log.log_info("Reading file '" .. file .. "'")

    local f = io.open(file, "rb")
    local content

    if f then
        content = f:read("*all")
        f:close()
    else
        error.throw_error_and_exit("Configuration file '" .. file .. "' doesn't exist")
    end

    return content
end

---Reverts a table
---@param arr table Table to be reverted
---@return table #Reverted table
local function reverte_array(arr)
    local n = #arr
    for i = 1, math.floor(n / 2) do
        arr[i], arr[n - i + 1] = arr[n - i + 1], arr[i]
    end

    return arr
end

---This function will iterate trought a path and generate a array with possible contexts uri
---@param path string Path to be iterated
---@return table #Table withy the possible contexts 
function utils.get_array_of_possible_contexts(path)
    local possible_contexts = {}

    local i = 2 -- ignore first '/'
    local path_size = #path

    -- Ignore last '/' if it exists
    if(string.byte(path, #path) == 47) then
        path_size = path_size - 1
    end

    while i <= path_size do
        -- char '/' == byte 47
        if(string.byte(path, i) == 47) then
            table.insert(possible_contexts,string.sub(path, 1, i-1))
        end
        i = i + 1
    end
    table.insert(possible_contexts, string.sub(path, 1, path_size))

    -- Case where is only the root path
    if(possible_contexts[1] == "") then
        possible_contexts[1] = "/"
    end

    return reverte_array(possible_contexts)
end

---Loops through array to find the given string. 
---@param items table table of strings
---@param test_str string string to look for
---@return boolean #True - String is in table | False - String is not in the table
function utils.table_contains_string(items, test_str)
    for _,item in pairs(items) do

      -- strip whitespace
      item = item:gsub("%s+", "")
      test_str = test_str:gsub("%s+", "")

      if item == test_str then
        return true
      end
    end

    return false
end

---Validates if the possible contexts belongs to the applications context
---@param possible_contexts_from_path table Contains all possible context paths from one url path
---@param existing_contexts table Contains all context paths from the implemented applications. Comes from configuration files.
---@return string #Returns the current context.
function utils.validate_if_context_path_exists(possible_contexts_from_path, existing_contexts)
    -- Validate first for every context path besides '/'
    for _,v in pairs(possible_contexts_from_path) do
        if(utils.table_contains_string(existing_contexts, v) == true) then
            return v
        end
    end

    -- Validate for '/'
    if(utils.table_contains_string(existing_contexts, "/") == true) then
        return "/"
    end

    return ""
end

---Validates if provided date is or not expired
---@param exp integer Date to be evaluated.
---@return boolean #True - Date not expired | False - Date expired
function utils.expiration_is_valid(exp)
    return os.difftime(exp, core.now().sec) > 0
end

---Validates rs256 signature. TO BE DONE
---@param token any JWT token
---@param public_key string Public key as string
---@return boolean #True - Valid | False - Not Valid
--- Adapted from: https://github.com/haproxytech/haproxy-lua-oauth/blob/master/lib/jwtverify.lua
function utils.rs256_signature_is_valid(token, public_key)
    local digest = openssl.digest.new('SHA256')
    digest:update(token.header .. '.' .. token.payload)

    print(token.signaturedecoded)

    --local vkey = openssl.pkey.new(publicKey)

    local vkey = openssl.pkey.new({
        alg = 'rsa',
        n = public_key["n"],
        e = public_key["e"]
    })

    local is_verified = vkey:verify(token.signaturedecoded, digest)

    return is_verified
end

---Validates the audience
---@param aud string|table String or table coming from decoded jwt
---@param expected_audience_param string Coming from the configuration file
---@return boolean #True - Audience match | False - Audience dont match
--- Adapted from: https://github.com/haproxytech/haproxy-lua-oauth/blob/master/lib/jwtverify.lua
function utils.audience_is_valid(aud, expected_audience_param)
    -- Validate if incoming audience is string and if it is simply compare it
    if(type(aud) == "string") then
        return aud==expected_audience_param
    end

    return utils.table_contains_string(aud, expected_audience_param)
end

---Builds URL parameters.
---@param params table Table with all parameters to be included.
---@return string #Built url with parameters
function utils.build_parameters(params)
    local encoded_params = {}
    for key, value in pairs(params) do
        if type(value) == "table" then
            -- If it's a list of strings
            for _, item in pairs(value) do
                table.insert(encoded_params, url.escape(key) .. "=" .. url.escape(item))
            end
        else
            -- If it's a single string, treat it as such
            table.insert(encoded_params, url.escape(key) .. "=" .. url.escape(value))
        end
    end
    return table.concat(encoded_params, "&")
end

---Parses a cookie to a dictionary
---@param cookie string Cookie to be parsed
---@return table|nil #Table if everything went well or nil if cookie couldn't be parsed.
function utils.cookie_to_dict(cookie)
    local dict = {}

    for key, value in string.gmatch(cookie, "([^=;]+)=([^;]*)") do
        key = string.gsub(key, "%s", "") -- Remove spaces from key
        if key==nil or not value==nil then
            log.logInfo("Cookie is improperly formatted: " .. (key or "nil") .. "=" .. (value or "nil"))
            return nil
        end

        if dict[key] == nil then
            dict[key] = value
        end
    end

    return dict
end

local charset = {}  do -- [0-9a-zA-Z]
    for c = 48, 57  do table.insert(charset, string.char(c)) end
    for c = 65, 90  do table.insert(charset, string.char(c)) end
    for c = 97, 122 do table.insert(charset, string.char(c)) end
end

function utils.generate_session_id(length)
    if not length or length <= 0 then return '' end

    local sessionId = {}
    for i = 1, length do
        table.insert(sessionId, charset[math.random(1, #charset)])
    end

    return table.concat(sessionId)
end

---Function to extract parameters from URL and return it as dictionary.
---@param uri string URI to be read and extracted parameters.
---@return table #Parameters in for of dictionary
function utils.extract_parameters(uri)
    local params = {}
    for key, value in uri:gmatch("([^&]+)=([^&]+)") do
        -- URL decode key and value (replace '+' with ' ' and '%xx' with corresponding characters)
        local k = key:gsub('+', ' '):gsub('%%(%x%x)', function(h) return string.char(tonumber(h, 16)) end)
        local v = value:gsub('+', ' '):gsub('%%(%x%x)', function(h) return string.char(tonumber(h, 16)) end)
        params[k] = v
    end
    return params
end

local function b64_decode(string)
    -- replace - and _
    local b64_formated_string = string:gsub('[-]', '+'):gsub('[_]', '/')

    return (mime.unb64(b64_formated_string .. b64_formated_string.rep('=', 3 - ((#b64_formated_string - 1) % 4))))
end

---Decodes a Json Web Token (jwt)
---@param jwt string JWT with 3 sections **{header | payload | signature}** separated by a dot '.'
---@return any|nil #Decoded token with type object that contains **{headerdecoded | payloaddecoded | signaturedecoded}**. Or nil in case JWT is improperly formated.
--- Adapted from: https://github.com/haproxytech/haproxy-lua-oauth/blob/master/lib/jwtverify.lua
function utils.decode_jwt(jwt, applet, redirect_uri)
    local header_fields = core.tokenize(jwt, ".")

    if #header_fields ~= 3 then
        error.throw_applet_error_redirect("Improperly formated jwt token. Should be 3 token sections.", applet, redirect_uri)
        return nil
    end

    local token = {}

    token.header = header_fields[1]
    token.headerdecoded = json.decode(b64_decode(token.header))

    token.payload = header_fields[2]
    token.payloaddecoded = json.decode(b64_decode(token.payload))

    token.signaturedecoded = b64_decode(header_fields[3])

    return token
end

---Validates jwt token properties: signature, issuer, audience and expiration
---@param token any Decoded JWT
---@param conf_p table Configurations of the provider that must contain the pub_key, issuer and audience
---@return boolean|table #Table decoded_token - If token is valid | False - If token is not valid
function utils.validate_jwt_token(token, conf_p)
    local decoded_token = utils.decode_jwt(token)

    local pub_key = conf_p["public_key"][1]
    local issuer = conf_p["issuer"]
    local aud = conf_p["client_id"]

    if(decoded_token == nil) then
        log.log_error("JWT token could not be decoded.")
        return false
    end

    -- TODO: Validate signature
    --[[ if utils.rs256_signature_is_valid(decoded_token, pub_key) == false then
        log.log_error("JWT signature not valid.")
        return false
    end ]]

    -- Verify that the token is not expired
    if utils.expiration_is_valid(decoded_token.payloaddecoded.exp) == false then
        log.log_error("JWT token is expired.")
        return false
    end

    -- Verify the issuer
    if issuer ~= nil and decoded_token.payloaddecoded.iss ~= issuer then
        log.log_error("JWT issuer not valid.")
        return false
    end

    -- Verify the audience
    if aud ~= nil and utils.audience_is_valid(decoded_token.payloaddecoded.aud, aud) == false then
        log.log_error("JWT audience not valid.")
        return false
    end

    return decoded_token
end

--- This function will validate the type of a value.
--- Its main porpose is to validate the configuration file.
--- If `default_value` is passed to this function that it's assumed that the `value` is not mandatory to exist.
---@param key string Key for the corresponding value
---@param value string Value to be validated and parsed
---@param value_type string Desired type to parse
---@param default_value any Default value
---@return any #Any
function utils.validate_type(key, value, value_type, default_value)
    if value ~= nil then
        if type(value) == value_type then
            return value
        else
            error.throw_error_and_exit("Value type doesn't not match for key '" .. key ..
            "' . Is expected '" .. value_type .. "' and got '" .. type(value) .. "'")
        end
    else
        if default_value ~= nil then
            return default_value
        else
            error.throw_error_and_exit("Value for the key '" .. key .. "' was not found")
        end
    end
end

-- This function is used to drop cookies so they are not sent to the backend
function utils.drop_cookies(txn, confs_webapp)
    -- Extract cookie from request
    local cookie = txn.http:req_get_headers()["cookie"]

    -- Parse cookie string to dictionary
    local cookie_dict = utils.cookie_to_dict(cookie[0])

    -- Failed to parse cookie to dictionary
    if cookie_dict == nil then
        return nil
    end

    -- Extract protected cookie keys
    local protected_cookie_keys = {}
    for _,custom_cookie in pairs(confs_webapp["custom_cookies"]) do
        local cookie_key = custom_cookie["cookie_name"]

        if cookie_key == nil then
            cookie_key = "ha_proxy_" .. custom_cookie["claim_name"]
        end

        table.insert(protected_cookie_keys, cookie_key)
    end

    -- Remove cookies from the dictionary
    for _,v in pairs(protected_cookie_keys) do
        cookie_dict[v] = nil
    end

    -- Rebuild cookie
    cookie = ""
    for k,_ in pairs(cookie_dict) do
        if(cookie_dict[k] ~= nil) then
            cookie = cookie .. k .. "=" .. cookie_dict[k] .. ";"
        end
    end

    txn.http:req_set_header("cookie", cookie)
end

-- Add cookies to the request
function utils.add_cookies(txn, user_info, confs_webapp)
    -- Extract cookie from request
    local cookie = txn.http:req_get_headers()["cookie"]

    -- Parse cookie string to dictionary
    local cookie_dict = utils.cookie_to_dict(cookie[0])

    -- Failed to parse cookie to dictionary
    if cookie_dict == nil then
        return nil
    end

    -- load cookies to be added to the request
    local cookies_to_add = {}
    for _,custom_cookie in pairs(confs_webapp["custom_cookies"]) do
        local cookie_key = custom_cookie["cookie_name"]
        local cookie_value = user_info[custom_cookie["claim_name"]]

        if cookie_key == nil then
            cookie_key = "HA_PROXY_" .. custom_cookie["claim_name"]
        end

        if cookie_value ~= nil then
            cookies_to_add[cookie_key] = cookie_value
        end
    end

    -- Add cookies to dict
    for k,v in pairs(cookies_to_add) do
        cookie_dict[k] = v
    end

    -- Build cookie
    cookie = cookie[0]
    for k,_ in pairs(cookie_dict) do
        if cookie_dict[k] ~= nil then
            cookie = cookie .. k .. "=" .. cookie_dict[k] .. ";"
        end
    end

    txn.http:req_set_header("cookie", cookie)
end

-- Add headers to the request
function utils.add_headers(txn, user_info)
    local headers_to_add = {
        ["x-proxy-haproxy-username"] = user_info["name"],
        ["x-proxy-haproxy-email"] = user_info["email"]
    }

    -- Add headers to request
    for k,v in pairs(headers_to_add) do
        txn.http:req_set_header(k, v) -- req_set_header overwrittes the header value
    end
end

return utils