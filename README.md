# SSO Proxy - HAProxy + Lua

- "[HAProxy](https://github.com/haproxy/haproxy/blob/master/README.md) is a free, very fast and reliable reverse-proxy offering high availability, load balancing, and proxying for TCP and HTTP-based applications"

- "[Lua](https://lua.org/about.html) is a powerful, efficient, lightweight, embeddable scripting language."

This project demonstrates how to build a SSO Proxy based on HAproxy and using Lua as scripting language. Making use of Lua as scripting language allow us to increase our possibilities and manipulate requests to, for example, add specific cookies/headers, protect specific cookies/headers, protect specific resources, and much more.

This project, is in use by CERN to support java critical applications that require specific use cases and protection via SSO Proxy using OIDC authentication protocol.

In this project, we use different providers to show that it can be built for any OIDC provider. It also adds the username and the email, from the information provided by the provider, to the request as cookies (**sso_proxy_username**, **sso_proxy_email**) and headers (**x-proxy-haproxy-username**, **x-proxy-haproxy-email**). A debug page it's also available at `/sso-proxy/debug` that dumps the information of the request before send it to the backend. Finally, it can also support multiple applications behinde the proxy with different contexts.

## How to use
First you must choose your provider, from the so far supported ones which are either `google` or `linkedin`, and create an registration for your application. You can get more information to do this using Google Provider in `docs/google.md`, or for Linkedin.md in `docs/linkedin.md`.

Then, you must configure the application by creating a `configs.json` and, once again, examples can be seen in the same documents templates or in `configs_templates/`.

### Configurations

The configurations are divided into 3 different sections:
    - `global` - Where you have configurations that affect all the applications that the Proxy protects
    - `web_apps` - Where you have configurations that affect that specific web app
    - `provider` - Where you have configurations regarding your provider

#### global
- `root_uri`: Defines the base uri of your application. Is a **mandatory string**.
- `public_uris`: Defines public endpoints that the proxy will ignore. This implies that no manipulation is going to be made to the request. Is a **not mandatory array of strings** with default being an empty array.
- `debug_mode_enabled`: Enables or disables the `/sso-proxy/debug` endpoints that dumps debugging information, and enables or disables the dump that also happens in the logs of the application when you add a specific header to the request (this implementation is not yet implemented). Is a **not mandatory boolean** with default value **false**.

Example:
```json
"global": {
    "root_uri": "http://localhost:4180",
    "public_uris": ["/public", "/api/public"],
    "debug_mode_enabled": true
},
```

#### web_apps
- `home_page_uri`: Endpoint of home page, it's mainly used to redirect the user after logout. Is a **not mandatory string** with default value `global.root_uri`.
- `error_page_uri`: Endpoint to redirect user after error. Is a **mandatory string**.
- `callback__uri`: Endpoint to process the `/callback` request from the provider. Is a **mandatory string**.
- `logout_uri`: Endpoint to logout the user. Is a **mandatory string**.
- `scope`: Scopes of the OIDC protocol. Is a **mandatory array of strings**.
- `headers_to_be_removed`: Headers that the proxy will remove from the request not allowing them to reach the backend. Is a **not mandatory array of strings** with default being an empty array. 
- `require_authentication`: Defines if the current web application requires or not authentication. If set to **false** all the requests are not required to be authenticated. In this case, the `header_to_be_removed` feature is still applied. Is **a mandatory boolean**.
- `session_cookie_name`: Name of the session cookie. Is a **not mandatory string** with default value `ha-session-id-` concatenated with context path without the initial /. For instance `ha-session-id-api` for `/api` and `ha-session-id-` for `/`.
- `session_cookie_httponly`: HttpOnly session cookie property. Is a **not mandatory boolean** with default value **true**.
- `session_cookie_secure`: Secure session cookie property. Is a **not mandatory boolean** with default value **true**.
- `session_cookie_samesite`: SameSite session cookie property. Is a **not mandatory string** with default value **Lax**. Possible values are **None**, **Lax** and **Strict**. More information can be seen [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value).
- `session_validity`: The validity of the session and the cookie. Is a **not mandatory integer** with default value 3600. Attention this value shall be treated as **seconds**.
- `custom_cookies`: It's an array of json objects that each contain a `claim_name`, which must match the name of a claim in the `id_token` (**mandatory**), and `cookie_name`, which is the name of the cookie that will contain the value of the corresponding claim (**not mandatory** with default value being *ha_proxy_* + *claim_name*. Example for claim_name = name : *ha_proxy_name*)

Example:

```json
"web_apps":{
    "/" : {
        "home_page_uri": "/",
        "error_page_uri": "/error",
        "callback_uri": "/callback",
        "logout_uri": "/logout",
        "scope": ["profile","email","openid"],
        "headers_to_be_removed": ["SAFE_HEADER"],
        "require_authentication": true,
        "session_cookie_name": "ha-sessionID", 
        "session_cookie_httponly": true,
        "session_cookie_secure": true,
        "session_cookie_samesite": "Lax",
        "session_validity": 3600,
        "custom_cookies": [
            {
                "claim_name": "name"
            },
            {
                "cookie_name": "proxy_email",
                "claim_name": "email"
            }
        ]
    },
    "/api" : {
        "home_page_uri": "/api",
        "error_page_uri": "/api/error",
        "callback_uri": "/api/callback",
        "logout_uri": "/api/logout",
        "scope": ["openid"]
    }
},
```

#### provider
- `name`: Provider you want to use. So far is a **mandatory string** with two possible values `google` or `linkedin`.
- `client_id`: Client id of the registration in the provider. Is a **mandatory string**.
- `client_secret`: Client secret of the registration in the provider. Is a **mandatory string**.
- `issuer`: Issuer uri to be used to validate the jwt tokens. Is a **mandatory string**.
- `auth_uri`: Provider uri to authenticate. Is a **mandatory string**.
- `token_uri`: Provider uri to retrieve the access token. Is a **mandatory string**.
- `public_key_uri`: Provider uri to retrieve public key data for token validation (not yet implemented but shall be provided for future usage). Is a **mandatory string**

Example:

```json
"provider": {
    "name": "google",
    "client_id":"client_id",
    "client_secret":"client_secret",
    "issuer": "https://accounts.google.com",
    "auth_uri":"https://accounts.google.com/o/oauth2/auth",
    "token_uri":"https://oauth2.googleapis.com/token",
    "public_key_uri":"https://www.googleapis.com/oauth2/v1/certs"
}
```

Finally, you can run it:

To avoid OS compatability issues, you can use podman to either develop or deploy the application. To do so, you first must:
- **Build the image**: `podman build -f Dockerfile.alma9 -t alma9`
- **Run it**: `podman run --network="host" -p 4180:4180 -it alma9 /bin/bash`
- **Start HAProxy**: `haproxy -f haproxy.cfg`

Don't forget to change ports in case you have different applications. In this example, the proxy is running on the 4180 and there is a backend application at 8080. See in `haproxy.cfg`.

To test this, you could use this [repo](https://github.com/DanielPortovedo/spring-boot-web-app) to create a web app based on spring boot that dumps the information from the requests at the `/userinfo` endpoint.

Simple!

# Usages

This can be used in multiple aways:

## Using HAProxy itself

Depending on the OS that you use you can locally run it by first installing the necessary dependencies. You can check the `Dockerfile.alma9` as a base example on what you need to install to use the application.

## Containerizing

To avoid OS compatability issues, you can use podman to either develop or deploy the application. To do so, you first must:
- **Build the image**: `podman build -f Dockerfile.alma9 -t alma9`
- **Run it**: `podman run --network="host" -p 4180:4180 -it alma9 /bin/bash`
- **Start HAProxy**: `haproxy -f haproxy.cfg`

Don't forget to change ports in case you have different applications. In this example, the proxy is running on the 4180 and there is a backend application at 8080 for **/** context and another at 8081 for **/api** context. See in `haproxy.cfg`.

To test this, you could use this [repo](https://github.com/DanielPortovedo/spring-boot-web-app) to create a web app based on spring boot that dumps the information from the requests at the `/userinfo` endpoint.

Simple!
