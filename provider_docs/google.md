Google OAuth2 docs: [OAuth2 docs](https://developers.google.com/identity/protocols/oauth2)

Google API docs: [API docs](https://developers.google.com/identity/protocols/oauth2/web-server#obtainingaccesstokens)

Google API scopes: [Scopes](https://developers.google.com/identity/protocols/oauth2/scopes#openid-connect)

Google API OpenID Scopes: [OpenID Scopes](https://developers.google.com/identity/protocols/oauth2/scopes#openid-connect)

You can obtain the provider information after registering your client credentials [here](https://console.cloud.google.com/apis/credentials) and then retrieve `client_id` and `client_secret` afterwards.

Example configuration:
```json
{   
    "global": {
        "root_uri": "http://localhost:4180",
        "public_uris": ["/"],
        "debug_mode_enabled": true
    },
    "web_apps":{
        "/" : {
            "home_page_uri": "/",
            "error_page_uri": "/error",
            "callback_uri": "/callback",
            "logout_uri": "/logout",
            "scope": ["profile","email","openid"],
            "require_authentication": true,
            "session_cookie_name": "ha-sessionID",
            "session_validity": 3600
        },
        "/api" : {
            "home_page_uri": "/api",
            "error_page_uri": "/api/error",
            "callback_uri": "/api/callback",
            "logout_uri": "/api/logout",
            "scope": ["openid"]
        }
    },
    "provider": {
        "name": "google",
        "client_id":"client_id",
        "client_secret":"client_secret",
        "issuer": "https://accounts.google.com",
        "auth_uri":"https://accounts.google.com/o/oauth2/auth",
        "token_uri":"https://oauth2.googleapis.com/token",
        "public_key_uri":"https://www.googleapis.com/oauth2/v1/certs"
    }
}
```