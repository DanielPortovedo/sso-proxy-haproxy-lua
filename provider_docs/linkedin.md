Quick guide: [Guide](https://stateful.com/blog/linkedin-oauth)

Create linkedin app: [Create app](https://developer.linkedin.com/)

OpenID linkedin Docs: [Docs](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2?context=linkedin%2Fconsumer%2Fcontext)

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
        "name": "linkedin",
        "client_id": "client_id",
        "client_secret": "client_secret",
        "issuer": "https://www.linkedin.com/oauth",
        "auth_uri": "https://www.linkedin.com/oauth/v2/authorization",
        "token_uri": "https://www.linkedin.com/oauth/v2/accessToken",
        "public_key_uri": "https://www.linkedin.com/oauth/openid/jwks"
    }
}
```