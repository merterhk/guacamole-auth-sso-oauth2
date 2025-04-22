# Guacamole OAuth2 Authentication Module

This project provides an OAuth2-based authentication extension for [Apache Guacamole](https://guacamole.apache.org/). It enables Single Sign-On (SSO) by integrating with an external OAuth2 identity provider.

---

## 🔧 Installation

1. Build the module and place the generated `.jar` file into the Guacamole extensions directory:

```/etc/guacamole/extensions/```


3. Add the following configuration to your `guacamole.properties` file, adjusting values according to your OAuth2 provider.


## 🛠️ Sample `guacamole.properties` Configuration

```properties
# Use the OAuth2 module as the authentication provider
auth-provider: net.sourceforge.guacamole.net.auth.oauth2.OAuth2AuthenticationProvider

# OAuth2 endpoints
oauth2-authorization-endpoint: https://oauth2.example.com/oauth/authorize
oauth2-token-endpoint: https://oauth2.example.com/oauth/token
oauth2-user-info-endpoint: https://oauth2.example.com/api/user
oauth2-issuer: https://oauth2.example.com

# OAuth2 client credentials
oauth2-client-id: ***
oauth2-client-secret: ***
oauth2-redirect-uri: https://guacamole.example.com

# Requested scopes
oauth2-scope: email, mobile

# (Optional) Enforce OAuth2 login by giving this extension highest priority
extension-priority: oauth2
```

3. Restart the Guacamole server (typically Tomcat):

``` sudo systemctl restart tomcat9 ```
