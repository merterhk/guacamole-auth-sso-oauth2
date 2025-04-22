# guacamole-auth-sso-oauth2
Guacamole OAuth2 Authentication Module

# Sample guacamole.properties config

auth-provider: net.sourceforge.guacamole.net.auth.oauth2.OAuth2AuthenticationProvider
oauth2-user-info-endpoint: https://oauth2.example.com/api/user
oauth2-authorization-endpoint: https://oauth2.example.com/oauth/authorize
oauth2-issuer: https://oauth2.example.com
oauth2-scope: email, mobile
oauth2-client-id: ***
oauth2-client-secret: ***
oauth2-redirect-uri: https://guacamole.example.com
oauth2-token-endpoint: https://oauth2.example.com/oauth/token


### Force login with OAuth2 (Optional):
extension-priority: oauth2
