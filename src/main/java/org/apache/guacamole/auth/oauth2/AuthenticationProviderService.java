/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.guacamole.auth.oauth2;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;
import org.apache.guacamole.auth.oauth2.conf.ConfigurationService;
import org.apache.guacamole.auth.oauth2.token.StateService;
import org.apache.guacamole.auth.oauth2.token.TokenValidationService;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.sso.SSOAuthenticationProviderService;
import org.apache.guacamole.auth.sso.user.SSOAuthenticatedUser;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.RedirectField;
import org.apache.guacamole.language.TranslatableMessage;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;
import org.apache.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;

/**
 * Service that authenticates Guacamole users by processing OAuth2 tokens.
 */
@Singleton
public class AuthenticationProviderService implements SSOAuthenticationProviderService {

    /**
     * The standard HTTP parameter which will be included within the URL by all
     * OAuth2 services upon successful authentication and redirect.
     */
    public static final String TOKEN_PARAMETER_NAME = "code";

    /**
     * Service for retrieving OAuth2 configuration information.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * Service for validating and generating unique state values.
     */
    @Inject
    private StateService stateService;

    /**
     * Service for validating received ID tokens.
     */
    @Inject
    private TokenValidationService tokenService;

    /**
     * Provider for AuthenticatedUser objects.
     */
    @Inject
    private Provider<SSOAuthenticatedUser> authenticatedUserProvider;

    @Override
    public SSOAuthenticatedUser authenticateUser(Credentials credentials)
            throws GuacamoleException {

        String username = null;
        Set<String> groups = null;

        HttpServletRequest request = credentials.getRequest();
        if (request != null) {
            String authorizationCode = request.getParameter("code");

            if (authorizationCode != null) {
                try {
                    // Authorization kodu ile access token al
                    String accessToken = tokenService.exchangeCodeForToken(authorizationCode);

                    // Access token ile kullanıcı bilgilerini al
                    OAuth2UserInfo userInfo = tokenService.getUserInfoFromToken(accessToken);
                    if (userInfo != null) {
                        username = userInfo.getUsername();
                        groups = userInfo.getGroups();
                    }

                } catch (Exception e) {
                    e.printStackTrace(); // catalina.out için
                    throw new GuacamoleInvalidCredentialsException("Failed to validate token or fetch user info.",
                            new CredentialsInfo(Arrays.asList(new Field[]{
                        new RedirectField("code", getLoginURI(),
                        new TranslatableMessage("LOGIN.INFO_IDP_REDIRECT_PENDING"))
                    }))
                    );
                }
            }
        }

        if (username != null) {
            SSOAuthenticatedUser authenticatedUser = authenticatedUserProvider.get();
            authenticatedUser.init(username, credentials, groups, Collections.emptyMap());
            return authenticatedUser;
        }

        // Kod yoksa kullanıcıyı tekrar yetkilendirme sayfasına gönder
        throw new GuacamoleInvalidCredentialsException("Invalid login. Authorization code is missing or invalid.",
                new CredentialsInfo(Arrays.asList(new Field[]{
            new RedirectField("code", getLoginURI(),
            new TranslatableMessage("LOGIN.INFO_IDP_REDIRECT_PENDING"))
        }))
        );
    }

    @Override
    public URI getLoginURI() throws GuacamoleException {
        return UriBuilder.fromUri(confService.getAuthorizationEndpoint())
                .queryParam("scope", confService.getScope())
                .queryParam("response_type", "code")
                .queryParam("client_id", confService.getClientID())
                .queryParam("redirect_uri", confService.getRedirectURI())
                .queryParam("state", stateService.generate(confService.getMaxStateValidity() * 60000L))
                .build();
    }

    @Override
    public void shutdown() {
        // Nothing to clean up
    }

}
