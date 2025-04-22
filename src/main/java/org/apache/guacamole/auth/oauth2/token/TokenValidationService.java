/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.guacamole.auth.oauth2.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.Inject;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import org.apache.guacamole.auth.oauth2.conf.ConfigurationService;
import org.apache.guacamole.auth.oauth2.OAuth2UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides functionality for validating ID tokens and retrieving user
 * information from the OAuth2 provider. Also handles the exchange of
 * authorization codes for access tokens.
 */
public class TokenValidationService {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(TokenValidationService.class);

    /**
     * Provides access to configured OAuth2 settings.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * Service for validating and generating unique OAuth2 state values.
     */
    @Inject
    private StateService stateService;

    /**
     * Retrieves user information from the OAuth2 provider using the given
     * access token.
     *
     * @param accessToken The access token issued by the OAuth2 provider.
     * @return An {@link OAuth2UserInfo} object containing the authenticated
     * user's info.
     * @throws Exception If the user info cannot be retrieved.
     */
    public OAuth2UserInfo getUserInfoFromToken(String accessToken) throws Exception {
        // Get the user info endpoint URI from configuration
        URI userInfoUri = confService.getUserInfoEndpoint();
        URL url = userInfoUri.toURL();

        // Open an HTTP GET request with Authorization header
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + accessToken);
        connection.setRequestProperty("Accept", "application/json");

        // Check response status
        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            throw new Exception("Failed to retrieve user info. HTTP " + responseCode);
        }

        // Parse the response JSON
        InputStream responseStream = connection.getInputStream();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode json = mapper.readTree(responseStream);

        // Extract username using configured claim name
        String usernameClaim = confService.getUsernameClaimType();
        JsonNode usernameNode = json.get(usernameClaim);
        if (usernameNode == null || usernameNode.isNull()) {
            throw new Exception("Username claim '" + usernameClaim + "' not found in user info response.");
        }
        String username = usernameNode.asText();

        // Extract groups using configured claim name (if any)
        Set<String> groups = new HashSet<>();
        String groupsClaim = confService.getGroupsClaimType();
        JsonNode groupsNode = json.get(groupsClaim);
        if (groupsNode != null && groupsNode.isArray()) {
            for (JsonNode group : groupsNode) {
                groups.add(group.asText());
            }
        }

        return new OAuth2UserInfo(username, groups);
    }

    /**
     * Exchanges the authorization code for an access token by calling the token
     * endpoint.
     *
     * @param authorizationCode The authorization code received from the OAuth2
     * provider.
     * @return The access token string.
     * @throws Exception If the exchange fails or the access token is not
     * returned.
     */
    public String exchangeCodeForToken(String authorizationCode) throws Exception {
        // Get the token endpoint URI from configuration
        URI tokenUri = confService.getTokenEndpoint();
        URL url = tokenUri.toURL();

        // Open a POST connection
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        // Construct the request body with required parameters
        String body = "grant_type=authorization_code"
                + "&code=" + authorizationCode
                + "&redirect_uri=" + confService.getRedirectURI()
                + "&client_id=" + confService.getClientID()
                + "&client_secret=" + confService.getClientSecret();

        // Send the request body
        connection.getOutputStream().write(body.getBytes("UTF-8"));

        // Check response status
        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            throw new Exception("Failed to exchange authorization code for token. HTTP " + responseCode);
        }

        // Parse the response JSON
        InputStream responseStream = connection.getInputStream();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonResponse = mapper.readTree(responseStream);

        // Extract the access token
        if (jsonResponse.has("access_token")) {
            return jsonResponse.get("access_token").asText();
        } else {
            throw new Exception("Access token not found in the response.");
        }
    }

}
