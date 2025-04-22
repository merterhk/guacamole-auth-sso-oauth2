/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.
 *
 * The ASF licenses this file under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.guacamole.auth.oauth2.conf;

import com.google.inject.Inject;
import java.net.URI;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.apache.guacamole.properties.URIGuacamoleProperty;

/**
 * Reads OAuth2 configuration values from the guacamole.properties file.
 */
public class ConfigurationService {

    // Default values for configuration
    private static final String DEFAULT_USERNAME_CLAIM_TYPE = "username";
    private static final String DEFAULT_GROUPS_CLAIM_TYPE = "groups";
    private static final String DEFAULT_SCOPE = "email profile";
    private static final int DEFAULT_ALLOWED_CLOCK_SKEW = 30; // seconds
    private static final int DEFAULT_MAX_TOKEN_VALIDITY = 300; // minutes
    private static final int DEFAULT_MAX_STATE_VALIDITY = 10;  // minutes

    // OAuth2 configuration keys
// OAuth2 URI property definitions
    private static final URIGuacamoleProperty OAUTH2_AUTHORIZATION_ENDPOINT
            = new URIGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-authorization-endpoint";
        }
    };

    private static final URIGuacamoleProperty OAUTH2_TOKEN_ENDPOINT
            = new URIGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-token-endpoint";
        }
    };

    private static final URIGuacamoleProperty OAUTH2_USER_INFO_ENDPOINT
            = new URIGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-user-info-endpoint";
        }
    };

    private static final URIGuacamoleProperty OAUTH2_REDIRECT_URI
            = new URIGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-redirect-uri";
        }
    };

// OAuth2 string property definitions
    private static final StringGuacamoleProperty OAUTH2_CLIENT_ID
            = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-client-id";
        }
    };

    private static final StringGuacamoleProperty OAUTH2_CLIENT_SECRET
            = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-client-secret";
        }
    };

    private static final StringGuacamoleProperty OAUTH2_ISSUER
            = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-issuer";
        }
    };

    private static final StringGuacamoleProperty OAUTH2_USERNAME_CLAIM_TYPE
            = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-username-claim-type";
        }
    };

    private static final StringGuacamoleProperty OAUTH2_GROUPS_CLAIM_TYPE
            = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-groups-claim-type";
        }
    };

    private static final StringGuacamoleProperty OAUTH2_SCOPE
            = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-scope";
        }
    };

    private static final IntegerGuacamoleProperty OAUTH2_MAX_STATE_VALIDITY
            = new IntegerGuacamoleProperty() {
        @Override
        public String getName() {
            return "oauth2-max-state-validity";
        }
    };

    /**
     * Provides access to environment variables.
     */
    @Inject
    private Environment environment;

    // OAuth2 endpoint getters
    public URI getAuthorizationEndpoint() throws GuacamoleException {
        return environment.getRequiredProperty(OAUTH2_AUTHORIZATION_ENDPOINT);
    }

    public URI getTokenEndpoint() throws GuacamoleException {
        return environment.getRequiredProperty(OAUTH2_TOKEN_ENDPOINT);
    }

    public URI getUserInfoEndpoint() throws GuacamoleException {
        return environment.getRequiredProperty(OAUTH2_USER_INFO_ENDPOINT);
    }

    public URI getRedirectURI() throws GuacamoleException {
        return environment.getRequiredProperty(OAUTH2_REDIRECT_URI);
    }

    // OAuth2 client credentials
    public String getClientID() throws GuacamoleException {
        return environment.getRequiredProperty(OAUTH2_CLIENT_ID);
    }

    public String getClientSecret() throws GuacamoleException {
        return environment.getRequiredProperty(OAUTH2_CLIENT_SECRET);
    }

    // Token verification and claim configuration
    public String getIssuer() throws GuacamoleException {
        return environment.getRequiredProperty(OAUTH2_ISSUER);
    }

    public String getUsernameClaimType() throws GuacamoleException {
        return environment.getProperty(OAUTH2_USERNAME_CLAIM_TYPE, DEFAULT_USERNAME_CLAIM_TYPE);
    }

    public String getGroupsClaimType() throws GuacamoleException {
        return environment.getProperty(OAUTH2_GROUPS_CLAIM_TYPE, DEFAULT_GROUPS_CLAIM_TYPE);
    }

    public String getScope() throws GuacamoleException {
        return environment.getProperty(OAUTH2_SCOPE, DEFAULT_SCOPE);
    }

    public int getMaxStateValidity() throws GuacamoleException {
        return environment.getProperty(OAUTH2_MAX_STATE_VALIDITY, DEFAULT_MAX_STATE_VALIDITY);
    }
}
