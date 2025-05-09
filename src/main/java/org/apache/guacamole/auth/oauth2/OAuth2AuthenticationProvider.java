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

import org.apache.guacamole.auth.sso.SSOAuthenticationProvider;
import org.apache.guacamole.auth.sso.SSOResource;

/**
 * Guacamole authentication backend which authenticates users using an
 * arbitrary external system implementing OAuth2. No storage for connections is
 * provided - only authentication. Storage must be provided by some other
 * extension.
 */
public class OAuth2AuthenticationProvider extends SSOAuthenticationProvider {

    /**
     * Creates a new OAuth2AuthenticationProvider that authenticates users
     * against an OAuth2 service.
     */
    public OAuth2AuthenticationProvider() {
        super(AuthenticationProviderService.class, SSOResource.class,
                new OAuth2AuthenticationProviderModule());
    }

    @Override
    public String getIdentifier() {
        return "oauth2";
    }

}
