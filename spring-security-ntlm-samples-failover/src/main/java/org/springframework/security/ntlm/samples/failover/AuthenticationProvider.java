/*
 * Copyright 2002-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ntlm.samples.failover;

import org.springframework.security.AuthenticationException;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.security.ui.ntlm.NtlmUsernamePasswordAuthenticationToken;
import org.springframework.security.userdetails.UserDetails;

/**
 * DaoAuthenticatioProvider used to disable password check when NTLM is used.
 * @author Alois Cochard
 *
 */
public class AuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        // Disable additional check (password) for NTLM authentication
        if (!(authentication instanceof NtlmUsernamePasswordAuthenticationToken)) {
            super.additionalAuthenticationChecks(userDetails, authentication);
        }
    }
}
