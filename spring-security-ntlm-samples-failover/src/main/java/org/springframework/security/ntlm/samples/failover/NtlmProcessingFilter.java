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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.Authentication;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.rememberme.RememberMeAuthenticationToken;
import org.springframework.util.Assert;

/**
 * Custom NtlmProcessingFilter to handle failover to prevent NTLM authentication when remember-me cookies is present.
 * @author Alois Cochard
 *
 */
public class NtlmProcessingFilter extends org.springframework.security.ui.ntlm.NtlmProcessingFilter implements InitializingBean {

    private SecurityConfiguration securityConfiguration;

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(securityConfiguration, "securityConfiguration is required");

        setDefaultDomain(securityConfiguration.getDefaultDomain());
        setDomainController(securityConfiguration.getDomainController());
        setStripDomain(securityConfiguration.isStripDomain());

        super.afterPropertiesSet();
    }

    @Override
    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // Preventing authenticated user with 'rememberMe' service to require NTLM
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication instanceof RememberMeAuthenticationToken)) {
            super.doFilterHttp(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    public void setSecurityConfiguration(SecurityConfiguration securityConfiguration) {
        this.securityConfiguration = securityConfiguration;
    }
}
