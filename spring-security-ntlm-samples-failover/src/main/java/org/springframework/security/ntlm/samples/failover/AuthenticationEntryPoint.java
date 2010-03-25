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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.ntlm.samples.failover.SecurityConfiguration.Authentication;
import org.springframework.security.ui.ntlm.NtlmProcessingFilter;
import org.springframework.security.ui.ntlm.NtlmProcessingFilterEntryPoint;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.util.Assert;


/**
 * Strategic AuthenticationEntryPoint for NTLM/Form authentication failover.
 * @author Alois Cochard
 *
 */
public class AuthenticationEntryPoint implements InitializingBean, org.springframework.security.ui.AuthenticationEntryPoint, ApplicationContextAware {

    private FilterChainProxy proxy;

    private SecurityConfiguration securityConfiguration;

    private org.springframework.security.ui.AuthenticationEntryPoint standardEntryPoint;

    private org.springframework.security.ui.AuthenticationEntryPoint ntlmEntryPoint;

    private ApplicationContext applicationContext;

    @SuppressWarnings("unchecked")
    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(proxy, "proxy is required");
        Assert.notNull(securityConfiguration, "securityConfiguration is required");

        // Retrieving original filter chain map
        Map filterChainMap = proxy.getFilterChainMap();

        if (securityConfiguration.getAuthentication().equals(Authentication.STANDARD)) {
            // NTLM Disabling
            for (Object value : filterChainMap.values()) {
                List<Filter> filters = (List<Filter>) value;
                for (Iterator<Filter> iterator = filters.iterator(); iterator.hasNext();) {
                    Filter filter = iterator.next();
                    if (filter instanceof NtlmProcessingFilter && securityConfiguration.getAuthentication().equals(Authentication.STANDARD)) {
                        // Deleting NTLM filter
                        iterator.remove();
                    }
                }
            }
        }

        // Defining updated filter chain map
        proxy.setFilterChainMap(filterChainMap);
    }

    @Override
    public void commence(ServletRequest request, ServletResponse response, AuthenticationException authException) throws IOException,
            ServletException {
        Authentication authentication = securityConfiguration.getAuthentication();

        // Switch to standard authentication in case of NTLM authentication failure.
        if (authentication.equals(Authentication.NTLM) && authException != null && authException instanceof BadCredentialsException) {
            authentication = Authentication.STANDARD;
        }

        org.springframework.security.ui.AuthenticationEntryPoint entryPoint = getEntryPoint(authentication);
        entryPoint.commence(request, response, authException);
    }

    private org.springframework.security.ui.AuthenticationEntryPoint getEntryPoint(Authentication authentication) {
        if (authentication.equals(Authentication.NTLM)) {
            // NTLM
            if (ntlmEntryPoint == null) {
                String[] beans = applicationContext.getBeanNamesForType(NtlmProcessingFilterEntryPoint.class);
                Assert.isTrue(beans.length > 0, "No bean of type NtlmProcessingFilterEntryPoint");
                ntlmEntryPoint = (NtlmProcessingFilterEntryPoint) applicationContext.getBean(beans[0]);
            }
            return ntlmEntryPoint;
        } else {
            // FORM
            if (standardEntryPoint == null) {
                String[] beans = applicationContext.getBeanNamesForType(AuthenticationProcessingFilterEntryPoint.class);
                Assert.isTrue(beans.length > 0, "No bean of type AuthenticationProcessingFilterEntryPoint");
                standardEntryPoint = (AuthenticationProcessingFilterEntryPoint) applicationContext.getBean(beans[0]);
            }
            return standardEntryPoint;
        }
    }

    public FilterChainProxy getProxy() {
        return proxy;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    public void setProxy(FilterChainProxy proxy) {
        this.proxy = proxy;
    }

    public void setSecurityConfiguration(SecurityConfiguration securityConfiguration) {
        this.securityConfiguration = securityConfiguration;
    }

}
