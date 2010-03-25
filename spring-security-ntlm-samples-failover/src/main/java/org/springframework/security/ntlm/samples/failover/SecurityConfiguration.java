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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Bean storing security configuration.
 * @author Alois Cochard
 *
 */
public final class SecurityConfiguration implements InitializingBean {

    public enum Authentication {
        NTLM,
        STANDARD;
    }

    private Authentication authentication;

    private String defaultDomain;

    private String domainController;

    private boolean stripDomain;

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(authentication, "authentication is required");
        if (authentication.equals(Authentication.NTLM)) {
        	Assert.hasText(defaultDomain, "defaultDomain is required");
        	Assert.hasText(domainController, "domainController is required");
        }
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public String getDefaultDomain() {
        return defaultDomain;
    }

    public String getDomainController() {
        return domainController;
    }

    public boolean isStripDomain() {
        return stripDomain;
    }

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    public void setDefaultDomain(String defaultDomain) {
        this.defaultDomain = defaultDomain;
    }

    public void setDomainController(String domainController) {
        this.domainController = domainController;
    }

    public void setStripDomain(boolean stripDomain) {
        this.stripDomain = stripDomain;
    }

}
