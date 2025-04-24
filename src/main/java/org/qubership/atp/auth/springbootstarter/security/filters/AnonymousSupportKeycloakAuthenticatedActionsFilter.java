/*
 * # Copyright 2024-2025 NetCracker Technology Corporation
 * #
 * # Licensed under the Apache License, Version 2.0 (the "License");
 * # you may not use this file except in compliance with the License.
 * # You may obtain a copy of the License at
 * #
 * #      http://www.apache.org/licenses/LICENSE-2.0
 * #
 * # Unless required by applicable law or agreed to in writing, software
 * # distributed under the License is distributed on an "AS IS" BASIS,
 * # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * # See the License for the specific language governing permissions and
 * # limitations under the License.
 */

package org.qubership.atp.auth.springbootstarter.security.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AuthenticatedActionsHandler;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticatedActionsFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;

import org.qubership.atp.auth.springbootstarter.security.facades.AnonymousSupportSimpleHttpFacade;

public class AnonymousSupportKeycloakAuthenticatedActionsFilter extends KeycloakAuthenticatedActionsFilter {

    private static final Logger log = LoggerFactory.getLogger(AnonymousSupportKeycloakAuthenticatedActionsFilter.class);

    private ApplicationContext applicationContext;
    private AdapterDeploymentContext deploymentContext;

    public AnonymousSupportKeycloakAuthenticatedActionsFilter() {
        super();
    }

    @Override
    protected void initFilterBean() {
        super.initFilterBean();
        deploymentContext = applicationContext.getBean(AdapterDeploymentContext.class);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        super.setApplicationContext(applicationContext);
        this.applicationContext = applicationContext;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpFacade facade = new AnonymousSupportSimpleHttpFacade((HttpServletRequest) request,
                (HttpServletResponse) response);
        AuthenticatedActionsHandler handler = new AuthenticatedActionsHandler(
                deploymentContext.resolveDeployment(facade), (OIDCHttpFacade) facade);
        boolean handled = handler.handledRequest();
        if (handled) {
            log.debug("Authenticated filter handled request: {}", ((HttpServletRequest) request).getRequestURI());
        } else {
            chain.doFilter(request, response);
        }
    }
}
