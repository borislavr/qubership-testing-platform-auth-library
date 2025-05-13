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

package org.qubership.atp.auth.springbootstarter.config;

import java.util.Set;
import java.util.UUID;

import org.apache.http.client.HttpClient;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticatedActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.qubership.atp.auth.springbootstarter.entities.UserInfo;
import org.qubership.atp.auth.springbootstarter.holders.DataContextHolder;
import org.qubership.atp.auth.springbootstarter.provider.impl.UserProvider;
import org.qubership.atp.auth.springbootstarter.security.filters.AnonymousSupportKeycloakAuthenticatedActionsFilter;
import org.qubership.atp.auth.springbootstarter.security.permissions.EntityAccessEnforcement;
import org.qubership.atp.auth.springbootstarter.security.permissions.PolicyEnforcement;
import org.qubership.atp.auth.springbootstarter.services.UserGroupService;
import org.qubership.atp.auth.springbootstarter.services.UsersService;
import org.qubership.atp.auth.springbootstarter.ssl.Provider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@KeycloakConfiguration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Profile("default")
public class SecurityConfiguration extends AtpKeycloakWebSecurityConfigurerAdapter {

    @Value("${spring.application.name}")
    private String serviceName;
    @Value("${atp-auth.headers.content-security-policy:default-src 'self' *}")
    private String contentSecurityPolicy;

    /**
     * Configure authentication.
     */
    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth) {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        SimpleAuthorityMapper converter = new SimpleAuthorityMapper();
        converter.setConvertToUpperCase(true);
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(converter);
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new NullAuthenticatedSessionStrategy();
    }

    @Bean
    @Override
    protected KeycloakAuthenticatedActionsFilter keycloakAuthenticatedActionsFilter() {
        return new AnonymousSupportKeycloakAuthenticatedActionsFilter();
    }

    /**
     * AdapterDeploymentContext is used by the keycloak lib for requests to the keycloak server.
     */
    @Bean
    @Primary
    public AdapterDeploymentContext sslAdapterDeploymentContext(final HttpClient sslHttpClient) throws Exception {
        AdapterDeploymentContextFactoryBean factoryBean =
                new AdapterDeploymentContextFactoryBean(keycloakConfigResolver);
        factoryBean.afterPropertiesSet();
        AdapterDeploymentContext deploymentContext = factoryBean.getObject();

        return new AdapterDeploymentContext() {
            @Override
            public KeycloakDeployment resolveDeployment(HttpFacade facade) {
                KeycloakDeployment keycloakDeployment = deploymentContext.resolveDeployment(facade);
                keycloakDeployment.setClient(sslHttpClient);
                return keycloakDeployment;
            }
        };
    }

    /**
     * Return {@link FilterRegistrationBean} filter for keycloak authentication.
     *
     * @return {@link FilterRegistrationBean}
     */
    @Bean
    public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
            final KeycloakAuthenticationProcessingFilter filter) {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean<>(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    @Bean("entityAccess")
    public PolicyEnforcement entityAccess(final UsersService usersService,
                                          final UserGroupService userGroupService,
                                          final DataContextHolder<Set<String>> userRolesContextHolder) {
        return new EntityAccessEnforcement(usersService, userGroupService, userRolesContextHolder, serviceName);
    }

    @Bean("userInfoProvider")
    public Provider<UserInfo> userInfoProvider() {
        return new UserProvider();
    }

    @Override
    public void configure(final WebSecurity web) throws Exception {
        super.configure(web);
        web
                .ignoring()
                .antMatchers("/assets/**")
                .antMatchers(HttpMethod.OPTIONS, "/**");
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        super.configure(http);
        http
                .headers()
                .xssProtection().xssProtectionEnabled(false)
                .and()
                .contentSecurityPolicy(contentSecurityPolicy)
                .and()
                .frameOptions()
                .sameOrigin()
                .and()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/ws/api").permitAll()
                .antMatchers("/api/public/**").permitAll()
                .antMatchers("/rest/deployment/**").permitAll()
                .antMatchers("/*/api/**", "/api/**").authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean("userGroupService")
    public UserGroupService userGroupService(final DataContextHolder<UUID> userIdContextHolder,
                                             final UsersService usersService,
                                             final DataContextHolder<Set<String>> userRolesContextHolder) {
        return new UserGroupService(userIdContextHolder, usersService, userRolesContextHolder);
    }
}
