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

package org.qubership.atp.auth.springbootstarter.security.oauth2.client.config;

import static org.qubership.atp.auth.springbootstarter.Constants.AUTHORIZATION_HEADER_NAME;
import static org.qubership.atp.auth.springbootstarter.Constants.BEARER_TOKEN_TYPE;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import brave.Span;
import brave.Tracer;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Oauth2FeignClientInterceptor implements RequestInterceptor {

    private final AccessTokenProvider accessTokenProvider;
    private final OAuth2ProtectedResourceDetails protectedResourceDetails;
    private final Tracer tracer;
    private final AccessTokenRequest accessTokenRequest;

    @Value("${atp-auth.refreshTimeBeforeExpirationInSec:300}")
    private Integer refreshTimeBeforeExpiration;

    /**
     * Oauth2FeignClientInterceptor.
     *
     * @param accessTokenProvider      accessTokenProvider
     * @param protectedResourceDetails protectedResourceDetails
     * @param tracer                   tracer
     */
    public Oauth2FeignClientInterceptor(
            AccessTokenProvider accessTokenProvider,
            OAuth2ProtectedResourceDetails protectedResourceDetails,
            Tracer tracer) {
        this(accessTokenProvider, protectedResourceDetails, tracer, new DefaultAccessTokenRequest());
    }

    /**
     * Oauth2FeignClientInterceptor.
     *
     * @param accessTokenProvider       accessTokenProvider
     * @param protectedResourceDetails  protectedResourceDetails
     * @param tracer                    tracer
     * @param accessTokenRequest        accessTokenRequest
     */
    public Oauth2FeignClientInterceptor(
            AccessTokenProvider accessTokenProvider,
            OAuth2ProtectedResourceDetails protectedResourceDetails,
            Tracer tracer, AccessTokenRequest accessTokenRequest) {
        this.accessTokenProvider = accessTokenProvider;
        this.protectedResourceDetails = protectedResourceDetails;
        this.tracer = tracer;
        this.accessTokenRequest = accessTokenRequest;
    }


    @Override
    public void apply(RequestTemplate requestTemplate) {
        log.debug("start apply [requestTemplate.path={}]", requestTemplate.path());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //noinspection unchecked
        Optional<KeycloakSecurityContext> contextOptional = Optional.ofNullable(authentication)
                .map(Authentication::getPrincipal)
                .filter(principal -> principal instanceof KeycloakPrincipal)
                .map(principal -> (KeycloakPrincipal<KeycloakSecurityContext>) principal)
                .map(KeycloakPrincipal::getKeycloakSecurityContext);
        if (contextOptional.isPresent()) {
            log.debug("Keycloak context is present");
            KeycloakSecurityContext context = contextOptional.get();
            if (isAccessTokenExpired(context.getToken())) {
                log.debug("Access token is expired or almost expired. Token expiration {}. "
                        + "Set null to existing token in accessTokenRequest", context.getToken().getExpiration());
                // needed to get new access token in accessTokenProvider.obtainAccessToken method
                accessTokenRequest.setExistingToken(null);
            } else {
                log.debug("user token found");
                setAuthorizationHeader(requestTemplate, context.getTokenString());
                return;
            }
        }
        Optional<Span> nextSpan = Optional.ofNullable(tracer).map(Tracer::nextSpan);
        try {
            OAuth2AccessToken existingToken = accessTokenRequest.getExistingToken();
            log.debug("Token expiration date {}",
                    Objects.nonNull(existingToken) ? existingToken.getExpiration() : null);
            if (Objects.nonNull(existingToken)
                    && (existingToken.isExpired() || existingToken.getExpiresIn() < refreshTimeBeforeExpiration)) {
                log.debug("m2m token is expired or almost expired. expiration date {}", existingToken.getExpiration());
                accessTokenRequest.setExistingToken(null);
            }
            log.debug("Get m2m token");
            nextSpan.ifPresent(span -> {
                span.name("get m2m token");
                span.start();
            });
            OAuth2AccessToken accessToken = accessTokenProvider.obtainAccessToken(
                    protectedResourceDetails,
                    accessTokenRequest
            );
            log.debug("m2m token received with expiration date {}", accessToken.getExpiration());
            setAuthorizationHeader(requestTemplate, accessToken.getValue());
            accessTokenRequest.setExistingToken(accessToken);
        } catch (Exception e) {
            log.error("Failed to obtain m2m token", e);
            throw e;
        } finally {
            nextSpan.ifPresent(Span::finish);
        }
    }

    private boolean isAccessTokenExpired(AccessToken token) {
        if (Objects.isNull(token) || token.isExpired()) {
            return true;
        }
        int expiresIn = token.getExpiration() - Long.valueOf(System.currentTimeMillis() / 1000L).intValue();
        return expiresIn < refreshTimeBeforeExpiration;
    }

    /**
     * Add or replace bearer token.
     */
    public void setAuthorizationHeader(RequestTemplate requestTemplate, String token) {
        requestTemplate.header(AUTHORIZATION_HEADER_NAME, String.format("%s %s", BEARER_TOKEN_TYPE, token));
        Collection<String> authorizationHeaderValues = requestTemplate.headers().get(AUTHORIZATION_HEADER_NAME);
        boolean authorizationHeaderHasToken = authorizationHeaderValues.stream()
                .anyMatch(value -> value.startsWith(BEARER_TOKEN_TYPE.toLowerCase()));
        if (authorizationHeaderValues.size() > 1 && authorizationHeaderHasToken) {
            authorizationHeaderValues =
                    authorizationHeaderValues.stream()
                            .filter(value -> !value.startsWith(BEARER_TOKEN_TYPE.toLowerCase()))
                            .collect(Collectors.toList());
            requestTemplate.removeHeader(AUTHORIZATION_HEADER_NAME);
            requestTemplate.header(AUTHORIZATION_HEADER_NAME, authorizationHeaderValues);
        }
    }
}
