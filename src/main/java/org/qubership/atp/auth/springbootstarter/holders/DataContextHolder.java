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

package org.qubership.atp.auth.springbootstarter.holders;

import java.util.Optional;

import org.keycloak.KeycloakPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Stores objects in context.
 */
public interface DataContextHolder<T> {

    /**
     * Save object in context.
     *
     * @param object this object to save
     */
    default void set(T object) {
        throw new UnsupportedOperationException("This holder does not support the set operation.");
    }

    /**
     * Get object from context.
     *
     * @return optional with object from context or empty optional
     */
    Optional<T> get();

    /**
     * Get principal from context.
     *
     * @return principal
     */
    default KeycloakPrincipal getPrincipal() {
        return (KeycloakPrincipal) SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();
    }
}