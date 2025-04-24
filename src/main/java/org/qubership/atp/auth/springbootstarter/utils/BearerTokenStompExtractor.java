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

package org.qubership.atp.auth.springbootstarter.utils;

import static org.qubership.atp.auth.springbootstarter.Constants.BEARER_TOKEN_TYPE;

import java.util.Objects;

import org.springframework.messaging.simp.stomp.StompHeaderAccessor;

import org.qubership.atp.auth.springbootstarter.Constants;

public class BearerTokenStompExtractor implements HeaderValueExtractor<String, StompHeaderAccessor> {
    @Override
    public String extract(StompHeaderAccessor accessor) {
        String token = accessor.getFirstNativeHeader(Constants.AUTHORIZATION_HEADER_NAME);
        if (!Objects.isNull(token)) {
            return token.replace(BEARER_TOKEN_TYPE + " ", "");
        }
        return null;
    }
}
