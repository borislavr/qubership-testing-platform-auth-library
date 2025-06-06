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

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;

class BearerTokenStompExtractorTest {

    private StompHeaderAccessor connectMessageHeaders;

    private final String token =
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6IC";

    @BeforeEach
    void setUp() {
        Map<String, List<String>> headers = new HashMap<>();
        List<String> authorization = new LinkedList<>();
        authorization.add("Bearer " + token);
        headers.put("Authorization", authorization);

        connectMessageHeaders = StompHeaderAccessor.create(StompCommand.CONNECT, headers);
        connectMessageHeaders.setLeaveMutable(true);
    }

    @Test
    void extract() {
        BearerTokenStompExtractor bearerTokenStompExtractor = new BearerTokenStompExtractor();
        String extractedToken = bearerTokenStompExtractor.extract(connectMessageHeaders);
        Assert.assertEquals(extractedToken, token);
    }
}