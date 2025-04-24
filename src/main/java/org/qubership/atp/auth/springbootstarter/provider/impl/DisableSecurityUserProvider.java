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

package org.qubership.atp.auth.springbootstarter.provider.impl;

import java.util.Collections;
import java.util.UUID;

import org.qubership.atp.auth.springbootstarter.entities.UserInfo;
import org.qubership.atp.auth.springbootstarter.ssl.Provider;

public class DisableSecurityUserProvider implements Provider<UserInfo> {

    private static final UUID USER_ID = UUID.fromString("1c0167c9-1bea-4587-8f32-d637ff341d31");

    @Override
    public UserInfo get() {
        UserInfo userInfo = new UserInfo();

        userInfo.setId(USER_ID);
        userInfo.setUsername("Username");
        userInfo.setFirstName("Firstname");
        userInfo.setLastName("Lastname");
        userInfo.setEmail("Email@some-company.com");
        userInfo.setRoles(Collections.singletonList("ADMIN"));

        return userInfo;
    }
}
