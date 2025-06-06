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

package org.qubership.atp.auth.springbootstarter;

import org.qubership.atp.auth.springbootstarter.config.DisableSecurityConfiguration;
import org.qubership.atp.auth.springbootstarter.config.FeignCapabilityConfiguration;
import org.qubership.atp.auth.springbootstarter.config.HttpClientsConfiguration;
import org.qubership.atp.auth.springbootstarter.config.KafkaConfig;
import org.qubership.atp.auth.springbootstarter.config.KeycloakConfiguration;
import org.qubership.atp.auth.springbootstarter.config.SecurityConfiguration;
import org.qubership.atp.auth.springbootstarter.config.ServiceConfiguration;
import org.qubership.atp.auth.springbootstarter.config.SslProviderConfiguration;
import org.qubership.atp.auth.springbootstarter.config.UndertowWebMvcConfiguration;
import org.qubership.atp.auth.springbootstarter.config.UtilsConfiguration;
import org.qubership.atp.auth.springbootstarter.handlers.GlobalExceptionHandler;
import org.qubership.atp.auth.springbootstarter.security.oauth2.client.config.TokenRelayConfiguration;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableCaching
@Import({
        KeycloakConfiguration.class,
        SecurityConfiguration.class, UtilsConfiguration.class,
        ServiceConfiguration.class, DisableSecurityConfiguration.class,
        TokenRelayConfiguration.class, HttpClientsConfiguration.class,
        FeignCapabilityConfiguration.class, SslProviderConfiguration.class,
        UndertowWebMvcConfiguration.class, GlobalExceptionHandler.class, KafkaConfig.class})
public class AtpAuthAutoConfiguration {
}
