/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.cds.client;

import org.apache.http.client.config.RequestConfig;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for {@link CDSHttpClient}.
 */
public class CDSHttpClientTest {

    @Test
    public void testTheClientIsShared() {

        assertNotNull(CDSHttpClient.get());
        assertSame(CDSHttpClient.get(), CDSHttpClient.get());
    }

    // A value of 0 or less means no timeout to HttpClient, so each one must be set.
    @Test
    public void testEveryTimeoutIsSet() {

        RequestConfig config = CDSHttpClient.requestConfig();
        assertEquals(config.getConnectTimeout(), CDSHttpClient.CONNECT_TIMEOUT_MILLIS);
        assertEquals(config.getSocketTimeout(), CDSHttpClient.SOCKET_TIMEOUT_MILLIS);
        assertEquals(config.getConnectionRequestTimeout(), CDSHttpClient.CONNECTION_REQUEST_TIMEOUT_MILLIS);
        assertTrue(config.getConnectTimeout() > 0);
        assertTrue(config.getSocketTimeout() > 0);
        assertTrue(config.getConnectionRequestTimeout() > 0);
    }

    @Test
    public void testTheAdminCallsWaitLongerForCDSOnly() {

        RequestConfig config = CDSHttpClient.adminRequestConfig();
        assertEquals(config.getSocketTimeout(), CDSHttpClient.ADMIN_SOCKET_TIMEOUT_MILLIS);
        assertTrue(config.getSocketTimeout() > CDSHttpClient.SOCKET_TIMEOUT_MILLIS);
        assertEquals(config.getConnectTimeout(), CDSHttpClient.CONNECT_TIMEOUT_MILLIS);
        assertEquals(config.getConnectionRequestTimeout(), CDSHttpClient.CONNECTION_REQUEST_TIMEOUT_MILLIS);
    }
}
