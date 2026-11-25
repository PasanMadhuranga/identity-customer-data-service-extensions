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
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

/**
 * The HTTP client of the calls to CDS. Without timeouts, a CDS that accepts a connection but does not respond holds
 * the calling thread, such as the thread of a sign-in, for as long as it does not respond. The client is shared, so
 * its connection pool also limits how many connections the Identity Server opens to CDS.
 */
final class CDSHttpClient {

    // Time to open the connection to CDS.
    static final int CONNECT_TIMEOUT_MILLIS = 2000;
    // Time to wait for data from CDS, between two packets of the response.
    static final int SOCKET_TIMEOUT_MILLIS = 3000;
    // The same for the calls an admin makes and waits for, as CDS calls the Identity Server back before it
    // responds to them.
    static final int ADMIN_SOCKET_TIMEOUT_MILLIS = 10000;
    // Time to wait for a free connection of the pool, when all of them are in use.
    static final int CONNECTION_REQUEST_TIMEOUT_MILLIS = 1000;
    // All the calls go to the one CDS, so the limit of the pool and of the route is the same.
    static final int MAX_CONNECTIONS = 20;

    private static final RequestConfig ADMIN_REQUEST_CONFIG = RequestConfig.copy(requestConfig())
            .setSocketTimeout(ADMIN_SOCKET_TIMEOUT_MILLIS)
            .build();

    private static volatile CloseableHttpClient client;

    private CDSHttpClient() {
    }

    /**
     * Get the shared client, creating it on first use. Callers close the response, not the client.
     *
     * @return The shared HTTP client.
     */
    static CloseableHttpClient get() {

        if (client == null) {
            synchronized (CDSHttpClient.class) {
                if (client == null) {
                    client = HttpClients.custom()
                            .setDefaultRequestConfig(requestConfig())
                            .setMaxConnTotal(MAX_CONNECTIONS)
                            .setMaxConnPerRoute(MAX_CONNECTIONS)
                            .build();
                }
            }
        }
        return client;
    }

    static RequestConfig requestConfig() {

        return RequestConfig.custom()
                .setConnectTimeout(CONNECT_TIMEOUT_MILLIS)
                .setSocketTimeout(SOCKET_TIMEOUT_MILLIS)
                .setConnectionRequestTimeout(CONNECTION_REQUEST_TIMEOUT_MILLIS)
                .build();
    }

    /**
     * Get the request config of the calls an admin makes and waits for, such as enabling CDS. It differs from the
     * default of the client only in the socket timeout.
     *
     * @return The request config of the admin calls.
     */
    static RequestConfig adminRequestConfig() {

        return ADMIN_REQUEST_CONFIG;
    }
}
