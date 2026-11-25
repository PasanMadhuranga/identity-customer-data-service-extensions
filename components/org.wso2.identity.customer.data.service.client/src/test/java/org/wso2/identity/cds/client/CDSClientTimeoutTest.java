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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.identity.cds.client.exception.CDSServerException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Tests that the calls to CDS end when CDS accepts the connection but never responds, so a slow CDS cannot hold
 * the threads of the Identity Server.
 */
public class CDSClientTimeoutTest {

    private static final Log LOG = LogFactory.getLog(CDSClientTimeoutTest.class);
    private static final String TENANT = "acme";
    // Longer than the socket timeouts of the client, so a call that has no timeout is seen as stuck.
    private static final long CALL_LIMIT_SECONDS = 15;

    private ServerSocket stalledCds;
    private final List<Socket> heldConnections = new CopyOnWriteArrayList<>();
    private ExecutorService caller;
    private long lastCallMillis;

    @BeforeMethod
    public void setUp() throws IOException {

        // Accepts every connection and reads nothing, as a CDS that hangs does.
        stalledCds = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread acceptor = new Thread(() -> {
            while (!stalledCds.isClosed()) {
                try {
                    heldConnections.add(stalledCds.accept());
                } catch (IOException e) {
                    return;
                }
            }
        }, "stalled-cds");
        acceptor.setDaemon(true);
        acceptor.start();

        caller = Executors.newSingleThreadExecutor();
    }

    @AfterMethod
    public void tearDown() throws IOException {

        // Closing the connections also frees a call that is still stuck.
        stalledCds.close();
        for (Socket connection : heldConnections) {
            connection.close();
        }
        caller.shutdownNow();
    }

    @Test
    public void testConfigUpdateEndsWhenCDSDoesNotRespond() throws Exception {

        Throwable failure = callWithinLimit(() -> {
            CDSClient.updateCDSConfig(TENANT, true);
            return null;
        });
        assertTrue(failure instanceof CDSServerException, "Expected a CDSServerException, got " + failure);
        assertWaitedForTheAdminTimeout();
    }

    @Test
    public void testServiceCredentialsSyncEndsWhenCDSDoesNotRespond() throws Exception {

        Throwable failure = callWithinLimit(() -> CDSClient.syncServiceCredentials(TENANT, "acme-org-id",
                "acme-client", "acme-secret"));
        assertTrue(failure instanceof CDSServerException, "Expected a CDSServerException, got " + failure);
        assertWaitedForTheAdminTimeout();
    }

    // The sync events log the failure and return, so the sign-in or user operation that sent them goes on.
    @Test
    public void testProfileSyncEndsWhenCDSDoesNotRespond() throws Exception {

        Throwable failure = callWithinLimit(() -> {
            CDSClient.triggerProfileSync("POST_ADD_USER", new HashMap<>(), TENANT);
            return null;
        });
        assertTrue(failure == null, "Expected the profile sync to return, got " + failure);
        assertTrue(lastCallMillis < CDSHttpClient.ADMIN_SOCKET_TIMEOUT_MILLIS,
                "The profile sync waited " + lastCallMillis + " ms, as long as an admin call.");
    }

    // A socket timeout ends a call only after it, so a shorter call did not use the admin timeout.
    private void assertWaitedForTheAdminTimeout() {

        assertTrue(lastCallMillis >= CDSHttpClient.ADMIN_SOCKET_TIMEOUT_MILLIS,
                "The admin call ended after " + lastCallMillis + " ms, before the admin socket timeout.");
    }

    /**
     * Run a call on another thread and wait for it up to the limit. The static mocks are opened on that thread,
     * as Mockito applies a static mock only on the thread that opened it.
     *
     * @return The exception the call threw, or null if it returned.
     */
    private Throwable callWithinLimit(Callable<?> call) throws InterruptedException {

        long start = System.nanoTime();
        Future<?> result = caller.submit(() -> {
            try (MockedStatic<Utils> utils = mockStatic(Utils.class, Mockito.CALLS_REAL_METHODS);
                 MockedStatic<OrganizationPathResolver> pathResolver = mockStatic(OrganizationPathResolver.class)) {
                utils.when(Utils::getCDSServiceURL).thenReturn("http://127.0.0.1:" + stalledCds.getLocalPort());
                utils.when(Utils::getBase64EncodedCredentials).thenReturn("dXNlcjpwYXNz");
                pathResolver.when(() -> OrganizationPathResolver.pathOf(TENANT)).thenReturn("/t/" + TENANT);
                return call.call();
            }
        });
        try {
            result.get(CALL_LIMIT_SECONDS, TimeUnit.SECONDS);
            return null;
        } catch (ExecutionException e) {
            return e.getCause();
        } catch (TimeoutException e) {
            fail("The call to CDS was still waiting after " + CALL_LIMIT_SECONDS + " seconds.");
            return null;
        } finally {
            lastCallMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            LOG.info("[CDSClientTimeoutTest] call ended after " + lastCallMillis + " ms");
        }
    }
}
