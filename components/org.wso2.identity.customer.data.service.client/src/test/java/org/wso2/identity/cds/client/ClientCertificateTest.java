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

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.expectThrows;

/**
 * Unit tests for {@link ClientCertificate}, against a stub CDD that requires a client certificate.
 */
public class ClientCertificateTest {

    private static final String KEYSTORE = "client-certificate-test.p12";
    private static final char[] PASSWORD = "testpass".toCharArray();
    private static final String[] TRUST_STORE_PROPERTIES = {"javax.net.ssl.trustStore",
            "javax.net.ssl.trustStorePassword", "javax.net.ssl.trustStoreType"};

    private KeyStore keyStore;
    private X509Certificate certificate;
    private HttpsServer cdd;
    private Properties savedProperties;

    @BeforeMethod
    public void setUp() throws Exception {

        keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(KEYSTORE)) {
            keyStore.load(in, PASSWORD);
        }
        certificate = (X509Certificate) keyStore.getCertificate("test");

        // CDD serves the test certificate, and trusts only it as a client certificate.
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, PASSWORD);
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(keyStore);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);

        cdd = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        cdd.setHttpsConfigurator(new HttpsConfigurator(serverContext) {
            @Override
            public void configure(HttpsParameters params) {

                SSLParameters parameters = serverContext.getDefaultSSLParameters();
                parameters.setNeedClientAuth(true);
                params.setSSLParameters(parameters);
            }
        });
        cdd.createContext("/", exchange -> {
            X509Certificate peer = (X509Certificate) ((HttpsExchange) exchange).getSSLSession()
                    .getPeerCertificates()[0];
            exchange.sendResponseHeaders(peer.equals(certificate) ? 204 : 403, -1);
            exchange.close();
        });
        cdd.start();

        // The Identity Server trusts CDD through the default trust managers, as it does with its trust store.
        savedProperties = new Properties();
        for (String property : TRUST_STORE_PROPERTIES) {
            if (System.getProperty(property) != null) {
                savedProperties.setProperty(property, System.getProperty(property));
            }
        }
        System.setProperty("javax.net.ssl.trustStore", getClass().getClassLoader().getResource(KEYSTORE).getPath());
        System.setProperty("javax.net.ssl.trustStorePassword", new String(PASSWORD));
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
    }

    @AfterMethod
    public void tearDown() throws Exception {

        cdd.stop(0);
        for (String property : TRUST_STORE_PROPERTIES) {
            System.clearProperty(property);
        }
        savedProperties.forEach((key, value) -> System.setProperty((String) key, (String) value));
        Field sslContext = ClientCertificate.class.getDeclaredField("sslContext");
        sslContext.setAccessible(true);
        sslContext.set(null, null);
    }

    @Test
    public void presentsTheKeyPairOfThePrimaryKeystore() throws Exception {

        KeyStoreManager keyStoreManager = mock(KeyStoreManager.class);
        when(keyStoreManager.getDefaultPrivateKey()).thenReturn((PrivateKey) keyStore.getKey("test", PASSWORD));
        when(keyStoreManager.getDefaultPrimaryCertificate()).thenReturn(certificate);
        when(keyStoreManager.getPrimaryKeyStore()).thenReturn(keyStore);

        try (MockedStatic<KeyStoreManager> keyStoreManagers = mockStatic(KeyStoreManager.class)) {
            keyStoreManagers.when(() -> KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID))
                    .thenReturn(keyStoreManager);

            assertEquals(get(), 204);
        }
    }

    @Test
    public void presentsNoCertificateWhenThePrimaryKeystoreCannotBeRead() throws Exception {

        try (MockedStatic<KeyStoreManager> keyStoreManagers = mockStatic(KeyStoreManager.class)) {
            keyStoreManagers.when(() -> KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID))
                    .thenThrow(new IllegalStateException("the keystore is not ready"));

            // CDD requires a certificate here, so the handshake fails; one that does not would take the call.
            expectThrows(IOException.class, this::get);
        }
    }

    private int get() throws Exception {

        try (CloseableHttpClient client = ClientCertificate.newHttpClient();
             CloseableHttpResponse response = client.execute(
                     new HttpGet("https://localhost:" + cdd.getAddress().getPort() + "/"))) {
            return response.getStatusLine().getStatusCode();
        }
    }
}
