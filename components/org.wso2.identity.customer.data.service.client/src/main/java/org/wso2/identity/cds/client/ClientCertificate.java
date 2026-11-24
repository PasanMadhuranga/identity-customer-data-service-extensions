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
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

/**
 * The client certificate the Identity Server presents to CDD: the key pair of its primary keystore. CDD requires it
 * on the sync endpoints when tls.require_client_cert is on. The server certificate of CDD is verified as before,
 * against the trust store of the Identity Server.
 */
final class ClientCertificate {

    private static final Log log = LogFactory.getLog(ClientCertificate.class);
    private static final String ALIAS = "cdd-client";
    private static final char[] IN_MEMORY_PASSWORD = new char[0];

    private static volatile SSLContext sslContext;

    private ClientCertificate() {
    }

    /**
     * An HTTP client that presents the client certificate, or none when the key pair cannot be loaded: a CDD that
     * does not require one still accepts the calls.
     *
     * @return A new HTTP client, which the caller closes.
     */
    static CloseableHttpClient newHttpClient() {

        SSLContext context = getSSLContext();
        if (context == null) {
            return HttpClients.createDefault();
        }
        return HttpClients.custom().setSSLContext(context).build();
    }

    // Only a context that loaded is kept, so a keystore that was not ready yet is read again on the next call.
    private static SSLContext getSSLContext() {

        if (sslContext == null) {
            synchronized (ClientCertificate.class) {
                if (sslContext == null) {
                    sslContext = buildSSLContext();
                }
            }
        }
        return sslContext;
    }

    private static SSLContext buildSSLContext() {

        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID);
            PrivateKey privateKey = keyStoreManager.getDefaultPrivateKey();
            X509Certificate certificate = keyStoreManager.getDefaultPrimaryCertificate();
            Certificate[] chain = certificateChainOf(keyStoreManager.getPrimaryKeyStore(), certificate);

            // A keystore of the one key pair, so the handshake cannot pick another entry of the primary keystore.
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setKeyEntry(ALIAS, privateKey, IN_MEMORY_PASSWORD, chain);

            // No trust material: the default trust managers, which read the trust store of the Identity Server.
            return SSLContexts.custom().loadKeyMaterial(keyStore, IN_MEMORY_PASSWORD).build();
        } catch (Exception | LinkageError e) {
            // A keystore that cannot be read leaves the calls as they were, without a client certificate.
            log.error("Could not load the key pair of the primary keystore. The calls to CDD present no client " +
                    "certificate, which a CDD with tls.require_client_cert on refuses.", e);
            return null;
        }
    }

    private static Certificate[] certificateChainOf(KeyStore primaryKeyStore, X509Certificate certificate)
            throws Exception {

        String alias = primaryKeyStore.getCertificateAlias(certificate);
        Certificate[] chain = alias == null ? null : primaryKeyStore.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            return new Certificate[]{certificate};
        }
        return chain;
    }
}
