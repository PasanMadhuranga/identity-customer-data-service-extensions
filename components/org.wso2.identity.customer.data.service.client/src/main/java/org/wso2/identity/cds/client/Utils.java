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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;
import org.wso2.securevault.commons.MiscellaneousUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;

/**
 * This class contains utility methods for the Customer Data Management Service client.
 */
public class Utils {

    private static final String SERVER_URL = "CustomerDataService.ServerURL";
    private static final String SYNC_URL = "CustomerDataService.SyncURL";

    /**
     * The URL the Identity Server calls CDD on: [customer_data_service] sync_url, the sync port of CDD, or
     * server_url when sync_url is not set, for a CDD that serves the sync endpoints on its public port.
     *
     * @return The URL of CDD for the calls of the Identity Server.
     */
    public static String getCDSServiceURL() {

        String syncURL = StringUtils.trimToNull(IdentityUtil.getProperty(SYNC_URL));
        return syncURL != null ? syncURL : IdentityUtil.getProperty(SERVER_URL);
    }

    /**
     * Where the Identity Server sends its syncs, and how CDD has to serve them for that.
     *
     * @return The message, or null when CDD is not enabled or no URL is set.
     */
    public static String describeSyncTarget() {

        if (!isCDSEnabled()) {
            return null;
        }
        String syncURL = StringUtils.trimToNull(IdentityUtil.getProperty(SYNC_URL));
        if (syncURL != null) {
            return "CDD syncs go to sync_url " + sanitizeForLog(syncURL) + ": CDD has to serve them on sync.addr.";
        }
        String serverURL = StringUtils.trimToNull(IdentityUtil.getProperty(SERVER_URL));
        if (serverURL == null) {
            return null;
        }
        return "CDD syncs go to server_url " + sanitizeForLog(serverURL) +
                ", as sync_url is not set: CDD has to serve them on addr.";
    }

  // Get Base64 encoded credentials for CDS admin user
    public static String getBase64EncodedCredentials() {

      String usernameProp =
              IdentityUtil.getProperty("CustomerDataService.AdminUsername");
      String passwordProp =
              IdentityUtil.getProperty("CustomerDataService.AdminPassword");

      String resolvedUserName = resolveIfRequired("CustomerDataService.AdminUsername",
                      StringUtils.trimToNull(usernameProp));

      String resolvedPassword = resolveIfRequired("CustomerDataService.AdminPassword",
                      StringUtils.trimToNull(passwordProp));

      if (StringUtils.isBlank(resolvedUserName) || StringUtils.isBlank(resolvedPassword)) {
          return "";
      }

      String credentials = resolvedUserName + ":" + resolvedPassword;

      return Base64.getEncoder()
              .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
  }


    public static boolean isCDSEnabled() {
        String cdsEnabled = IdentityUtil.getProperty("CustomerDataService.Enable");
        return Boolean.parseBoolean(cdsEnabled);
    }

    // Resolve secrets if secure vault is enabled
    public static String resolveIfRequired(String key, String value) {

        if (value == null) {
            return null;
        }

        Properties props = new Properties();
        props.put(key, value);

        SecretResolver resolver = SecretResolverFactory.create(props);

        if (resolver != null && resolver.isInitialized()) {
            return MiscellaneousUtil.resolve(value, resolver);
        }
        return value;
    }

    /**
     * Prevent CRLF/log forging.
     * Updated to handle more edge cases and satisfy scanners.
     */
    public static String sanitizeForLog(Object input) {
        if (input == null) {
            return "null";
        }
        String clean = String.valueOf(input);
        if (StringUtils.isBlank(clean)) {
            return "empty";
        }
        // Comprehensive CRLF replacement
        return clean.replace("\r", "_")
                .replace("\n", "_")
                .replaceAll("(?i)%0a", "_")
                .replaceAll("(?i)%0d", "_");
    }
}
