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

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * Unit tests for where {@link Utils} sends the calls to CDD: [customer_data_service] sync_url, or server_url when
 * sync_url is not set.
 */
public class UtilsSyncURLTest {

    private static final String PUBLIC = "https://cdd.example.com:8900";
    private static final String SYNC = "https://cdd.internal:8901";

    private final Map<String, String> properties = new HashMap<>();
    private MockedStatic<IdentityUtil> identityUtil;

    @BeforeMethod
    public void setUp() {

        properties.clear();
        properties.put("CustomerDataService.Enable", "true");
        identityUtil = mockStatic(IdentityUtil.class);
        identityUtil.when(() -> IdentityUtil.getProperty(anyString()))
                .thenAnswer(invocation -> properties.get(invocation.<String>getArgument(0)));
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
    }

    @Test
    public void callsGoToSyncURLWhenSet() {

        properties.put("CustomerDataService.ServerURL", PUBLIC);
        properties.put("CustomerDataService.SyncURL", SYNC);

        assertEquals(Utils.getCDSServiceURL(), SYNC);
    }

    @Test
    public void callsGoToServerURLWhenSyncURLIsNotSet() {

        properties.put("CustomerDataService.ServerURL", PUBLIC);

        assertEquals(Utils.getCDSServiceURL(), PUBLIC);
    }

    @Test
    public void blankSyncURLCountsAsNotSet() {

        properties.put("CustomerDataService.ServerURL", PUBLIC);
        properties.put("CustomerDataService.SyncURL", "  ");

        assertEquals(Utils.getCDSServiceURL(), PUBLIC);
    }

    @Test
    public void syncURLIsTrimmed() {

        properties.put("CustomerDataService.ServerURL", PUBLIC);
        properties.put("CustomerDataService.SyncURL", " " + SYNC + " ");

        assertEquals(Utils.getCDSServiceURL(), SYNC);
    }

    @Test
    public void describesTheSharedPortWhenSyncURLIsNotSet() {

        properties.put("CustomerDataService.ServerURL", PUBLIC);

        String message = Utils.describeSyncTarget();

        assertEquals(message, "CDD syncs go to server_url " + PUBLIC +
                ", as sync_url is not set: CDD has to serve them on addr.");
    }

    @Test
    public void describesTheSyncPortWhenSyncURLIsSet() {

        properties.put("CustomerDataService.ServerURL", PUBLIC);
        properties.put("CustomerDataService.SyncURL", SYNC);

        String message = Utils.describeSyncTarget();

        assertEquals(message, "CDD syncs go to sync_url " + SYNC + ": CDD has to serve them on sync.addr.");
    }

    @Test
    public void describesTheSyncPortWhenOnlySyncURLIsSet() {

        properties.put("CustomerDataService.SyncURL", SYNC);

        assertEquals(Utils.describeSyncTarget(), "CDD syncs go to sync_url " + SYNC +
                ": CDD has to serve them on sync.addr.");
    }

    @Test
    public void saysNothingWhenCDDIsNotEnabled() {

        properties.put("CustomerDataService.Enable", "false");
        properties.put("CustomerDataService.ServerURL", PUBLIC);

        assertNull(Utils.describeSyncTarget());
    }

    @Test
    public void saysNothingWhenNoURLIsSet() {

        assertNull(Utils.describeSyncTarget());
    }
}
