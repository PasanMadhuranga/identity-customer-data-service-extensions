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

package org.wso2.identity.cds.auth.listener;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.identity.cds.auth.listener.internal.AuthListenerServiceDataHolder;
import org.wso2.identity.cds.client.CDSClient;
import org.wso2.identity.cds.config.mgt.CDSConfigService;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.AUTHENTICATION_SUCCESS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.SESSION_EXPIRE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.SESSION_TERMINATE;

public class AuthEventListenerTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String USER_ID = "8a6e3c1f-6c1b-4d5e-9a3e-0e5c2b7d9f10";
    private static final String CDS_PROFILE = "cds_profile";
    private static final String TRACKER_PARAM = "anonymous_profile_tracker";
    private static final String COOKIE_VALUE = "c00kie-profile";
    private static final String PARAM_VALUE = "p4ram-profile";

    private AuthEventListener listener;
    private MockedStatic<CDSClient> cdsClient;
    private AuthenticationContext context;
    private AuthenticationRequest authenticationRequest;
    private Map<String, String> requestHeaders;

    @BeforeMethod
    public void setUp() throws Exception {

        listener = new AuthEventListener();
        CDSConfigService cdsConfigService = mock(CDSConfigService.class);
        when(cdsConfigService.isCDSEnabled(TENANT_DOMAIN)).thenReturn(true);
        AuthListenerServiceDataHolder.setCDSConfigService(cdsConfigService);
        cdsClient = mockStatic(CDSClient.class);

        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(user.getUserId()).thenReturn(USER_ID);
        requestHeaders = new HashMap<>();
        authenticationRequest = mock(AuthenticationRequest.class);
        when(authenticationRequest.getRequestHeaders()).thenReturn(requestHeaders);
        context = mock(AuthenticationContext.class);
        when(context.getTenantDomain()).thenReturn(TENANT_DOMAIN);
        when(context.getLastAuthenticatedUser()).thenReturn(user);
        when(context.getAuthenticationRequest()).thenReturn(authenticationRequest);
    }

    @AfterMethod
    public void tearDown() {

        cdsClient.close();
        AuthListenerServiceDataHolder.setCDSConfigService(null);
    }

    @Test
    public void testLoginSendsTheProfileFromTheContext() throws Exception {

        when(context.getProperty(CDS_PROFILE)).thenReturn(COOKIE_VALUE);

        listener.handleEvent(event(AUTHENTICATION_SUCCESS));

        Map<String, Object> payload = capturedPayload(AUTHENTICATION_SUCCESS);
        assertEquals(payload.get(AuthEventListener.PROFILE_COOKIE), COOKIE_VALUE);
        assertEquals(payload.get(AuthEventListener.USER_ID), USER_ID);
    }

    @Test
    public void testLoginWithoutAProfileSendsNothing() throws Exception {

        when(context.getProperty(CDS_PROFILE)).thenReturn(null);
        setQueryParam(PARAM_VALUE);

        listener.handleEvent(event(AUTHENTICATION_SUCCESS));

        cdsClient.verify(() -> CDSClient.triggerIdentityDataSync(anyString(), anyMap(), anyString()), never());
    }

    @Test
    public void testLogoutSendsTheProfileFromTheCookie() throws Exception {

        requestHeaders.put("cookie", "other=value; " + CDS_PROFILE + "=" + COOKIE_VALUE);
        setQueryParam(PARAM_VALUE);

        listener.handleEvent(event(SESSION_TERMINATE));

        Map<String, Object> payload = capturedPayload(SESSION_TERMINATE);
        assertEquals(payload.get(AuthEventListener.PROFILE_COOKIE), COOKIE_VALUE);
        assertEquals(payload.get(AuthEventListener.USER_ID), USER_ID);
    }

    @Test
    public void testLogoutDoesNotUseTheTrackerQueryParameter() throws Exception {

        setQueryParam(PARAM_VALUE);

        listener.handleEvent(event(SESSION_TERMINATE));

        Map<String, Object> payload = capturedPayload(SESSION_TERMINATE);
        assertFalse(payload.containsKey(AuthEventListener.PROFILE_COOKIE));
        assertEquals(payload.get(AuthEventListener.USER_ID), USER_ID);
    }

    @Test
    public void testSessionExpirySendsTheUserOfTheExpiredSessionAndTheCookie() throws Exception {

        AuthenticatedUser expiredSessionUser = mock(AuthenticatedUser.class);
        when(expiredSessionUser.getUserId()).thenReturn(USER_ID);
        when(context.getLastAuthenticatedUser()).thenReturn(null);
        when(context.getAuthenticationRequest()).thenReturn(null);
        when(context.getSubject()).thenReturn(expiredSessionUser);

        listener.handleEvent(expiryEvent(new Cookie("other", "value"), new Cookie(CDS_PROFILE, COOKIE_VALUE)));

        Map<String, Object> payload = capturedPayload(SESSION_EXPIRE);
        assertEquals(payload.get(AuthEventListener.PROFILE_COOKIE), COOKIE_VALUE);
        assertEquals(payload.get(AuthEventListener.USER_ID), USER_ID);
        assertEquals(payload.get(AuthEventListener.ORG_HANDLE), TENANT_DOMAIN);
    }

    @Test
    public void testSessionExpiryWithoutACookieSendsNothing() throws Exception {

        AuthenticatedUser expiredSessionUser = mock(AuthenticatedUser.class);
        when(expiredSessionUser.getUserId()).thenReturn(USER_ID);
        when(context.getSubject()).thenReturn(expiredSessionUser);

        listener.handleEvent(expiryEvent(new Cookie("other", "value")));

        cdsClient.verify(() -> CDSClient.triggerIdentityDataSync(anyString(), anyMap(), anyString()), never());
    }

    @Test
    public void testSessionExpiryWithoutAUserSendsNothing() throws Exception {

        when(context.getSubject()).thenReturn(null);

        listener.handleEvent(expiryEvent(new Cookie(CDS_PROFILE, COOKIE_VALUE)));

        cdsClient.verify(() -> CDSClient.triggerIdentityDataSync(anyString(), anyMap(), anyString()), never());
    }

    private Event expiryEvent(Cookie... cookies) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(cookies);
        Event event = event(SESSION_EXPIRE);
        event.getEventProperties().put("request", request);
        return event;
    }

    private void setQueryParam(String value) {

        when(authenticationRequest.getRequestQueryParam(TRACKER_PARAM)).thenReturn(new String[]{value});
    }

    private Event event(String eventName) {

        Map<String, Object> properties = new HashMap<>();
        properties.put("context", context);
        return new Event(eventName, properties);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> capturedPayload(String eventName) {

        ArgumentCaptor<Map<String, Object>> payload = ArgumentCaptor.forClass(Map.class);
        cdsClient.verify(() -> CDSClient.triggerIdentityDataSync(eq(eventName), payload.capture(),
                eq(TENANT_DOMAIN)));
        return payload.getValue();
    }
}
