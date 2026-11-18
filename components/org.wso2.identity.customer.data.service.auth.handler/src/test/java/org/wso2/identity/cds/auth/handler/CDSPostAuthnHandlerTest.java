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

package org.wso2.identity.cds.auth.handler;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.identity.cds.auth.handler.internal.CDSPostAuthHandlerDataHolder;
import org.wso2.identity.cds.config.mgt.CDSConfigService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class CDSPostAuthnHandlerTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String CDS_PROFILE = "cds_profile";
    private static final String TRACKER_PARAM = "anonymous_profile_tracker";
    private static final String COOKIE_VALUE = "c00kie-profile";
    private static final String PARAM_VALUE = "p4ram-profile";

    private CDSPostAuthnHandler handler;
    private CDSConfigService cdsConfigService;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private AuthenticationContext context;

    @BeforeMethod
    public void setUp() throws Exception {

        handler = new CDSPostAuthnHandler();
        cdsConfigService = mock(CDSConfigService.class);
        when(cdsConfigService.isCDSEnabled(TENANT_DOMAIN)).thenReturn(true);
        CDSPostAuthHandlerDataHolder.setCDSConfigService(cdsConfigService);

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        context = mock(AuthenticationContext.class);
        when(context.getTenantDomain()).thenReturn(TENANT_DOMAIN);
    }

    @AfterMethod
    public void tearDown() {

        CDSPostAuthHandlerDataHolder.setCDSConfigService(null);
    }

    @Test
    public void testProfileFromTheCookie() throws Exception {

        when(request.getCookies()).thenReturn(new Cookie[]{
                new Cookie("other", "value"), new Cookie(CDS_PROFILE, COOKIE_VALUE)});

        assertEquals(handler.handle(request, response, context), PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED);
        verify(context).setProperty(CDS_PROFILE, COOKIE_VALUE);
    }

    @Test
    public void testTrackerQueryParameterIsNotUsedWithoutTheCookie() throws Exception {

        when(request.getCookies()).thenReturn(null);
        setAuthorizeQueryParam(PARAM_VALUE);

        assertEquals(handler.handle(request, response, context), PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED);
        verify(context, never()).setProperty(eq(CDS_PROFILE), anyString());
    }

    @Test
    public void testTrackerQueryParameterIsNotUsedWhenTheCookieIsBlank() throws Exception {

        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(CDS_PROFILE, " ")});
        setAuthorizeQueryParam(PARAM_VALUE);

        assertEquals(handler.handle(request, response, context), PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED);
        verify(context, never()).setProperty(eq(CDS_PROFILE), anyString());
    }

    @Test
    public void testCookieWinsOverTheTrackerQueryParameter() throws Exception {

        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(CDS_PROFILE, COOKIE_VALUE)});
        setAuthorizeQueryParam(PARAM_VALUE);

        handler.handle(request, response, context);
        verify(context).setProperty(CDS_PROFILE, COOKIE_VALUE);
        verify(context, never()).setProperty(CDS_PROFILE, PARAM_VALUE);
    }

    @Test
    public void testNoProfileWhenThereIsNoCookie() throws Exception {

        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("other", "value")});

        assertEquals(handler.handle(request, response, context), PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED);
        verify(context, never()).setProperty(eq(CDS_PROFILE), anyString());
    }

    @Test
    public void testNothingIsSetWhenCDSIsDisabled() throws Exception {

        when(cdsConfigService.isCDSEnabled(TENANT_DOMAIN)).thenReturn(false);
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(CDS_PROFILE, COOKIE_VALUE)});

        assertEquals(handler.handle(request, response, context), PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED);
        verify(context, never()).setProperty(eq(CDS_PROFILE), anyString());
    }

    private void setAuthorizeQueryParam(String value) {

        AuthenticationRequest authenticationRequest = mock(AuthenticationRequest.class);
        when(authenticationRequest.getRequestQueryParam(TRACKER_PARAM)).thenReturn(new String[]{value});
        when(context.getAuthenticationRequest()).thenReturn(authenticationRequest);
    }
}
