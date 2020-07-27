/*
 * Copyright 2005 - 2020 Alfresco Software Limited.
 *
 * This file is part of the Alfresco software.
 * If the software was purchased under a paid Alfresco license, the terms of the paid license agreement will prevail.
 * Otherwise, the software is provided under the following open source license terms:
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */
package org.alfresco.web.webscripts;

import junit.framework.TestCase;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.http.HttpHeaders;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicHeader;
import org.codehaus.plexus.util.Base64;
import org.htmlparser.http.HttpHeader;
import org.junit.Assert;
import org.springframework.extensions.surf.util.URLEncoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class HttpBasicAuthenticationTest extends TestCase
{
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "admin";

    private static final String TOKEN = "Alfresco-CSRFToken";

    protected String generateAuthorizationHeaderValue(String username, String password)
    {
        return "Basic " + new String(Base64.encodeBase64((username + ":" + password).getBytes(StandardCharsets.UTF_8)));
    }

    protected String generateCSRFTokenCookieValue(String token)
    {
        return TOKEN + "=" + URLEncoder.encode(token) + ";";
    }

    /**
     *
     * @return
     */
    protected String generateCSRFToken()
    {
        byte[] bytes = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        return org.springframework.extensions.surf.util.Base64.encodeBytes(bytes);
    }

    /**
     *
     * @throws IOException
     */
    public void testAuthenticationWithValidCredentials() throws IOException
    {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet("http://localhost:8080/share/page/surfBugStatus");

        request.setHeader(HttpHeaders.AUTHORIZATION, this.generateAuthorizationHeaderValue(ADMIN_USERNAME, ADMIN_PASSWORD));

        CloseableHttpResponse response = client.execute(request);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    /**
     *
     * @throws IOException
     */
    public void testAuthenticationWithInvalidCredentials() throws IOException
    {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet("http://localhost:8080/share/page/surfBugStatus");

        request.setHeader(HttpHeaders.AUTHORIZATION, this.generateAuthorizationHeaderValue(ADMIN_USERNAME, "invalid"));

        CloseableHttpResponse response = client.execute(request);
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusLine().getStatusCode());
    }

    /**
     *
     * @throws IOException
     */
    public void testCSRFWithValidHeaderAndCookieTokens() throws IOException
    {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        String token = this.generateCSRFToken();
        HttpPost request = new HttpPost("http://localhost:8080/share/service/components/dashboard/customise-dashboard");

        request.setHeader(HttpHeaders.AUTHORIZATION, this.generateAuthorizationHeaderValue(ADMIN_USERNAME, ADMIN_PASSWORD));
        request.setHeader(TOKEN, token);
        request.setHeader("Cookie", this.generateCSRFTokenCookieValue(token));
        request.setEntity(new StringEntity("{}", ContentType.APPLICATION_JSON));

        CloseableHttpResponse response = client.execute(request);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    /**
     *
     * @throws IOException
     */
    public void testCSRFWithInvalidHeaderToken() throws IOException
    {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        String token = this.generateCSRFToken();
        HttpPost request = new HttpPost("http://localhost:8080/share/service/components/dashboard/customise-dashboard");

        request.setHeader(HttpHeaders.AUTHORIZATION, this.generateAuthorizationHeaderValue(ADMIN_USERNAME, ADMIN_PASSWORD));
        request.setHeader(TOKEN, "invalid");
        request.setHeader("Cookie", this.generateCSRFTokenCookieValue(token));
        request.setEntity(new StringEntity("{}", ContentType.APPLICATION_JSON));

        CloseableHttpResponse response = client.execute(request);

        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusLine().getStatusCode());
    }

    /**
     *
     * @throws IOException
     */
    public void testCSRFWithInvalidCookieToken() throws IOException
    {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        String token = this.generateCSRFToken();
        HttpPost request = new HttpPost("http://localhost:8080/share/service/components/dashboard/customise-dashboard");

        request.setHeader(HttpHeaders.AUTHORIZATION, this.generateAuthorizationHeaderValue(ADMIN_USERNAME, ADMIN_PASSWORD));
        request.setHeader(TOKEN, token);
        request.setHeader("Cookie", this.generateCSRFTokenCookieValue("invalid"));
        request.setEntity(new StringEntity("{}", ContentType.APPLICATION_JSON));

        CloseableHttpResponse response = client.execute(request);

        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusLine().getStatusCode());
    }

    /**
     *
     * @throws IOException
     */
    public void testCSRFTokenWithoutHeaderAndCookieTokens() throws IOException
    {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpPost request = new HttpPost("http://localhost:8080/share/service/components/dashboard/customise-dashboard");

        request.setHeader(HttpHeaders.AUTHORIZATION, this.generateAuthorizationHeaderValue(ADMIN_USERNAME, ADMIN_PASSWORD));
        request.setEntity(new StringEntity("{}", ContentType.APPLICATION_JSON));

        CloseableHttpResponse response = client.execute(request);

        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusLine().getStatusCode());
    }
}
