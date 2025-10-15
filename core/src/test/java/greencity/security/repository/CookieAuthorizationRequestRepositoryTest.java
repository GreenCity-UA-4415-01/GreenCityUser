package greencity.security.repository;

import greencity.exception.exceptions.CookieDeserializeException;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the CookieAuthorizationRequestRepository. Verifies that OAuth2
 * authorization requests are correctly saved to, loaded from, and removed from
 * HTTP cookies.
 */
class CookieAuthorizationRequestRepositoryTest {
    private CookieAuthorizationRequestRepository repository;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private static final OAuth2AuthorizationRequest MOCK_AUTH_REQUEST = OAuth2AuthorizationRequest.authorizationCode()
        .authorizationUri("https://example.com/oauth/authorize")
        .clientId("client-id")
        .redirectUri("http://localhost:8080/auth/google/callback")
        .scopes(Collections.singleton("openid"))
        .state("test-state-1234")
        .attributes(Map.of(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue()))
        .build();

    @BeforeEach
    void setUp() {
        repository = new CookieAuthorizationRequestRepository();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    /**
     * Helper to get a cookie by name from the response.
     */
    private Cookie getResponseCookie(String name) {
        return response.getCookie(name);
    }

    @Test
    void testSaveAuthorizationRequest_shouldSetCookie() {
        repository.saveAuthorizationRequest(MOCK_AUTH_REQUEST, request, response);

        Cookie authCookie =
            getResponseCookie(CookieAuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        assertNotNull(authCookie, "Auth Request cookie must be set");
        assertTrue(authCookie.isHttpOnly(), "Cookie must be HTTP-only for security");
        assertTrue(authCookie.getSecure(), "Cookie must be Secure");
        assertEquals("/", authCookie.getPath(), "Cookie path must be root");
        assertEquals(180, authCookie.getMaxAge(), "Cookie max age must be 180 seconds");
    }

    @Test
    void testSaveNullAuthorizationRequest_shouldRemoveCookies() {
        request.setCookies(
            new Cookie(CookieAuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, "dummy"),
            new Cookie(CookieAuthorizationRequestRepository.REDIRECT_URI_COOKIE_NAME, "dummy"));

        repository.saveAuthorizationRequest(null, request, response);

        assertEquals(0, getResponseCookie(CookieAuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
            .getMaxAge());
        assertEquals(0, getResponseCookie(CookieAuthorizationRequestRepository.REDIRECT_URI_COOKIE_NAME).getMaxAge());
    }

    @Test
    void testLoadAuthorizationRequest_shouldLoadFromCookie() {
        String serializedRequest = repository.serialize(MOCK_AUTH_REQUEST);
        request.setCookies(
            new Cookie(CookieAuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                serializedRequest));

        OAuth2AuthorizationRequest loadedRequest = repository.loadAuthorizationRequest(request);

        assertNotNull(loadedRequest, "Loaded request should not be null");
        assertEquals(MOCK_AUTH_REQUEST.getState(), loadedRequest.getState(), "State must match");
        assertEquals(MOCK_AUTH_REQUEST.getAuthorizationUri(), loadedRequest.getAuthorizationUri(), "URI must match");
    }

    @Test
    void testLoadAuthorizationRequest_shouldReturnNullWhenNoCookie() {
        assertNull(repository.loadAuthorizationRequest(request), "Should return null if no cookie is present");
    }

    @Test
    void testLoadThrowsCookieDeserializeException_forCorruptCookie() {
        request.setCookies(
            new Cookie(CookieAuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                "not-a-valid-serialized-object"));

        assertThrows(CookieDeserializeException.class, () -> repository.loadAuthorizationRequest(request),
            "Loading a corrupt cookie must throw CookieDeserializeException");
    }

    @Test
    void testRemoveAuthorizationRequest_shouldRemoveCookiesAndReturnRequest() {
        String serializedRequest = repository.serialize(MOCK_AUTH_REQUEST);
        request.setCookies(
            new Cookie(CookieAuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                serializedRequest));

        OAuth2AuthorizationRequest removedRequest = repository.removeAuthorizationRequest(request, response);

        assertNotNull(removedRequest, "Removed request should return the loaded request object");
        assertEquals(MOCK_AUTH_REQUEST.getState(), removedRequest.getState(),
            "The returned request state must match original");

        assertEquals(0, getResponseCookie(CookieAuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
            .getMaxAge());
    }
}
