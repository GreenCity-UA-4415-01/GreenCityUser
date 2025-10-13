package greencity.security.repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import greencity.exception.exceptions.CookieDeserializeException;
import greencity.exception.exceptions.CookieSerializeException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.StringUtils;
import java.io.*;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Stores and retrieves the OAuth2AuthorizationRequest in an HTTP-only cookie.
 * This is essential for maintaining state in a stateless application, as it
 * replaces the default HttpSession-based repository. The authorization request
 * contains the 'state' parameter for CSRF protection.
 */
public class CookieAuthorizationRequestRepository implements
    AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_COOKIE_NAME = "redirect_uri";

    private static final int COOKIE_MAX_AGE_SECONDS = 180;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
            .map(cookie -> deserialize(cookie, OAuth2AuthorizationRequest.class))
            .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(
        OAuth2AuthorizationRequest authorizationRequest,
        HttpServletRequest request,
        HttpServletResponse response) {
        if (authorizationRequest == null) {
            removeAuthorizationRequestCookies(request, response);
            return;
        }

        String serializedRequest = serialize(authorizationRequest);
        addCookie(response,
            OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
            serializedRequest,
            COOKIE_MAX_AGE_SECONDS);

        String redirectUri = (String) authorizationRequest.getAdditionalParameters()
            .get(REDIRECT_URI_COOKIE_NAME);

        if (StringUtils.hasText(redirectUri)) {
            addCookie(response, REDIRECT_URI_COOKIE_NAME, redirectUri, COOKIE_MAX_AGE_SECONDS);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(
        HttpServletRequest request,
        HttpServletResponse response) {
        OAuth2AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);

        removeAuthorizationRequestCookies(request, response);

        return authorizationRequest;
    }

    /**
     * Deletes the cookies created by this repository.
     */
    public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        deleteCookie(request, response, REDIRECT_URI_COOKIE_NAME);
    }

    /**
     * Retrieves the cookie with the given name from the request.
     */
    private Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Adds a new cookie to the response.
     */
    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        String header = String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; Secure; SameSite=Lax",
                name, value, maxAge);
        response.addHeader("Set-Cookie", header);
    }

    /**
     * Deletes a cookie by setting its maxAge to 0.
     */
    private void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        getCookie(request, name).ifPresent(cookie -> {
            cookie.setValue("");
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setMaxAge(0);
            String header = String.format("%s=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax", name);
            response.addHeader("Set-Cookie", header);
        });
    }

    /**
     * Serializes an object to a Base64-encoded string using standard Java
     * serialization.
     * 
     * @param object The object to serialize.
     * @return The Base64 encoded string.
     */
    public String serialize(Serializable object) {
        try {
            OAuth2AuthorizationRequest o = (OAuth2AuthorizationRequest) object;
            Map<String, Object> payload = Map.of(
                "authorizationUri", o.getAuthorizationUri(),
                "clientId", o.getClientId(),
                "redirectUri", o.getRedirectUri(),
                "scopes", o.getScopes(),
                "state", o.getState(),
                "attributes", o.getAttributes(),
                "additionalParameters", o.getAdditionalParameters());
            String json = MAPPER.writeValueAsString(payload);
            return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (IOException | ClassCastException e) {
            throw new CookieSerializeException("Serialization failed.", e);
        }
    }

    /**
     * Deserializes a Base64-encoded string back into an object using standard Java
     * serialization.
     * 
     * @param cookie The cookie containing the Base64 serialized object.
     * @param cls    The expected class of the deserialized object.
     * @return The deserialized object.
     */
    public <T> T deserialize(Cookie cookie, Class<T> cls) {
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(cookie.getValue());
            String json = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
            Map<String, Object> p = MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {
            });

            @SuppressWarnings("unchecked")
            OAuth2AuthorizationRequest result =
                OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri((String) p.get("authorizationUri"))
                    .clientId((String) p.get("clientId"))
                    .redirectUri((String) p.get("redirectUri"))
                    .scopes(new java.util.HashSet<>((java.util.List<String>) p.get("scopes")))
                    .state((String) p.get("state"))
                    .attributes((Map<String, Object>) p.getOrDefault("attributes", Map.of()))
                    .additionalParameters((Map<String, Object>) p.getOrDefault("additionalParameters", Map.of()))
                    .build();

            if (!cls.isInstance(result)) {
                throw new CookieDeserializeException("Unexpected deserialized type: " + result.getClass(), null);
            }
            return cls.cast(result);
        } catch (IOException | ClassCastException | IllegalArgumentException e) {
            throw new CookieDeserializeException("Deserialization failed.", e);
        }
    }
}
