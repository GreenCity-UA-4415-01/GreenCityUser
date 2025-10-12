package greencity.security.service;

import greencity.dto.user.GoogleUserDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Provides the interface to manage {@link GoogleAuthService} entity.
 *
 * @author Oleksandr Braiko
 * @version 1.0
 */
public interface GoogleAuthService {
    /**
     * Generates the Google Authorization URL, including the state parameter, and
     * persists the state for later verification.
     *
     * @param request  HttpServletRequest
     * @param response HttpServletResponse
     * @return The complete redirect URL to Google's consent screen.
     * @author Oleksandr Braiko
     */
    String generateGoogleAuthRedirectUrl(HttpServletRequest request, HttpServletResponse response);

    /**
     * Exchanges the authorization code for tokens, validates the id_token, and
     * extracts user identity data.
     *
     * @param code     The authorization code received from Google.
     * @param state    The state parameter received from Google.
     * @param request  The HttpServletRequest to retrieve the original authorization
     *                 request.
     * @param response The HttpServletResponse to remove the saved authorization
     *                 request.
     * @return A DTO containing validated user identity data.
     * @author Oleksandr Braiko
     */
    GoogleUserDto handleGoogleAuthCallback(String code, String state,
        HttpServletRequest request, HttpServletResponse response);
}