package greencity.security.service;

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
}