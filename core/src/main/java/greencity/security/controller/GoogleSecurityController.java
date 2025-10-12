package greencity.security.controller;

import greencity.annotations.ApiLocale;
import greencity.dto.user.GoogleUserDto;
import greencity.exception.exceptions.GoogleCodeExchangeException;
import greencity.exception.exceptions.GoogleIdTokenValidationException;
import greencity.exception.exceptions.StateMismatchException;
import greencity.security.service.GoogleAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/**
 * Controller that provides Google OAuth2 authentication logic.
 *
 * @author Oleksandr Braiko
 * @version 1.0
 */
@RestController
@Validated
@Slf4j
public class GoogleSecurityController {
    private final GoogleAuthService googleAuthService;

    public GoogleSecurityController(GoogleAuthService googleAuthService) {
        this.googleAuthService = googleAuthService;
    }

    /**
     * GET /auth/google - redirect user to Google consent with CSRF state.
     *
     * @return 302 FOUND status and redirects to Google's authorization endpoint.
     */
    @Operation(summary = "Redirect to Google consent with CSRF state")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "302", description = "Redirect to Google OAuth URL", headers = {
            @Header(name = "Location", description = "Google Authorization URL")
        }),
    })
    @GetMapping("/auth/google")
    @ApiLocale
    public ResponseEntity<Void> redirectToGoogleConsent(
        HttpServletRequest request,
        HttpServletResponse response) {
        String redirectUrl = googleAuthService.generateGoogleAuthRedirectUrl(request, response);

        return ResponseEntity
            .status(HttpStatus.FOUND)
            .header(HttpHeaders.LOCATION, redirectUrl)
            .build();
    }

    /**
     * GET /auth/google/callback - exchanges code for tokens, validates id_token.
     *
     * @param code     The authorization code from Google.
     * @param state    The state parameter for CSRF verification.
     * @param request  The HttpServletRequest.
     * @param response The HttpServletResponse.
     * @return User identity data or an error response.
     */
    @Operation(summary = "Google OAuth2 Callback: exchange code for tokens and validate id_token")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successful authentication and identity data retrieval"),
        @ApiResponse(responseCode = "400", description = "Invalid code, state mismatch, or unverified email"),
    })
    @GetMapping(value = "/auth/google/callback", produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiLocale
    public ResponseEntity<GoogleUserDto> handleGoogleAuthCallback(
        @RequestParam(name = "code", required = false) String code,
        @RequestParam(name = "state", required = false) String state,
        @RequestParam(name = "error", required = false) String error,
        HttpServletRequest request,
        HttpServletResponse response) {
        if (error != null) {
            log.error("Google authentication error: {}", error);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Google authentication failed: " + error);
        }

        if (code == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing authorization code.");
        }

        try {
            GoogleUserDto userDto = googleAuthService.handleGoogleAuthCallback(code, state, request, response);
            return ResponseEntity.ok(userDto);
        } catch (StateMismatchException e) {
            log.error("Authentication failed: State mismatch", e);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "State parameter mismatch. Possible CSRF attack.",
                e);
        } catch (GoogleCodeExchangeException e) {
            log.error("Authentication failed: Code exchange error", e);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired authorization code.", e);
        } catch (GoogleIdTokenValidationException e) {
            log.error("Authentication failed: ID Token validation error", e);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ID Token validation failed. " + e.getMessage(),
                e);
        } catch (Exception e) {
            log.error("Unexpected error during Google authentication callback", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred.", e);
        }
    }
}
