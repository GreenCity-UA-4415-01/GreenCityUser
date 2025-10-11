package greencity.security.controller;

import greencity.annotations.ApiLocale;
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
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

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
}
