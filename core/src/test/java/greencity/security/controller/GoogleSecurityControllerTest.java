package greencity.security.controller;

import greencity.dto.user.GoogleUserDto;
import greencity.exception.exceptions.GoogleCodeExchangeException;
import greencity.exception.exceptions.GoogleIdTokenValidationException;
import greencity.exception.exceptions.StateMismatchException;
import greencity.security.dto.SuccessSignInDto;
import greencity.security.service.GoogleAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Google Security Controller Tests")
class GoogleSecurityControllerTest {

    @Mock
    private GoogleAuthService googleAuthService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private GoogleSecurityController googleSecurityController;

    private static final String VALID_CODE = "valid_code";
    private static final String VALID_STATE = "valid_state";

    private SuccessSignInDto createMockSuccessSignInDto() {
        return new SuccessSignInDto(
            1L,
            "mock.access.token.jwt",
            "mock.refresh.token.jwt",
            "Test User",
            false);
    }

    @Test
    @DisplayName("GET /auth/google should return 302 redirect with Location header")
    void redirectToGoogleConsent_ShouldReturn302AndCorrectLocationHeader() {
        final String expectedRedirectUrl =
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=cid&state=random_state";

        when(googleAuthService.generateGoogleAuthRedirectUrl(request, response))
            .thenReturn(expectedRedirectUrl);

        ResponseEntity<Void> actualResponse = googleSecurityController.redirectToGoogleConsent(request, response);

        verify(googleAuthService).generateGoogleAuthRedirectUrl(request, response);

        assertEquals(HttpStatus.FOUND, actualResponse.getStatusCode(),
            "The HTTP status code should be 302 Found.");

        assertTrue(actualResponse.getHeaders().containsKey(HttpHeaders.LOCATION),
            "The response must contain a Location header.");

        assertEquals(expectedRedirectUrl, actualResponse.getHeaders().getFirst(HttpHeaders.LOCATION),
            "The Location header value must match the URL returned by the service.");
    }

    @Test
    @DisplayName("Callback: Happy Path - Should return 200 OK with GoogleUserDto")
    void handleGoogleAuthCallback_HappyPath_ShouldReturn200() {
        SuccessSignInDto mockSignInDto = createMockSuccessSignInDto();

        when(googleAuthService.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, request, response))
            .thenReturn(mockSignInDto);

        ResponseEntity<SuccessSignInDto> actualResponse = googleSecurityController
            .handleGoogleAuthCallback(VALID_CODE, VALID_STATE, null, request, response);

        assertEquals(HttpStatus.OK, actualResponse.getStatusCode(), "Expected 200 OK status.");
        assertNotNull(actualResponse.getBody(), "Response body should not be null.");
        assertEquals(1L, actualResponse.getBody().getUserId(), "User ID should match mock DTO.");
        assertEquals("mock.access.token.jwt", actualResponse.getBody().getAccessToken(),
            "Access token should be returned.");
        assertFalse(actualResponse.getBody().isOwnRegistrations(), "ownRegistrations should be false for OAuth user.");

        verify(googleAuthService).handleGoogleAuthCallback(VALID_CODE, VALID_STATE, request, response);
    }

    @Test
    @DisplayName("Callback: State Mismatch - Should throw ResponseStatusException (400 Bad Request)")
    void handleGoogleAuthCallback_StateMismatch_ShouldReturn400() {
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any()))
            .thenThrow(new StateMismatchException("State error"));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
            () -> googleSecurityController.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, null, request, response));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode(), "Expected 400 Bad Request for StateMismatch.");
        assertTrue(Objects.requireNonNull(exception.getReason()).contains("State parameter mismatch"),
            "Reason should mention state mismatch.");
    }

    @Test
    @DisplayName("Callback: Invalid Code - Should throw ResponseStatusException (400 Bad Request)")
    void handleGoogleAuthCallback_InvalidCode_ShouldReturn400() {
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any()))
            .thenThrow(new GoogleCodeExchangeException("Code error"));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
            () -> googleSecurityController.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, null, request, response));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode(),
            "Expected 400 Bad Request for GoogleCodeExchangeException.");
        assertTrue(Objects.requireNonNull(exception.getReason()).contains("Invalid or expired authorization code"),
            "Reason should mention invalid code.");
    }

    @Test
    @DisplayName("Callback: Unverified Email - Should throw ResponseStatusException (400 Bad Request)")
    void handleGoogleAuthCallback_UnverifiedEmail_ShouldReturn400() {
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any()))
            .thenThrow(new GoogleIdTokenValidationException("Unverified email."));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
            () -> googleSecurityController.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, null, request, response));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode(),
            "Expected 400 Bad Request for validation failure.");
        assertTrue(Objects.requireNonNull(exception.getReason()).contains("ID Token validation failed"),
            "Reason should mention validation failure.");
    }

    @Test
    @DisplayName("Callback: Google Error Parameter - Should throw ResponseStatusException (400 Bad Request) and not call service")
    void handleGoogleAuthCallback_GoogleError_ShouldReturn400() {
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> googleSecurityController
            .handleGoogleAuthCallback(null, VALID_STATE, "access_denied", request, response));

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode(), "Expected 400 Bad Request for Google error.");
        assertTrue(
            Objects.requireNonNull(exception.getReason()).contains("Google authentication failed: access_denied"),
            "Reason should mention the Google error.");

        verify(googleAuthService, never()).handleGoogleAuthCallback(any(), any(), any(), any());
    }
}
