package greencity.security.controller;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("MainController Integration Tests")
class MainControllerTest {

    @Mock
    private GoogleAuthService googleAuthService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private GoogleSecurityController googleSecurityController;

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
}
