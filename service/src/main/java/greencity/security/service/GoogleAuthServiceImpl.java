package greencity.security.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import greencity.dto.user.GoogleUserDto;
import greencity.exception.exceptions.GoogleCodeExchangeException;
import greencity.exception.exceptions.GoogleIdTokenValidationException;
import greencity.exception.exceptions.StateMismatchException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;
import java.security.SecureRandom;
import java.util.*;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.stream.Collectors;

@Service
@Slf4j
public class GoogleAuthServiceImpl implements GoogleAuthService {
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.registration.google.scope}")
    private String scope;

    @Value("${spring.security.oauth2.client.registration.google.authorization-grant-type}")
    private String grantType;

    private final String responseType = "code";

    @Value("${spring.security.oauth2.client.provider.google.authorization-uri}")
    private String authorizationUri;

    @Value("${spring.security.oauth2.client.provider.google.token-uri}")
    private String tokenUri;

    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
    private final SecureRandom secureRandom = new SecureRandom();
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final RestTemplate restTemplate;

    /**
     * Constructor.
     *
     * @param authorizationRequestRepository we pass the OAuth2AuthorizationRequest
     *                                       to use Spring Security mechanisms
     */
    public GoogleAuthServiceImpl(
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository,
        GoogleIdTokenVerifier googleIdTokenVerifier,
        RestTemplate restTemplate) {
        this.authorizationRequestRepository = authorizationRequestRepository;
        this.googleIdTokenVerifier = googleIdTokenVerifier;
        this.restTemplate = restTemplate;
    }

    /**
     * Helper method to generate state.
     */
    private String generateState() {
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Helper method to build the request.
     */
    private OAuth2AuthorizationRequest buildAuthorizationRequest(String state) {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("access_type", "offline");

        return OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri(authorizationUri)
            .clientId(clientId)
            .redirectUri(redirectUri)
            .scopes(Arrays.stream(scope.split(",")).map(String::trim).collect(Collectors.toSet()))
            .additionalParameters(additionalParameters)
            .attributes(Collections.singletonMap(
                OAuth2ParameterNames.REGISTRATION_ID, "google"))
            .state(state)
            .build();
    }

    @Override
    public String generateGoogleAuthRedirectUrl(HttpServletRequest request, HttpServletResponse response) {
        String state = generateState();

        OAuth2AuthorizationRequest authorizationRequest = buildAuthorizationRequest(state);

        authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);

        String formattedScope = Arrays.stream(scope.split(","))
            .map(String::trim)
            .collect(java.util.stream.Collectors.joining(" "));

        return UriComponentsBuilder.fromUriString(authorizationUri)
            .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
            .queryParam(OAuth2ParameterNames.REDIRECT_URI, redirectUri)
            .queryParam(OAuth2ParameterNames.SCOPE, formattedScope)
            .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, responseType)
            .queryParam("state", state)
            .queryParam("access_type", "offline")
            .encode()
            .build()
            .toUriString();
    }

    /**
     * Exchanges the authorization code for tokens and validates the id_token.
     */
    @Override
    public GoogleUserDto handleGoogleAuthCallback(
        String code,
        String state,
        HttpServletRequest request,
        HttpServletResponse response) {
        OAuth2AuthorizationRequest savedRequest = authorizationRequestRepository
            .removeAuthorizationRequest(request, response);

        if (savedRequest == null || !savedRequest.getState().equals(state)) {
            log.error("State mismatch detected");
            throw new StateMismatchException("State parameter mismatch.");
        }

        MultiValueMap<String, String> tokenRequestParams = new LinkedMultiValueMap<>();
        tokenRequestParams.add("code", code);
        tokenRequestParams.add("client_id", clientId);
        tokenRequestParams.add("client_secret", clientSecret);
        tokenRequestParams.add("redirect_uri", redirectUri);
        tokenRequestParams.add("grant_type", grantType);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(tokenRequestParams, headers);

        TokenResponse tokenResponse;
        try {
            ResponseEntity<TokenResponse> responseEntity = restTemplate.postForEntity(
                tokenUri,
                requestEntity,
                TokenResponse.class);
            if (!responseEntity.getStatusCode().is2xxSuccessful() || responseEntity.getBody() == null) {
                log.error("Google token exchange failed with status: {}",
                    responseEntity.getStatusCode());
                throw new GoogleCodeExchangeException("Failed to exchange code for tokens.");
            }
            tokenResponse = responseEntity.getBody();
        } catch (RestClientException e) {
            log.error("HTTP error during Google token exchange", e);
            throw new GoogleCodeExchangeException("Invalid or expired code.");
        }

        String idTokenString = tokenResponse.getIdToken();
        if (idTokenString == null || idTokenString.isEmpty()) {
            throw new GoogleCodeExchangeException("Token response missing id_token.");
        }

        GoogleIdToken idToken;
        try {
            idToken = googleIdTokenVerifier.verify(idTokenString);
        } catch (GeneralSecurityException | IOException e) {
            log.error("Google ID Token verification failed", e);
            throw new GoogleIdTokenValidationException("ID Token validation failed.");
        }

        if (idToken == null) {
            throw new GoogleIdTokenValidationException("Invalid ID Token received.");
        }

        GoogleIdToken.Payload payload = idToken.getPayload();

        Boolean emailVerified = (Boolean) payload.get("email_verified");
        if (emailVerified == null || !emailVerified) {
            throw new GoogleIdTokenValidationException("Unverified email.");
        }

        return GoogleUserDto.builder()
            .sub(payload.getSubject())
            .email(payload.getEmail())
            .emailVerified(emailVerified)
            .name((String) payload.get("name"))
            .picture((String) payload.get("picture"))
            .build();
    }

    /** Inner class for deserializing the token endpoint response. */
    @Getter
    @Setter
    public static class TokenResponse {
        @JsonProperty("id_token")
        private String idToken;
    }
}