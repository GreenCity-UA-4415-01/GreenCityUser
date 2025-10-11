package greencity.security.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import java.security.SecureRandom;
import java.util.*;

@Service
@Slf4j
public class GoogleAuthServiceImpl implements GoogleAuthService {
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.registration.google.scope}")
    private String scope;

    @Value("${spring.security.oauth2.client.registration.google.authorization-grant-type}")
    private String responseType;

    @Value("${spring.security.oauth2.client.provider.google.authorization-uri}")
    private String authorizationUri;

    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Constructor.
     * 
     * @param authorizationRequestRepository we pass the OAuth2AuthorizationRequest
     *                                       to use Spring Security mechanisms
     */
    public GoogleAuthServiceImpl(
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
        this.authorizationRequestRepository = authorizationRequestRepository;
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
            .scopes(Set.of(scope.split(",")))
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
}