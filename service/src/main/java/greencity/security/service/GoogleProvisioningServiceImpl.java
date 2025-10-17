package greencity.security.service;

import greencity.dto.user.GoogleUserDto;
import greencity.dto.user.UserVO;
import greencity.entity.Language;
import greencity.entity.User;
import greencity.enums.EmailNotification;
import greencity.enums.Role;
import greencity.enums.UserStatus;
import greencity.repository.LanguageRepo;
import greencity.repository.UserRepo;
import greencity.security.dto.SuccessSignInDto;
import greencity.security.jwt.JwtTool;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoogleProvisioningServiceImpl implements GoogleProvisioningService {
    private static final String GOOGLE_PROVIDER = "GOOGLE";
    private static final String DEFAULT_LANGUAGE_CODE = "en";
    private static final Double DEFAULT_RATING = 0.0;

    private final UserRepo userRepo;
    private final JwtTool jwtTool;
    private final ModelMapper modelMapper;
    private final LanguageRepo languageRepo;

    /**
     * Provisions the user based on Google ID Token data. Steps: 1. If no user by
     * email → create a new user and link to Google provider. 2. If user exists by
     * email → link/update provider fields. 3. If user exists by (provider,
     * provider_id) → update profile fields. 4. Issue access token / refresh token
     * or session according to current authentication scheme.
     *
     * @param dto The extracted user data from Google ID Token.
     * @return SuccessSignInDto containing the user ID, tokens, and name.
     */
    @Override
    @Transactional
    public SuccessSignInDto provisionUserAndIssueToken(GoogleUserDto dto) {
        // 1. Check for user by (provider, provider_id) - existing Google user (Step 3).
        Optional<User> linkedUser = userRepo.findByProviderAndProviderId(GOOGLE_PROVIDER, dto.getSub());

        if (linkedUser.isPresent()) {
            User user = linkedUser.get();
            log.debug("Found user by provider/id: {}", maskEmail(user.getEmail()));
            updateUserProfile(user, dto);
            userRepo.save(user);
            // This is an existing linked Google user, so ownRegistrations is false.
            return issueTokens(user, false);
        }

        // 2. Check for user by email - for existing non-Google users (Step 2).
        Optional<User> userByEmail = userRepo.findByEmail(dto.getEmail());

        if (userByEmail.isPresent()) {
            User user = userByEmail.get();
            log.debug("User found by email: {} (linking Google)", maskEmail(user.getEmail()));
            linkGoogleProvider(user, dto);
            userRepo.save(user);
            // This user was previously registered via the app's own security, so
            // ownRegistrations is true.
            return issueTokens(user, true);
        }

        // 3. If no user found, create a new user (Step 1).
        log.debug("No user found. Creating new user for email: {}", maskEmail(dto.getEmail()));
        User newUser = createNewGoogleUser(dto);
        userRepo.save(newUser);
        // This is a brand-new Google user, so ownRegistrations is false.
        return issueTokens(newUser, false);
    }

    private User createNewGoogleUser(GoogleUserDto dto) {
        // Adapt logic from OwnSecurityServiceImpl.createNewRegisteredUser.
        String refreshTokenKey = jwtTool.generateTokenKey();

        Language defaultLanguage = languageRepo.findByCode(DEFAULT_LANGUAGE_CODE)
            .orElseThrow(() -> new IllegalStateException("Default language 'en' not found in database."));

        return User.builder()
            .name(dto.getName() != null ? dto.getName() : dto.getEmail().split("@")[0])
            .email(dto.getEmail())
            .dateOfRegistration(LocalDateTime.now())
            .role(Role.ROLE_USER)
            .refreshTokenKey(refreshTokenKey)
            .lastActivityTime(LocalDateTime.now())
            .userStatus(UserStatus.ACTIVATED)
            .emailNotification(EmailNotification.DISABLED)
            .rating(DEFAULT_RATING)
            .language(defaultLanguage)
            .uuid(UUID.randomUUID().toString())
            .provider(GOOGLE_PROVIDER)
            .providerId(dto.getSub())
            .emailVerified(dto.getEmailVerified())
            .profilePicturePath(dto.getPicture())
            .showLocation(true)
            .showEcoPlace(true)
            .showShoppingList(true)
            .build();
    }

    private void linkGoogleProvider(User user, GoogleUserDto dto) {
        user.setProvider(GOOGLE_PROVIDER);
        user.setProviderId(dto.getSub());
        user.setEmailVerified(dto.getEmailVerified());

        if (user.getProfilePicturePath() == null || user.getProfilePicturePath().isEmpty()) {
            user.setProfilePicturePath(dto.getPicture());
        }

        if (user.getName() == null || user.getName().isEmpty()) {
            user.setName(dto.getName());
        }
    }

    private void updateUserProfile(User user, GoogleUserDto dto) {
        user.setEmailVerified(dto.getEmailVerified());
        if (dto.getName() != null && !dto.getName().isEmpty()) {
            user.setName(dto.getName());
        }
        if (dto.getPicture() != null && !dto.getPicture().isEmpty()) {
            user.setProfilePicturePath(dto.getPicture());
        }
        user.setLastActivityTime(LocalDateTime.now());
    }

    private SuccessSignInDto issueTokens(User user, boolean ownRegistrations) {
        String newRefreshTokenKey = jwtTool.generateTokenKey();
        user.setRefreshTokenKey(newRefreshTokenKey);

        UserVO userVO = modelMapper.map(user, UserVO.class);

        String accessToken = jwtTool.createAccessToken(userVO.getEmail(), userVO.getRole());
        String refreshToken = jwtTool.createRefreshToken(userVO);

        userRepo.save(user);

        return new SuccessSignInDto(
            user.getId(),
            accessToken,
            refreshToken,
            user.getName(),
            ownRegistrations);
    }

    /** Inner method to mask email while logging. */
    private String maskEmail(String email) {
        if (email == null) {
            return "null";
        }
        int at = email.indexOf('@');
        if (at <= 1) {
            return "***";
        }
        return email.charAt(0) + "***@" + email.substring(at + 1);
    }
}
