package greencity.security.service;

import greencity.dto.user.GoogleUserDto;
import greencity.dto.user.UserVO;
import greencity.entity.User;
import greencity.enums.EmailNotification;
import greencity.enums.Role;
import greencity.enums.UserStatus;
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
    private static final Long DEFAULT_LANGUAGE_ID = 2L; // Assuming 'en' is ID 2 from OwnSecurityServiceImpl
    private static final Double DEFAULT_RATING = 0.0; // From AppConstant/OwnSecurityServiceImpl

    private final UserRepo userRepo;
    private final JwtTool jwtTool;
    private final ModelMapper modelMapper;

    /**
     * Provisions the user based on Google ID Token data (provisioning logic from
     * steps 1-3).
     *
     * @param dto The extracted user data from Google ID Token.
     * @return SuccessSignInDto containing the user ID, tokens, and name.
     */
    @Override
    @Transactional
    public SuccessSignInDto provisionUserAndIssueToken(GoogleUserDto dto) {
        // Step 3: Check for user by (provider, provider_id) - existing Google user
        Optional<User> linkedUser = userRepo.findByProviderAndProviderId(GOOGLE_PROVIDER, dto.getSub());

        if (linkedUser.isPresent()) {
            User user = linkedUser.get();
            log.info("Found user {} by provider/id. Updating profile fields.", user.getEmail());
            // Step 3: Update profile fields
            updateUserProfile(user, dto);
            userRepo.save(user); // Save updates
            return issueTokens(user);
        }

        // 2. Check for user by email - for existing non-Google users (Steps 1 & 2)
        Optional<User> userByEmail = userRepo.findByEmail(dto.getEmail());

        if (userByEmail.isPresent()) {
            User user = userByEmail.get();
            log.info("User found by email: {}. Linking Google provider.", user.getEmail());
            linkGoogleProvider(user, dto);
            userRepo.save(user);
            return issueTokens(user);
        }

        // 3. If no user found, create a new user (Step 1)
        log.info("No user found. Creating new user for email: {}", dto.getEmail());
        User newUser = createNewGoogleUser(dto);
        userRepo.save(newUser);
        return issueTokens(newUser);
    }

    private User createNewGoogleUser(GoogleUserDto dto) {
        // Adapt logic from OwnSecurityServiceImpl.createNewRegisteredUser
        String refreshTokenKey = jwtTool.generateTokenKey();

        return User.builder()
            .name(dto.getName() != null ? dto.getName() : dto.getEmail().split("@")[0])
            .email(dto.getEmail())
            .dateOfRegistration(LocalDateTime.now())
            .role(Role.ROLE_USER)
            .refreshTokenKey(refreshTokenKey)
            .lastActivityTime(LocalDateTime.now())
            // Google users skip the CREATED/VerifyEmail stage, moving straight to ACTIVATED
            .userStatus(UserStatus.ACTIVATED)
            .emailNotification(EmailNotification.DISABLED)
            .rating(DEFAULT_RATING)
            .language(greencity.entity.Language.builder().id(DEFAULT_LANGUAGE_ID).build())
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
        user.setName(dto.getName());
        user.setProfilePicturePath(dto.getPicture());
        user.setLastActivityTime(LocalDateTime.now());
    }

    private SuccessSignInDto issueTokens(User user) {
        UserVO userVO = modelMapper.map(user, UserVO.class);

        String accessToken = jwtTool.createAccessToken(userVO.getEmail(), userVO.getRole());
        String refreshToken = jwtTool.createRefreshToken(userVO);

        String newRefreshTokenKey = jwtTool.generateTokenKey();
        user.setRefreshTokenKey(newRefreshTokenKey);
        userRepo.save(user);

        return new SuccessSignInDto(
            user.getId(),
            accessToken,
            refreshToken,
            user.getName(),
            true);
    }
}
