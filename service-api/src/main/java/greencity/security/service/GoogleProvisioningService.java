package greencity.security.service;

import greencity.dto.user.GoogleUserDto;
import greencity.security.dto.SuccessSignInDto;

/**
 * Provides the interface to manage {@link GoogleProvisioningService} entity.
 *
 * @author Oleksandr Braiko
 * @version 1.0
 */
public interface GoogleProvisioningService {
    /**
     * Method to integrate Google authenticated user to a local DB. Either by
     * checking whether the user exists, or by creating a new one.
     *
     * @param googleUserDto - DTO of Google authentication.
     * @return Successful SignIn DTO to keep unified data objects with existing
     *         OwnSecurity logic.
     * @author Oleksandr Braiko
     */
    SuccessSignInDto provisionUserAndIssueToken(GoogleUserDto googleUserDto);
}
