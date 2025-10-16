package greencity.dto.user;

import lombok.Builder;
import lombok.Value;

/**
 * DTO for validated Google identity data. sub is Google user ID
 */
@Value
@Builder
public class GoogleUserDto {
    String sub;
    String email;
    Boolean emailVerified;
    String name;
    String picture;
}
