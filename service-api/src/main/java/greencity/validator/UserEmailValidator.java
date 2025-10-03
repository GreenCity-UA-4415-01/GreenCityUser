package greencity.validator;

import greencity.annotations.EmailValidation;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.hibernate.validator.internal.constraintvalidators.bv.EmailValidator;
import org.springframework.stereotype.Component;

@Component
public class UserEmailValidator implements ConstraintValidator<EmailValidation, String> {
    private EmailValidator validator;

    public UserEmailValidator() {
        this.validator = new EmailValidator();
    }

    @Override
    public void initialize(EmailValidation constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
    }

    @Override
    public boolean isValid(String email, ConstraintValidatorContext context) {
        return validator.isValid(email, context);
    }

    public boolean isValid(String email) {
        return isValid(email, null);
    }

}
