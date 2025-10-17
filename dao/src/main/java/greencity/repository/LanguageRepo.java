package greencity.repository;

import greencity.entity.Language;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface LanguageRepo extends JpaRepository<Language, Long> {
    /**
     * Finds a language by its code (e.g., 'en', 'ua').
     *
     * @param code The language code.
     * @return An Optional containing the Language entity if found.
     */
    Optional<Language> findByCode(String code);
}
