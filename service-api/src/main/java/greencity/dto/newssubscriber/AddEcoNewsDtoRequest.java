package greencity.dto.newssubscriber;

import greencity.dto.econews.AddEcoNewsDtoResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AddEcoNewsDtoRequest {
    private List<NewsSubscriberResponseDto> subscribers;
    private AddEcoNewsDtoResponse newsDto;
}
