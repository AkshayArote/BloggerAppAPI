package com.bloggingapp.payload;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@Setter
public class CategoryDto {
	private int categoryId;
	@NotEmpty
	private String categoryTitle;
	@NotEmpty
	@Size(min = 4,message = "Description must be 4 character !!")
	private String categoryDescription;

}
