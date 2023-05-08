package com.bloggingapp.services;

import java.util.List;

import com.bloggingapp.payload.CategoryDto;

public interface CategoryServices {

	//add
	CategoryDto addCategory(CategoryDto categoryDto);
	
	//update
	CategoryDto updateCategory(CategoryDto categoryDto,Integer id);
	
	//delete
	void deleteCategory(Integer id);
	
	//get Category
	CategoryDto getCategory(Integer id);
	
	//get all category
	List<CategoryDto> getAllCategory();
}
