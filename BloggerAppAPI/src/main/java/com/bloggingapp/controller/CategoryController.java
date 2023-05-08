package com.bloggingapp.controller;

import java.util.List;

import org.hibernate.query.NativeQuery.ReturnableResultNode;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bloggingapp.payload.ApiResponse;
import com.bloggingapp.payload.CategoryDto;
import com.bloggingapp.services.CategoryServices;
import com.bloggingapp.utility.GlobleResources;

import jakarta.validation.Valid;
import lombok.Getter;

@RestController
@RequestMapping("/api/category/")
public class CategoryController {
	
	private Logger logger=GlobleResources.getLogger(CategoryController.class);

	@Autowired
	private CategoryServices service;

	// Post-add category
	@PostMapping("/")
	public ResponseEntity<CategoryDto> addCategory(@Valid @RequestBody CategoryDto categoryDto) {
		logger.info("Started addCategory() Function");
		CategoryDto dto=null;
		try {
			dto = this.service.addCategory(categoryDto);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return new ResponseEntity<CategoryDto>(dto, HttpStatus.OK);
	}

	// PUT-update date
	@PutMapping("/{id}")
	public ResponseEntity<CategoryDto> updateCategory(@Valid @RequestBody CategoryDto category,
			@PathVariable("id") Integer id) {
		logger.info("Started updateCategory() Function");
		CategoryDto update =null;
		try {
			update= this.service.updateCategory(category, id);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return  new ResponseEntity<CategoryDto>(update, HttpStatus.OK);

	}

	// Delete
	@DeleteMapping("/{id}")
	public ResponseEntity<ApiResponse> delteCategory(@PathVariable("id") Integer id) {
		logger.info("Started deleteCategory() Function");

		try {
			this.service.deleteCategory(id);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new ResponseEntity(new ApiResponse("Category deleted successfylly...", true), HttpStatus.OK);
	}

	// GET-det single category
	@GetMapping("/{id}")
	public ResponseEntity<CategoryDto> getCategory(@PathVariable("id") Integer id) {
		logger.info("Started getCategory() Function");
		return ResponseEntity.ok(this.service.getCategory(id));

	}

	// GET-all category
	@GetMapping("/")
	public ResponseEntity<List<CategoryDto>> getAllCategory() {
		logger.info("Started getAllCategory() Function");

		return ResponseEntity.ok(this.service.getAllCategory());
	}
}
