package com.bloggingapp.exception;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResourceNotFoundException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	String resourceName;
	String fieldName;
	int userId;
	public ResourceNotFoundException(String resourceName, String fieldName, int userId) {
		super(String.format("%s not foun with %s : %s", resourceName,fieldName,userId));
		this.resourceName = resourceName;
		this.fieldName = fieldName;
		this.userId = userId;
	}
	
}
