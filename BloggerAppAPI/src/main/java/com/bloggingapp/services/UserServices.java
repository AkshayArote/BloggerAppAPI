package com.bloggingapp.services;

import java.util.List;

import com.bloggingapp.payload.UserDto;

public interface UserServices {
	
	UserDto addUser(UserDto userDto);
	
	void deleteUser(Integer id);
	
	UserDto getById(Integer id);
	
	List<UserDto> getAllUser();
	
	UserDto updateUser(UserDto userDto,Integer Id);
		
	

}
