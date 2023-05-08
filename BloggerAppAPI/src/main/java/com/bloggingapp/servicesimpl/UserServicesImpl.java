package com.bloggingapp.servicesimpl;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.bloggingapp.entity.User;
import com.bloggingapp.exception.ResourceNotFoundException;
import com.bloggingapp.payload.UserDto;
import com.bloggingapp.repository.UserRepository;
import com.bloggingapp.services.UserServices;
import com.bloggingapp.utility.GlobleResources;

@Service
public class UserServicesImpl implements UserServices {
	
	private Logger logger=GlobleResources.getLogger(UserServicesImpl.class);
	
	@Autowired
	UserRepository userRepo;

	@Autowired
	ModelMapper modelMapper;
	
	
	@Override
	public UserDto addUser(UserDto userDto) {
		logger.info("Sarted addUser() Function");
		User user=null;
		User saveUser=null;
		try {
			user=this.userDtoToUser(userDto);
			saveUser=this.userRepo.save(user);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return this.userToUserDto(saveUser);
	}

	@Override
	public void deleteUser(Integer id) {
		logger.info("Sarted deleteUser() Function");
		try {
			this.userRepo.findById(id).orElseThrow(()-> new ResourceNotFoundException(" User "," id ",id));
			this.userRepo.deleteById(id);

		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// TODO Auto-generated method stub

	}

	@Override
	public UserDto getById(Integer id) {

		logger.info("Sarted getById() Function");
		String method=" getAllUser(Integer id)";
		logger.info(method);
		User user=this.userRepo.findById(id).orElseThrow(()-> new ResourceNotFoundException(" User" , " id ", id));
		
		
		return this.userToUserDto(user);
	}

	@Override
	public List<UserDto> getAllUser() {
		logger.info("Sarted getAllUser() Function");	
		List<User> allUser=null;
		List<UserDto> userDto=null;
		
		try {
			allUser=this.userRepo.findAll();
			userDto=allUser.stream().map(user->this.userToUserDto(user)).collect(Collectors.toList());
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return userDto;
	}

	@Override
	public UserDto updateUser(UserDto userDto, Integer id) {
		logger.info("Sarted updateUser() Function");
		User user=null;
		User updateId=null;
		UserDto userDto1=null;
		try {
			user=this.userRepo.findById(id).orElseThrow(()->new ResourceNotFoundException(" user ", " id ", id));
			user.setId(userDto.getId());
			user.setName(userDto.getName());
			user.setEmail(userDto.getEmail());
			user.setPassword(userDto.getPassword());
			user.setAbout(userDto.getAbout());
			
			updateId=this.userRepo.save(user);
			userDto1=this.userToUserDto(updateId);
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return userDto1;
	}
	
	
	
	
	public User userDtoToUser(UserDto userdto) {
		User user=this.modelMapper.map(userdto, User.class);
		return user;
	}
	
	public UserDto userToUserDto(User user) {
		UserDto userDto=this.modelMapper.map(user, UserDto.class);
		return userDto;
	}
	
	
//	User userDtoToUser(UserDto userDto) {
//		User user=new User();
//		user.setId(userDto.getId());
//		user.setName(userDto.getName());
//		user.setEmail(userDto.getEmail());
//		user.setPassword(userDto.getPassword());
//		user.setAbout(userDto.getAbout());
//		return user;
//	}
//	
//	UserDto userToUserDto(User user) {
//		UserDto userDto=new UserDto();
//		userDto.setId(user.getId());
//		userDto.setName(user.getName());
//		userDto.setEmail(user.getEmail());
//		userDto.setPassword(user.getPassword());
//		userDto.setAbout(user.getAbout());
//		return userDto;
//	}

}
