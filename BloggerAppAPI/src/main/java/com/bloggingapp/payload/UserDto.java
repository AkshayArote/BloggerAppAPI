package com.bloggingapp.payload;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;


import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
public class UserDto {
	
	
	private int id;
	
	@NotEmpty
	@Size(min = 4,message = "Username must be 4 character !!")
	private String name;
	@Email(message = "Email address is not valid !!")
	private String email;
	@NotEmpty
	@Size(min = 4,max=10,message="Password must be min 4 character and max 10 character !!")
	private String password;
	@NotEmpty
	private String about;

	
	
}
