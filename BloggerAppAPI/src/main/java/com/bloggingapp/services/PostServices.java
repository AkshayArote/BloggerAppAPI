package com.bloggingapp.services;

import java.util.List;

import com.bloggingapp.entity.Post;
import com.bloggingapp.payload.PostDto;
import com.bloggingapp.payload.PostResponse;

public interface PostServices {
	
	PostDto createPost(PostDto postdto,Integer userId,Integer categoryId);
	
	PostDto updatePost(PostDto postDto,Integer id);
	
	void deletePost(Integer id);
	
	//get all record
	PostResponse getAllPost(Integer pageNumber, Integer pageSize, String sortBy, String sortDir);
	
	//get by id
	PostDto getSinglePost(Integer id);
	
	//get all post by categary
	List<PostDto> getPostsByCategory(Integer categoryId);
	
	//get all post by
	List<PostDto> getPostByUser(Integer userId);
	
	//serch post
	List<PostDto> serchPosts(String keyword);

	
}
