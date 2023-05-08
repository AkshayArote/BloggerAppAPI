package com.bloggingapp.repository;
	
import java.util.List;
	
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;

import com.bloggingapp.entity.Category;
import com.bloggingapp.entity.Post;
import com.bloggingapp.entity.User;

@Service
public interface PostRepository extends JpaRepository<Post, Integer> {
	
	List<Post> findByUser(User user);
	
	
	List<Post> findByCategory(Category category);
	
	List<Post> findByTitleContaining(String title);
	
}	