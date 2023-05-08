package com.bloggingapp.servicesimpl;

import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.ui.ModelMap;

import com.bloggingapp.entity.Comment;
import com.bloggingapp.entity.Post;
import com.bloggingapp.exception.ResourceNotFoundException;
import com.bloggingapp.payload.CommentDto;
import com.bloggingapp.payload.PostResponse;
import com.bloggingapp.repository.CommentRepository;
import com.bloggingapp.repository.PostRepository;
import com.bloggingapp.services.CommentServices;
import com.bloggingapp.utility.GlobleResources;

@Service
public class CommentSetvicesImpl implements CommentServices {
	
	private Logger logger=GlobleResources.getLogger(CommentSetvicesImpl.class);

	@Autowired
	private CommentRepository commentRepo;

	@Autowired
	private PostRepository postRepo;
	
	@Autowired
	private ModelMapper modelMapper;
	
	

	@Override
	public CommentDto ctrateComment(CommentDto commentDto, Integer postId) {
		logger.info("Sarted createComment() Function");

		Post post =null;
		Comment comment=null;
		Comment saveComment=null;
		
		try {
			post = this.postRepo.findById(postId)
					.orElseThrow(() -> new ResourceNotFoundException("Post", " id ", postId));

			comment=this.modelMapper.map(commentDto, Comment.class);
			
			comment.setPost(post);
			
			saveComment=this.commentRepo.save(comment);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
		return this.modelMapper.map(saveComment, CommentDto.class);
	}

	@Override
	public void deleteComment(Integer commentId) {
		logger.info("Sarted deleteComment() Function");

		Comment comment=null;
		
		try {
			comment=this.commentRepo.findById(commentId).orElseThrow(()->new ResourceNotFoundException("Comment", " id ", commentId));

		} catch (Exception e) {
			e.printStackTrace();
		}
		
		this.commentRepo.deleteById(commentId);

	}

}
