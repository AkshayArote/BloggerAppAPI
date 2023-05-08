package com.bloggingapp.controller;
		
import java.lang.ModuleLayer.Controller;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bloggingapp.payload.ApiResponse;
import com.bloggingapp.payload.CommentDto;
import com.bloggingapp.services.CommentServices;
import com.bloggingapp.utility.GlobleResources;
	
@RestController
@RequestMapping("/api/")
	
public class CommentController {
	
	private Logger logger=GlobleResources.getLogger(Controller.class);
	
	@Autowired
	private CommentServices commentServices;
	
	@PostMapping("/posts/{postId}/comments")
	public ResponseEntity<CommentDto> createComment(@RequestBody CommentDto commetnt, @PathVariable Integer postId) {
		logger.info("Started createComment() Function");
		CommentDto createComment=null;
		
		try {			
			createComment=this.commentServices.ctrateComment(commetnt, postId);
		} catch (Exception e) {
			e.printStackTrace();
		}	
		return new ResponseEntity<CommentDto>(createComment,HttpStatus.CREATED);
	}	
	
	@DeleteMapping("/comments/{commentId}")
	public ResponseEntity<ApiResponse> deleteComment(@PathVariable Integer commentId){
		logger.info("Started deleteComment() Function");
		try {

			this.commentServices.deleteComment(commentId);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new ResponseEntity<ApiResponse>(new ApiResponse("Comment Deleted Successfully...!",true),HttpStatus.OK);
		
	}
	
}
