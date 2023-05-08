package com.bloggingapp.services;

import com.bloggingapp.payload.CommentDto;

public interface CommentServices {
	CommentDto ctrateComment(CommentDto commentDto,Integer postId);
	void deleteComment(Integer commentId);

}
