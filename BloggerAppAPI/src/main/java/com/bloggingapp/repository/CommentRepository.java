package com.bloggingapp.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bloggingapp.entity.Comment;

public interface CommentRepository extends JpaRepository<Comment, Integer> {

}
