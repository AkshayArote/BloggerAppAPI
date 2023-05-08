package com.bloggingapp.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bloggingapp.entity.Category;

public interface CategoryRepository extends JpaRepository<Category, Integer>{

}
