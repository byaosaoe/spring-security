package com.example.security.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.security.model.MemberDetails;
import com.example.security.model.Post;

@Service
public class PostService {

	private final Logger log = LoggerFactory.getLogger(PostService.class);
	
	@Autowired
	private CustomUserDetailsManager customUserDetailsManager;
	
	public List<Post> retrieveAllPostByEmail(String email) {
		log.info("POST SERVICE - RETRIEVE");
		MemberDetails memberDetails = customUserDetailsManager.loadUserByUsername(email);
		List<Post> postList = memberDetails.getMember().getPosts();
		return postList;
	}
}