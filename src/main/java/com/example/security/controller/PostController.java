package com.example.security.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.security.model.MemberDetails;
import com.example.security.model.Post;
import com.example.security.service.PostService;

@RestController
@RequestMapping("/api/v1/users")
public class PostController {
	
	private final Logger log = LoggerFactory.getLogger(PostController.class);
	
	@Autowired
	private PostService postService;

	@GetMapping("/posts")
	public ResponseEntity<?> retrievePostByEmail(Authentication authentication) {
		log.info("RETRIEVE POSTS BY AUTH(JWT)");
		
		Object principal = authentication.getPrincipal();
		MemberDetails memberDetails = (MemberDetails) principal;
		
		List<Post> postList = postService.retrieveAllPostByEmail(memberDetails.getUsername());
		return ResponseEntity.ok(postList);
	}
}
