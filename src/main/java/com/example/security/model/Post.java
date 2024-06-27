package com.example.security.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Entity
@Table
public class Post {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long postId;
	private String title;
	private String content;
	private String imageUrl;
	private Long memberId;
	
	public String getTitle() {
		return title;
	}

	public String getContent() {
		return content;
	}
	
	public String getImageUrl() {
		return imageUrl;
	}
	
	@Builder
	public Post(String title, String content, String imageUrl, Long memberId) {
		this.title = title;
		this.content = content;
		this.imageUrl = imageUrl;
		this.memberId = memberId;
	}
}
