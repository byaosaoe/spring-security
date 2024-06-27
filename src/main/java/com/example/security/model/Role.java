package com.example.security.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
	
	ADMIN("ROLE_ADMIN", "Admin"),
	USER("ROLE_USER", "User");

	private final String key;
	private final String title;

}