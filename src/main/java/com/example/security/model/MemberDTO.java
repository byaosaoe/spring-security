package com.example.security.model;

import lombok.Builder;
import lombok.NoArgsConstructor;

@NoArgsConstructor
public class MemberDTO {
	
	private String email;
	private String nickname;
	private String password;
	private String provider;
	private String providerId;
	
	public String getEmail() {
		return email;
	}

	public String getPassword() {
		return password;
	}
	
	public String getNickname() {
		return nickname;
	}
	
	public String getProvider() {
		return provider;
	}
	
	public String getProviderId() {
		return providerId;
	}

	//@Builder
	//public MemberDTO(String email, String password, String refreshToken, String nickname, String provider, String providerId) {
	//	this.email = email;
    //    this.password = password;
    //    this.nickname = nickname;
    //    this.provider = provider;
    //    this.providerId = providerId;
	//}
	
	public void setEmail(String email) {
		this.email = email;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setNickname(String nickname) {
		this.nickname = nickname;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public void setProviderId(String providerId) {
		this.providerId = providerId;
	}
}
