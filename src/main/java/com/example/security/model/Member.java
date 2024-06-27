package com.example.security.model;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.annotations.ColumnDefault;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Entity
@Table
public class Member extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	@Column(nullable = false)
	private String email;
	
	@Column(nullable = false)
	private String password;
	
	@Column(columnDefinition="text")
	private String refreshToken;
	
	@Column(nullable = false)
	@Enumerated(EnumType.STRING)
	private Role role;
	
	private String provider;
	
	private String providerId;
	
	@Column(nullable = false)
	private String nickname;
	
	@Builder
	public Member(String email, String password, String refreshToken, String nickname, String provider, String providerId) {
		this.email = email;
        this.password = password;
        this.role = Role.USER;
        this.refreshToken = refreshToken;
        this.nickname = nickname;
        this.provider = provider;
        this.providerId = providerId;
	}
	
	public Long getId() {
		return id;
	}
	
	public String getEmail() {
		return email;
	}
	
	public String getPassword() {
		return password;
	}
	
	public String getRefreshToken() {
		return refreshToken;
	}
	
	public String getRole() {
		return this.role.getKey();
	}
	
	public String getProvider() {
		return provider;
	}
	
	public String getProviderId() {
		return providerId;
	}
	
	public String getNickname() {
		return nickname;
	}
	
	public Member updateRefreshToken(String newRefreshToken) {
		this.refreshToken = newRefreshToken;
		return this;
	}
	
	@OneToMany(mappedBy="memberId")
	private List<Post> posts = new ArrayList<>();
}
