package com.example.security.service;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import com.example.security.exception.UserAlreadyExistsException;
import com.example.security.model.Member;
import com.example.security.model.MemberDetails;
import com.example.security.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsManager implements UserDetailsManager {
	
	private final Logger log = LoggerFactory.getLogger(CustomUserDetailsManager.class);
	
	@Autowired
	private MemberRepository memberRepository;

	@Override
	public MemberDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		log.info("LOAD USER BY USERNAME");
		
		Member member = memberRepository.findByEmail(username)
				.orElseThrow(()->new UsernameNotFoundException("User does not exists"));
		return new MemberDetails(member);
	}
	
	@Override
	public void createUser(UserDetails user) {
	}
	
	public void createUser(Member user) {
		log.info("CREATE USER BY Member Entity");
		
		if (!userExists(user.getEmail())) {
			memberRepository.save(user);
		} else {
			throw new UserAlreadyExistsException("Email already in use");
		}
	}

	public void updateUser(Member member) {
		log.info("UPDATE USER BY Member Entity");
		memberRepository.save(member);
	}

	@Override
	public void deleteUser(String username) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changePassword(String oldPassword, String newPassword) {
		// TODO Auto-generated method stub
	}
	
	@Override
	public boolean userExists(String username) {
		log.info("USER EXISTS");
		
		Optional<Member> member = memberRepository.findByEmail(username);
		
		if (member.isEmpty()) return false;
		return true;
	}

	@Override
	public void updateUser(UserDetails user) {
		
	}

}
