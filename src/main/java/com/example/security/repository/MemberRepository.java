package com.example.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.security.model.Member;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long>{

	public Optional<Member> findByEmail(String email);
	
	@Override
	public Member save(Member member);
	
	
}
