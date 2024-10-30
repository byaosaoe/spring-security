package com.example.security.controller;

import java.io.IOException;
import java.net.URISyntaxException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.security.exception.UserAlreadyExistsException;
import com.example.security.model.Member;
import com.example.security.model.MemberDTO;
import com.example.security.model.MemberDetails;
import com.example.security.model.TokenDTO;
import com.example.security.service.CustomUserDetailsManager;
import com.example.security.service.JwtService;
import com.example.security.service.OAuthService;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEException;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
	
	private final Logger log = LoggerFactory.getLogger(AuthController.class);

	@Autowired
    	private OAuthService oauthService;
    	@Autowired
    	private CustomUserDetailsManager customUserDetailsManager;
    	@Autowired
    	private JwtService jwtService;
    	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
    
    	@GetMapping("/oauth2/{registrationId}")
    	public void loginByGoogleOauth(HttpServletResponse response, @RequestParam("code") String code,@PathVariable("registrationId") String registrationId) throws URISyntaxException, IOException {
		log.info("LOGIN : URL을 통해 로그인 화면 접근 & 코드 반환");
		response.sendRedirect("http://localhost:5173/login/google?code="+code);
    	}
    
    	@PostMapping("/join")
	public ResponseEntity<?> signUp(@RequestBody MemberDTO memberDto) {
		log.info("SIGN UP");
		
	    	String email = memberDto.getEmail();
	    	String password = memberDto.getPassword();
	    	String nickname = memberDto.getNickname();
	    	String provider = memberDto.getProvider();
	    	String providerId = memberDto.getProviderId();
    	
	    	Member member = Member.builder()
	    			.email(email)
	    			.password(passwordEncoder.encode(password))
	    			.nickname(nickname)
	    			.provider(provider)
	    			.providerId(providerId)
	    			.build();
    	
	    	try {
	    		customUserDetailsManager.createUser(member);
	    		return ResponseEntity.ok("Your Account Is Created");
	    	} catch(UserAlreadyExistsException e) {
	    		return ResponseEntity.badRequest().body("Already Exists Email");
	    	}
    	}

	@PostMapping("/login/basic")
	public ResponseEntity<?> loginByEmail(Authentication authentication) {
		log.info("LOGIN BY EMAIL");
		
		Object principal = authentication.getPrincipal();
		MemberDetails memberDetails = (MemberDetails) principal;
		
		try {
			TokenDTO tokenDTO = jwtService.createToken(memberDetails);
			
			HttpHeaders httpHeaders = new HttpHeaders();
			httpHeaders.add("X-Auth-Access-Token", tokenDTO.getAccessToken());
			httpHeaders.add("X-Auth-Refresh-Token", tokenDTO.getRefreshToken());
			return ResponseEntity.ok().headers(httpHeaders).body(memberDetails.getNickname());
		} catch (JOSEException e) {
			e.printStackTrace();
			return ResponseEntity.internalServerError().body(null);
		}
	}
	
    	@PostMapping("/oauth2/google")
    	public ResponseEntity<?> loginByGoogle(HttpServletResponse response, @RequestParam("code") String code) 
		log.info("LOGIN BY GOOGLE OAUTH & REDIRECT BY GOOGLE API SERVER");
    	
	    	JsonNode googleUser = oauthService.socialLogin(code, "google");
	    	String email = googleUser.get("email").asText();
	    	String provider = "google";
		String providerId = googleUser.get("id").asText();
    	
		try {
			MemberDetails memberDetails = customUserDetailsManager.loadUserByUsername(email);
			
			TokenDTO tokenDTO = jwtService.createToken(memberDetails);
			
			HttpHeaders httpHeaders = new HttpHeaders();
			httpHeaders.add("X-Auth-Access-Token", tokenDTO.getAccessToken());
			httpHeaders.add("X-Auth-Refresh-Token", tokenDTO.getRefreshToken());
			
			return ResponseEntity.ok().headers(httpHeaders).body(memberDetails.getNickname());
		} catch(UsernameNotFoundException e) {
			MemberDTO memberDTO = new MemberDTO();
			memberDTO.setEmail(email);
			memberDTO.setProvider(provider);
			memberDTO.setProviderId(providerId);
			return ResponseEntity.ok(memberDTO);
		} catch (JOSEException e) {
			e.printStackTrace();
			return ResponseEntity.internalServerError().body(null);
		}
    	}
}
