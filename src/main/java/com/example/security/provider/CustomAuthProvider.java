package com.example.security.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.example.security.service.CustomUserDetailsManager;


public class CustomAuthProvider implements AuthenticationProvider {

	@Autowired
    private CustomUserDetailsManager customUserDetailsManager;
	@Autowired
    private BCryptPasswordEncoder passwordEncoder;
 

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    	
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        UserDetails user = customUserDetailsManager.loadUserByUsername(username);
        
        if (!passwordEncoder.matches(password, user.getPassword())) {
        	throw new BadCredentialsException("Invalid password");
        }
        return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
      return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
