package com.example.security.entrypoint;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.example.security.exception.InvalidTokenException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AuthEntryPoint implements AuthenticationEntryPoint {

	private static final Logger logger = LoggerFactory.getLogger(AuthEntryPoint.class);
	
	@Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        logger.error("Unauthorized error: {}", authException.getMessage());

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        if (authException instanceof UsernameNotFoundException) {
            response.getWriter().write("{\"error\": \"USER_NOT_FOUND\", \"message\": \"User does not exist\"}");
        } else if (authException instanceof BadCredentialsException) {
            response.getWriter().write("{\"error\": \"INVALID_CREDENCIALS\", \"message\": \"Invalid username or password\"}");
        } else if (authException instanceof InvalidTokenException) {
        	response.getWriter().write("{\"error\": \"INVALID_TOKEN\", \"message\": \"Invalid token\"}");
        } else {
            response.getWriter().write("{\"error\": \"AUTHENTICATION_FAILED\", \"message\": \"" + authException.getMessage() + "\"}");  
        }
    }
}
