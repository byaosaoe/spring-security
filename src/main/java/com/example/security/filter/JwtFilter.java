package com.example.security.filter;

import java.io.IOException;

import org.apache.logging.log4j.util.InternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.security.entrypoint.AuthEntryPoint;
import com.example.security.model.MemberDetails;
import com.example.security.service.JwtService;
import com.nimbusds.jose.JOSEException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
	
	private final Logger log = LoggerFactory.getLogger(JwtFilter.class);
	
	@Autowired
	private final JwtService jwtService;
	
	@Autowired
	private final AuthEntryPoint authEntryPoint;
	
	private String resolveToken(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
			return bearerToken.substring(7);
		}
		return null;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		log.info("JWT FILTER INVOKE");

		try {
			String token = resolveToken((HttpServletRequest) request);
			if (token!= null) {
				jwtService.setAuthByToken(token);
				System.out.println(((MemberDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername());
			}
			filterChain.doFilter(request, response);
		} catch (AuthenticationException e) {
			authEntryPoint.commence(request, response, e);
		} catch (java.text.ParseException | JOSEException e) {
			e.printStackTrace();
			throw new InternalException("CREATE_TOKEN_EXCEPTION");
		}
	}

}
