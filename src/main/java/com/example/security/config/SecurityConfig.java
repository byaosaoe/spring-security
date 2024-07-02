package com.example.security.config;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.example.security.entrypoint.AuthEntryPoint;
import com.example.security.filter.JwtFilter;
import com.example.security.provider.CustomAuthProvider;
import com.example.security.service.CustomUserDetailsManager;
import com.example.security.service.JwtService;

@Configuration
public class SecurityConfig {

	@Bean
    AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(customAuthProvider()));
    }

    @Bean
    CustomAuthProvider customAuthProvider() {
        return new CustomAuthProvider();
    }
    
	@Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
        config.setAllowedOrigins(Arrays.asList("http://localhost:5173"));
        config.setAllowedMethods(Arrays.asList("HEAD","POST","GET","DELETE","PUT"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.addExposedHeader("X-Auth-Access-Token");
        config.addExposedHeader("X-Auth-Refresh-Token");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(
				auth -> {
					auth
						.requestMatchers("/api/v1/auth/**").permitAll()
						.anyRequest().authenticated();
				}
			)
			
			.httpBasic(httpBasic -> httpBasic
                .authenticationEntryPoint(authEntryPoint())  // 인증 실패 시 처리
            )
			
			.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(authEntryPoint())  // 인증 실패 시 처리
            )

			.cors(cors->cors
				.configurationSource(corsConfigurationSource())
			)
			
			.csrf(csrf->csrf.disable())
			
			.addFilterBefore(new JwtFilter(jwtService(), authEntryPoint()),UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}

    @Bean
    JwtService jwtService() throws NoSuchAlgorithmException {
		return new JwtService();
	}
	
	@Bean
	AuthEntryPoint authEntryPoint() {
		return new AuthEntryPoint();
	}
	
	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	CustomUserDetailsManager customUserDetailsManager() {
		return new CustomUserDetailsManager();
	}
}
