package com.example.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.databind.JsonNode;

@Service
public class OAuthService {
	
	private final Logger log = LoggerFactory.getLogger(OAuthService.class);
	
	private final Environment env;
    private RestClient restClient = RestClient.create();

    public OAuthService(Environment env) {
        this.env = env;
    }
    
    public JsonNode socialLogin(String code, String registrationId) {
    	log.info("MAIN METHOD INVOKED : socialLogin");
    	
        String accessToken = getAccessToken(code, registrationId);
        JsonNode userResourceNode = getUserResource(accessToken, registrationId);

        return userResourceNode;
    }

    private String getAccessToken(String authorizationCode, String registrationId) {
    	log.info("GET ACCESSTOKEN BY ACCESSING TO GOOGLE API SERVER");

        String clientId = env.getProperty("oauth2." + registrationId + ".client-id");
        String clientSecret = env.getProperty("oauth2." + registrationId + ".client-secret");
        String redirectUri = env.getProperty("oauth2." + registrationId + ".redirect-uri");
        String tokenUri = env.getProperty("oauth2." + registrationId + ".token-uri");
        
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", authorizationCode);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");

        ResponseEntity<JsonNode> responseNode = restClient.post()
        		.uri(tokenUri)
        		.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        		.body(params)
        		.retrieve()
        		.toEntity(JsonNode.class);

        JsonNode accessTokenNode = responseNode.getBody();
        
        return accessTokenNode.get("access_token").asText();
    }

    private JsonNode getUserResource(String accessToken, String registrationId) {
        log.info("발급받은 GOOGLE API ACCESSTOKEN으로 사용자 정보 받아오기");
    	
    	String resourceUri = env.getProperty("oauth2."+registrationId+".resource-uri");

        return restClient.get()
        		.uri(resourceUri)
        		.header("Authorization", "Bearer " + accessToken)
        		.retrieve()
        		.body(JsonNode.class);
    }

}
