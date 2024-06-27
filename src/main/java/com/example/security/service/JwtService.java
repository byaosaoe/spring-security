package com.example.security.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.example.security.exception.InvalidTokenException;
import com.example.security.model.Member;
import com.example.security.model.MemberDetails;
import com.example.security.model.Role;
import com.example.security.model.TokenDTO;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class JwtService {

	private final Logger log = LoggerFactory.getLogger(JwtService.class);
			
	private static final int ACCESS_TOKEN_EXPIRE_MINUTES = 1;
	private static final int REFRESH_TOKEN_EXPIRE_MINUTES = 5;
	
	@Autowired
	private CustomUserDetailsManager customUserDetailsManager;
	
	private RSAPublicKey publicKey;
	private RSAPrivateKey privateKey;
	
	private JWSVerifier verifier;
	private JWSSigner signer;
	
	
	public JwtService() throws NoSuchAlgorithmException {
		initialize();
	}
	
	private void initialize() throws NoSuchAlgorithmException {
		log.info("INITIALIZE");
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(2048);
	    KeyPair keyPair = keyGen.generateKeyPair();
	    
	    publicKey = (RSAPublicKey) keyPair.getPublic();
	    privateKey = (RSAPrivateKey) keyPair.getPrivate();
	    
	    verifier = new RSASSAVerifier(publicKey);
	    signer = new RSASSASigner(privateKey);
	}
	
	public SignedJWT decryptToken(String token) throws ParseException, JOSEException {
		log.info("DECRYPT TOKEN");
		
		JWEObject decryptedAccessJWE = JWEObject.parse(token);
		decryptedAccessJWE.decrypt(new RSADecrypter(privateKey));
        return decryptedAccessJWE.getPayload().toSignedJWT();
	}
	
	public boolean verifyToken(SignedJWT signedJWT) throws ParseException, JOSEException {
		log.info("VERIFY TOKEN");
		
		String sub = signedJWT.getJWTClaimsSet().getSubject();
		
		if (signedJWT.verify(verifier) && new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()) && customUserDetailsManager.userExists(sub)) {
			return true;
		} else {
			Member member = customUserDetailsManager.loadUserByUsername(sub).getMember();
			if (new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()) && member.getRefreshToken().equals(signedJWT)) {
				return true;
			}
		}
		return false;

	}
	
	private String createToken(MemberDetails member, int m) throws JOSEException {
		log.info("PRIVATE : CREATE TOKEN");
		
		SignedJWT token = new SignedJWT(
				new JWSHeader(JWSAlgorithm.RS256),
			    new JWTClaimsSet.Builder()
				    .subject(member.getUsername())
				    .issuer("bia")
				    .claim("auth", member.getAuthorities())
				    .expirationTime(new Date(new Date().getTime() + 60 * 1000 * m))
				    .build());
		
		token.sign(signer);
		
		JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM).contentType("JWT").build(),
                new Payload(token)
        );
		
		jweObject.encrypt(new RSAEncrypter(publicKey));
		
		return jweObject.serialize();
	}
	
	public TokenDTO createToken(MemberDetails memberDetails) throws JOSEException {
		log.info("PUBLIC : CREATE TOKEN");
		
		String accessToken = createToken(memberDetails, ACCESS_TOKEN_EXPIRE_MINUTES);
		String refreshToken = createToken(memberDetails, REFRESH_TOKEN_EXPIRE_MINUTES);
		
		TokenDTO token = new TokenDTO();
		token.setAccessToken(accessToken);
		token.setRefreshToken(refreshToken);
		
		customUserDetailsManager.updateUser(memberDetails.getMember().updateRefreshToken(refreshToken));
		
		return token;
	}
	
	public void setAuthByToken(String token) throws ParseException, JOSEException  {
		log.info("SET AUTHENTICATION BY TOKEN");
		
		SignedJWT decryptedSignedJWT = decryptToken(token);
		boolean isTokenValid = verifyToken(decryptedSignedJWT);

		if (isTokenValid) {
			JWTClaimsSet decryptedToken = decryptedSignedJWT.getJWTClaimsSet();
			MemberDetails member = new MemberDetails(Member.builder()
									.email(decryptedToken.getSubject())
									.build());
			List<GrantedAuthority> authorities = new ArrayList<>();
	        authorities.add(new SimpleGrantedAuthority(Role.USER.getTitle()));
	        
			SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(member, null, authorities));
		} else {	
			throw new InvalidTokenException("This token is invalid");
		}
	}
}
