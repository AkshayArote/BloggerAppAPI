package com.bloggingapp.servicesimpl;

import java.security.Key;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private final String SECRATE_KEY="367639792F423F4528482B4D6251655468576D5A7134743777217A2543264629";
	
	public String extractUserName(String jwt) {
		
		return null;
	}

	private Claims extractAllClaims(String token) {
		return Jwts.
				parserBuilder()
				.setSigningKey(getSignInKey())
				.build()
				.parseClaimsJws(token).getBody();
		
	}
	
	private Key getSignInKey() {
		byte[] keyBytes=Decoders.BASE64.decode(SECRATE_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
