package com.bloggingapp.servicesimpl;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	// It is sign n key (web-
	private final String SECRATE_KEY = "367639792F423F4528482B4D6251655468576D5A7134743777217A2543264629";

	public String extractUserName(String token) {
		// ectract the username
		return extractClaims(token, Claims::getSubject);
	}

	public <T> T extractClaims(String token, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(token);
		return claimResolver.apply(claims);
	}

	// generate Token
	public String generateToken(UserDetails details) {
		return generateToken(new HashMap<>(), details);
	}

	public String generateToken(Map<String, Object> extractClaim, UserDetails userDetails) {

		return Jwts.builder().setClaims(extractClaim).setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
				.signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();
	}

	// check Valid token
	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String userName = extractUserName(token);
		return (userName.equals(userDetails.getUsername()) && !isTokenExpire(token));
	}

//	check expire token
	private boolean isTokenExpire(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaims(token, Claims::getExpiration);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody();

	}

	private Key getSignInKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRATE_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
