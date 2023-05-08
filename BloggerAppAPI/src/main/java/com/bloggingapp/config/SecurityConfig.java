//package com.bloggingapp.config;
//
//import java.io.IOException;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import com.bloggingapp.security.JwtService;
//
//import jakarta.annotation.Nonnull;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig extends OncePerRequestFilter {
//
//	private  JwtService jwtService;
//
//	@Override
//	protected void doFilterInternal(@Nonnull HttpServletRequest request,@Nonnull HttpServletResponse response,@Nonnull FilterChain filterChain)
//			throws ServletException, IOException {
//		final String authHeader= request.getHeader("Authorizatoin");
//		final String jwt;
//		final String userEmail;
//		if(authHeader==null ||! authHeader.startsWith("Bearer ")) {
//			filterChain.doFilter(request, response);
//			return;
//		}
//		jwt=authHeader.substring(7);
//		userEmail=jwtService.extractUserName(jwt);
//	
//	}
//	
//	
//
//}
