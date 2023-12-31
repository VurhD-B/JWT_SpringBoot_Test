package com.jwt.services;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import com.jwt.repositories.TokenRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler{
    
    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        jwtToken = authHeader.substring(7);
        var tokenStored = tokenRepository.findByToken(jwtToken).orElse(null);
        if(tokenStored != null) {
            tokenStored.setExpired(true);
            tokenStored.setRevoked(true);
            tokenRepository.save(tokenStored);
            SecurityContextHolder.clearContext();
        }
    }
}
