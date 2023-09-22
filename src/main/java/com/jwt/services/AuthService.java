package com.jwt.services;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.dto.AuthenticationReponse;
import com.jwt.dto.AuthenticationRequest;
import com.jwt.dto.RegisterRequest;
import com.jwt.models.Role;
import com.jwt.models.Token;
import com.jwt.models.TokenType;
import com.jwt.models.User;
import com.jwt.repositories.TokenRepository;
import com.jwt.repositories.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationReponse register(RegisterRequest registerRequest){
        var user = User.builder()
                    .email(registerRequest.getEmail())
                    .password(passwordEncoder.encode(registerRequest.getPassword()))
                    .phoneNumber(registerRequest.getPhoneNumber())
                    .dateOfBirth(registerRequest.getDateOfBirth())
                    .role(Role.USER)
                    .build();
        var userSaved = userRepository.save(user);
        var jwtAccessToken = jwtService.generateToken(userSaved);
        var jwtRefreshToken = jwtService.generateRefreshToken(userSaved);
        saveUserToken(userSaved, jwtRefreshToken);
        return AuthenticationReponse.builder()
                    .accessToken(jwtAccessToken)
                    .refreshToken(jwtRefreshToken)
                    .build();
    }

    public AuthenticationReponse login(AuthenticationRequest authenticationRequest){
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                authenticationRequest.getEmail(),
                authenticationRequest.getPassword()
            ));

        var user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
        var jwtAccessToken = jwtService.generateToken(user);
        var jwtRefreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtAccessToken);
        return AuthenticationReponse.builder()
                    .accessToken(jwtAccessToken)
                    .refreshToken(jwtRefreshToken)
                    .build();
    }

    private void saveUserToken(User user, String jwtToken){
        var token = Token.builder()
                    .token(jwtToken)
                    .user(user)
                    .tokenType(TokenType.BEARER)
                    .expired(false)
                    .revoked(false)
                    .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user){
        var userValidTokens = tokenRepository.findValidTokenPerUser(user.getUserId());
        if(userValidTokens.isEmpty()){
            return;
        }
        userValidTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(userValidTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response)
    throws java.io.IOException {

        final String authHeader = request.getHeader("Authorization");
        final String refreshToken;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if(userEmail != null){
            var user = userRepository.findByEmail(userEmail).orElseThrow();
            if(jwtService.isTokenValid(refreshToken, user)){
                var jwtAccessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, refreshToken);
                var authResponse = AuthenticationReponse.builder()
                                    .accessToken(jwtAccessToken)
                                    .refreshToken(refreshToken)
                                    .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

}
