package com.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.jwt.models.Permissions.ADMIN_READ;
import static com.jwt.models.Permissions.ADMIN_WRITE;
import static com.jwt.models.Role.ADMIN;
// import static com.jwt.models.Permissions.USER_READ;
// import static com.jwt.models.Permissions.USER_WRITE;
// import static com.jwt.models.Role.USER;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthFilter jwtAuthFilter;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authenticationProvider(authenticationProvider).addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(request -> {
                request.requestMatchers("/api/auth/**").permitAll();
                request.requestMatchers("api/admin/**").hasAnyRole(ADMIN.name());
                request.requestMatchers(GET, "/api/admin/**").hasAnyAuthority(ADMIN_READ.name());
                request.requestMatchers(POST, "/api/admin/**").hasAnyAuthority(ADMIN_WRITE.name());
                request.requestMatchers(PUT, "/api/admin/**").hasAnyAuthority(ADMIN_WRITE.name());
                request.requestMatchers(DELETE, "/api/admin/**").hasAnyAuthority(ADMIN_WRITE.name());
            })
            .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .logout(logout -> {
                logout.logoutUrl("/logout");
                logout.addLogoutHandler(logoutHandler);
                logout.logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext());
            });

            return http.build();
    }
}
