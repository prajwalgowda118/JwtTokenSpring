package com.scaler.springsecurity.jwtspring.Config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.bind.annotation.RequestMapping;

import static com.scaler.springsecurity.jwtspring.Model.Permission.*;
import static com.scaler.springsecurity.jwtspring.Model.Role.ADMIN;
import static com.scaler.springsecurity.jwtspring.Model.Role.MANAGER;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity

public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**").permitAll()  // Ensure /register is publicly accessible
                .requestMatchers("/h2-console/**").permitAll()
               /*.requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(),MANAGER.name())
                .requestMatchers("/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(),MANAGER_READ.name())
                .requestMatchers("/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(),MANAGER_UPDATE.name())
                .requestMatchers("/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(),MANAGER_DELETE.name())
                .requestMatchers("/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(),MANAGER_CREATE.name())

                .requestMatchers("/api/v1/admin/**").hasRole(ADMIN.name())
                .requestMatchers("/api/v1/admin/**").hasAnyAuthority(ADMIN_READ.name())
                .requestMatchers("/api/v1/admin/**").hasAnyAuthority(ADMIN_UPDATE.name())
                .requestMatchers("/api/v1/admin/**").hasAnyAuthority(ADMIN_DELETE.name())
                .requestMatchers("/api/v1/admin/**").hasAnyAuthority(ADMIN_CREATE.name())*/
                .anyRequest().authenticated() // All other requests require authentication
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // Use stateless session management for JWT
                .and()
                .authenticationProvider(authenticationProvider)  // Ensure you have defined an authenticationProvider bean
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)// Add JWT authentication filter before UsernamePasswordAuthenticationFilter
                .logout()
                .logoutUrl("/api/v1/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext());

        http.headers().frameOptions().sameOrigin();

        return http.build();
    }


}
