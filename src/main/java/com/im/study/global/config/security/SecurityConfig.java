package com.im.study.global.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.im.study.domain.user.entity.UserRoleType;
import com.im.study.global.config.security.filter.JwtAuthenticationFilter;
import com.im.study.global.config.security.filter.LoginFilter;
import com.im.study.global.config.security.handler.RefreshTokenLogoutHandler;
import com.im.study.global.config.security.jwt.JwtProvider;
import com.im.study.global.config.security.jwt.TokenAuthenticationService;
import com.im.study.global.config.security.token.RefreshTokenBlacklistService;
import com.im.study.global.config.security.token.RefreshTokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final AuthenticationSuccessHandler loginSuccessHandler;
    private final AuthenticationFailureHandler loginFailureHandler;
    private final AuthenticationSuccessHandler socialSuccessHandler;
    private final AuthenticationFailureHandler socialFailureHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenBlacklistService refreshTokenBlacklistService;
    private final ObjectMapper objectMapper;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, @Qualifier("LoginSuccessHandler") AuthenticationSuccessHandler loginSuccessHandler, @Qualifier("LoginFailureHandler") AuthenticationFailureHandler loginFailureHandler, @Qualifier("SocialSuccessHandler") AuthenticationSuccessHandler socialSuccessHandler, @Qualifier("SocialFailureHandler") AuthenticationFailureHandler socialFailureHandler, JwtAuthenticationFilter jwtAuthenticationFilter, JwtProvider jwtProvider, RefreshTokenService refreshTokenService, RefreshTokenBlacklistService refreshTokenBlacklistService, ObjectMapper objectMapper) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.loginSuccessHandler = loginSuccessHandler;
        this.loginFailureHandler = loginFailureHandler;
        this.socialSuccessHandler = socialSuccessHandler;
        this.socialFailureHandler = socialFailureHandler;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtProvider = jwtProvider;
        this.refreshTokenService = refreshTokenService;
        this.refreshTokenBlacklistService = refreshTokenBlacklistService;
        this.objectMapper = objectMapper;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173")); // vite 기반 React 프로젝트일 경우 기본 포트번호가 5173
        configuration.setAllowedMethods(List.of("GET", "POST", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Authorization", "Set-Cookie"));
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withRolePrefix("ROLE_")
                .role(UserRoleType.ADMIN.name()).implies(UserRoleType.USER.name())
                .build();
    }

    @Bean
    public LoginFilter loginFilter(AuthenticationManager authenticationManager) {
        return new LoginFilter(authenticationManager, objectMapper, loginSuccessHandler, loginFailureHandler);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(TokenAuthenticationService tokenAuthenticationService) {
        return new JwtAuthenticationFilter(tokenAuthenticationService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtProvider jwtProvider, RefreshTokenService refreshTokenService, RefreshTokenBlacklistService refreshTokenBlacklistService, TokenAuthenticationService tokenAuthenticationService) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
        ;

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/api/auth/refresh").permitAll()
                        .requestMatchers("/jwt/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/user/exist", "/user").permitAll()
                        .requestMatchers(HttpMethod.GET, "/user").hasRole(UserRoleType.USER.name())
                        .requestMatchers(HttpMethod.PATCH, "/user").hasRole(UserRoleType.USER.name())
                        .requestMatchers(HttpMethod.DELETE, "/user").hasRole(UserRoleType.USER.name())
                        .anyRequest().authenticated()
                )
        ;

        http
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN);
                        })
                )
        ;

        http
                .addFilterAt(loginFilter(authenticationManager(authenticationConfiguration)), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        ;

        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
        ;

        http
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(socialSuccessHandler)
                        .failureHandler(socialFailureHandler)
                )
        ;

        http
                .logout(logout -> logout
                        .addLogoutHandler(new RefreshTokenLogoutHandler(jwtProvider, refreshTokenService, refreshTokenBlacklistService))
                )
        ;

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }
}
