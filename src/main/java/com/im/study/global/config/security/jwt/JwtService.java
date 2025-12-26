package com.im.study.global.config.security.jwt;

import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final JwtProvider jwtProvider;

    public JwtService(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    public String createAccessToken(Long userId, String role) {
        return jwtProvider.createAccessToken(userId, role);
    }

    public String createRefreshToken(Long userId, String role) {
        return jwtProvider.createRefreshToken(userId);
    }

    public boolean validate(String token) {
        return jwtProvider.validateToken(token);
    }

    public Long getUserId(String token) {
        return jwtProvider.getUserId(token);
    }

    public String getRole(String token) {
        return jwtProvider.getRole(token);
    }
}
