package com.im.study.global.config.security.jwt;

import com.im.study.global.config.security.token.TokenPair;
import org.springframework.stereotype.Component;

@Component
public class JwtIssuer {
    private final JwtProvider jwtProvider;

    public JwtIssuer(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    // jwt 발급(TODO: 별도로 JWT 비밀키 발급후 값을 .env 에 저장)
    public TokenPair issue(Long userId, String role) {
        return new TokenPair(jwtProvider.createAccessToken(userId, role), jwtProvider.createRefreshToken(userId));
    }
}
