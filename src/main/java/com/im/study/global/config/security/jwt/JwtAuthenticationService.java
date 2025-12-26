package com.im.study.global.config.security.jwt;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JwtAuthenticationService implements TokenAuthenticationService {

    private final JwtProvider jwtProvider;

    public JwtAuthenticationService(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    public Authentication authenticate(String accessToken) {
        if (!jwtProvider.validateToken(accessToken)) {
            return null;
        }

        if (jwtProvider.getTokenType(accessToken) != TokenType.ACCESS) {
            return null;
        }

        Long userId = jwtProvider.getUserId(accessToken);
        String role = jwtProvider.getRole(accessToken);

        return new UsernamePasswordAuthenticationToken(userId, null, List.of(new SimpleGrantedAuthority("ROLE_" + role)));
    }
}
