package com.im.study.global.config.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtProvider {

    private final JwtProperties properties;
    private final SecretKey secretKey;

    public JwtProvider(JwtProperties properties) {
        this.properties = properties;
        this.secretKey = Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    private String createToken(Long userId, String role, TokenType tokenType, long expiredMs) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expiredMs);

        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("tokenType", tokenType.name())
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }

    public String createAccessToken(Long userId, String role) {
        return createToken(userId, role, TokenType.ACCESS, properties.getAccessTokenExpireMs());
    }

    public String createRefreshToken(Long userId) {
        return createToken(userId, null, TokenType.REFRESH, properties.getRefreshTokenExpireMs());
    }

    // 토큰 파싱
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // 토큰 파싱 검증
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // 토큰에서 userId 추출
    public Long getUserId(String token) {
        return Long.valueOf(parseClaims(token).getSubject());
    }

    // 토큰에서 role 추출
    public String getRole(String token) {
        return parseClaims(token).get("role", String.class);
    }

    // 토큰에서 tokenType 추출
    public TokenType getTokenType(String token) {
        return TokenType.valueOf(parseClaims(token).get("tokenType", String.class));
    }

    // 토큰 만료 여부
    public boolean isExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }

    // 헤더나 쿠키에 있는 refreshToken 추출
    public String resolveRefreshToken(HttpServletRequest request) {
        // 헤더
        String token = request.getHeader("Refresh-Token");
        if (token != null && !token.isBlank()) {
            return token;
        }

        // 쿠키
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }

    // refreshToken 토큰 검증(헤더용)
    public void validateRefreshToken(String token) {
        try {
            Claims claims = parseClaims(token);

            if (!TokenType.REFRESH.name().equals(claims.get("tokenType"))) {
                throw new JwtException("Not a refresh token");
            }
        } catch (JwtException | IllegalArgumentException e) {
            throw new RuntimeException("Invalid refresh token", e);
        }
    }
}
