package com.im.study.global.config.security.token;

import com.im.study.global.config.security.jwt.JwtIssuer;
import com.im.study.global.config.security.jwt.JwtProvider;
import com.im.study.global.config.security.jwt.TokenType;
import com.im.study.global.config.security.jwt.dto.JWTResponseDTO;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TokenReissueService {

    private final JwtProvider jwtProvider;
    private final JwtIssuer jwtIssuer;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenBlacklistService blacklistService;

    public TokenReissueService(JwtProvider jwtProvider, JwtIssuer jwtIssuer, RefreshTokenService refreshTokenService, RefreshTokenBlacklistService blacklistService) {
        this.jwtProvider = jwtProvider;
        this.jwtIssuer = jwtIssuer;
        this.refreshTokenService = refreshTokenService;
        this.blacklistService = blacklistService;
    }

    // refreshToken 을 받아서 jwt 토큰 재발급
    @Transactional
    public JWTResponseDTO reissue(String refreshToken) {

        if (!jwtProvider.validateToken(refreshToken)) { // 토큰 검증
            throw new RuntimeException("Invalid refresh token");
        }

        if (jwtProvider.getTokenType(refreshToken) != TokenType.REFRESH) { // refreshToken 인지 확인
            throw new RuntimeException("Not refresh token");
        }

        if (blacklistService.isBlacklist(refreshToken)) { // refreshToken 이 blacklist 에 등록되었는지 확인
            throw new RuntimeException("Blacklisted token");
        }

        Long userId = jwtProvider.getUserId(refreshToken);
        if (!refreshTokenService.isValid(userId, refreshToken)) {
            throw new RuntimeException("Refresh token mismatch");
        }

        String role = refreshTokenService.getRefreshTokenRole(userId);

        blacklistService.blacklist(refreshToken); // refreshToken 블랙리스트 등록
        refreshTokenService.delete(userId); // refreshToken 제거

        TokenPair tokenPair = jwtIssuer.issue(userId, role);
        refreshTokenService.saveRefreshToken(userId, tokenPair.getRefreshToken(), role);

        return new JWTResponseDTO(tokenPair.getAccessToken(), tokenPair.getRefreshToken());
    }
}
