package com.im.study.global.config.security.token;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TokenLogoutService {

    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenBlacklistService blacklistService;

    public TokenLogoutService(RefreshTokenService refreshTokenService, RefreshTokenBlacklistService blacklistService) {
        this.refreshTokenService = refreshTokenService;
        this.blacklistService = blacklistService;
    }

    // 회원 탈퇴, 강제 로그아웃 기능에서만 사용
    @Transactional
    public void logoutByUserId(Long userId) {

        String refreshToken = refreshTokenService.getRefreshToken(userId);

        if (refreshToken == null) {
            return;
        }

        blacklistService.blacklist(refreshToken);
        refreshTokenService.delete(userId);
    }
}
