package com.im.study.global.config.security.handler;

import com.im.study.global.config.security.jwt.JwtProvider;
import com.im.study.global.config.security.token.RefreshTokenBlacklistService;
import com.im.study.global.config.security.token.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public class RefreshTokenLogoutHandler implements LogoutHandler {

    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenBlacklistService blacklistService;

    public RefreshTokenLogoutHandler(JwtProvider jwtProvider, RefreshTokenService refreshTokenService, RefreshTokenBlacklistService blacklistService) {
        this.jwtProvider = jwtProvider;
        this.refreshTokenService = refreshTokenService;
        this.blacklistService = blacklistService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        String refreshToken = jwtProvider.resolveRefreshToken(request);
        if (refreshToken == null) {
            return;
        }

        jwtProvider.validateRefreshToken(refreshToken);

        Long userId = jwtProvider.getUserId(refreshToken);

        blacklistService.blacklist(refreshToken);

        refreshTokenService.delete(userId);
    }
}
