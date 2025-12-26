package com.im.study.global.config.security.handler;

import com.im.study.global.config.security.jwt.JwtIssuer;
import com.im.study.global.config.security.jwt.JwtService;
import com.im.study.global.config.CustomUser;
import com.im.study.global.config.security.token.RefreshTokenService;
import com.im.study.global.config.security.token.TokenPair;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Qualifier("SocialSuccessHandler")
public class SocialSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtIssuer jwtIssuer;
    private final RefreshTokenService refreshTokenService;

    public SocialSuccessHandler(JwtIssuer jwtIssuer, RefreshTokenService refreshTokenService) {
        this.jwtIssuer = jwtIssuer;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        CustomUser customUser = (CustomUser) authentication.getPrincipal();
        Long userId = customUser.getUserId();
        String role = customUser.getRoleType().name();

        TokenPair tokenPair = jwtIssuer.issue(userId, role);
        String accessToken = tokenPair.getAccessToken();
        String refreshToken = tokenPair.getRefreshToken();
        refreshTokenService.saveRefreshToken(userId, refreshToken, role);

        // 쿠키 생성
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // false 시 HTTP, HTTPS 전송 가능(true 일 경우 HTTPS 에서만 전송됨)
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7일
        cookie.setAttribute("SameSite", "None");

        response.addCookie(cookie);
        response.sendRedirect("http://localhost:5173/oauth2/success?accessToken=" + accessToken); // 프론트엔드로 리다이렉트
    }
}
