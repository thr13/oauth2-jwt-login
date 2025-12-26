package com.im.study.global.config.security.handler;

import com.im.study.global.config.CustomUser;
import com.im.study.global.config.security.jwt.JwtIssuer;
import com.im.study.global.config.security.token.RefreshTokenService;
import com.im.study.global.config.security.token.TokenPair;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Qualifier("LoginSuccessHandler")
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtIssuer jwtIssuer;
    private final RefreshTokenService refreshTokenService;

    public LoginSuccessHandler(JwtIssuer jwtIssuer, RefreshTokenService refreshTokenService) {
        this.jwtIssuer = jwtIssuer;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        CustomUser customUser = (CustomUser) authentication.getPrincipal();
        Long userId = customUser.getUserId();
        String role = customUser.getRoleType().name();

        TokenPair tokenPair = jwtIssuer.issue(userId, role);
        refreshTokenService.saveRefreshToken(userId, tokenPair.getRefreshToken(), role);

        response.setContentType("application/json");
        response.getWriter().write("""
            {
              "accessToken": "%s",
              "refreshToken": "%s"
            }
        """.formatted(tokenPair.getAccessToken(), tokenPair.getRefreshToken()));

    }
}
