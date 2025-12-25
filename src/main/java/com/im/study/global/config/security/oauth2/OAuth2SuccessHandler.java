package com.im.study.global.config.security.oauth2;

import com.im.study.global.config.security.jwt.JwtIssuer;
import com.im.study.global.config.security.token.RefreshTokenService;
import com.im.study.global.config.security.token.TokenPair;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtIssuer jwtIssuer;
    private final RefreshTokenService refreshTokenService;

    public OAuth2SuccessHandler(JwtIssuer jwtIssuer, RefreshTokenService refreshTokenService) {
        this.jwtIssuer = jwtIssuer;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        CustomOAuth2User customOAuth2User = (CustomOAuth2User) oAuth2AuthenticationToken.getPrincipal();
        Long userId = customOAuth2User.getUserId();
        String role = customOAuth2User.getRole();

        TokenPair tokenPair = jwtIssuer.issue(userId, role);
        refreshTokenService.saveRefreshToken(userId, tokenPair.getRefreshToken());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("""
                    {
                      "accessToken": "%s",
                      "refreshToken": "%s"
                    }
                """.formatted(
                tokenPair.getAccessToken(),
                tokenPair.getRefreshToken()
        ));
    }
}
