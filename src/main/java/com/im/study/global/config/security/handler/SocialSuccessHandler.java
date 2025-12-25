package com.im.study.global.config.security.handler;

import com.im.study.domain.jwt.service.JwtService;
import com.im.study.global.util.JWTUtil;
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
    private final JwtService jwtService;
    private final JWTUtil jwtUtil;

    public SocialSuccessHandler(JwtService jwtService, JWTUtil jwtUtil) {
        this.jwtService = jwtService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();
        String role = authentication.getAuthorities().iterator().next().getAuthority();

        String refreshToken = jwtUtil.createJWT(username, "ROLE_" + role, false); // Refresh Token 발급(JWT)
        jwtService.addRefresh(username, refreshToken); // Refresh Token 만 상태 관리 필요(Refresh Token Whitelist)

        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false); // false 시 HTTP, HTTPS 전송 가능(true 일 경우 HTTPS 에서만 전송됨)
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(604800000); // 쿠키 만료 시간(Refresh Token 만료 시간과 동일)
        refreshCookie.setAttribute("SameSite", "None");

        response.addCookie(refreshCookie);
        response.sendRedirect("http://localhost:5173/cookie"); // 프론트엔드로 리다이렉트
    }
}
