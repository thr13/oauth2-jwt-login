package com.im.study.global.config.security.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.im.study.domain.jwt.service.JwtService;
import com.im.study.global.util.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class RefreshTokenLogoutHandler implements LogoutHandler {

    private final JwtService jwtService;
    private final JWTUtil jwtUtil;

    public RefreshTokenLogoutHandler(JwtService jwtService, JWTUtil jwtUtil) {
        this.jwtService = jwtService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            String body = new BufferedReader(new InputStreamReader(request.getInputStream()))
                    .lines()
                    .reduce("", String::concat);

            if (!StringUtils.hasText(body)) {
                return;
            }

            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(body);
            String refreshToken = jsonNode.has("refreshToken") ? jsonNode.get("refreshToken").asText() : null;

            if (refreshToken.isEmpty()) {
                return;
            }

            Boolean isValid = jwtUtil.isValid(refreshToken, false);
            if (!isValid) {
                return;
            }

            jwtService.removeRefresh(refreshToken);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read refresh token", e);
        }
    }
}
