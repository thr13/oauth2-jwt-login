package com.im.study.domain.jwt.service;

import com.im.study.domain.jwt.dto.JWTResponseDTO;
import com.im.study.domain.jwt.dto.RefreshRequestDTO;
import com.im.study.domain.jwt.entity.RefreshEntity;
import com.im.study.domain.jwt.repository.RefreshRepository;
import com.im.study.global.util.JWTUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class JwtService {

    private final RefreshRepository refreshRepository;
    private final JWTUtil jwtUtil;

    public JwtService(RefreshRepository refreshRepository, JWTUtil jwtUtil) {
        this.refreshRepository = refreshRepository;
        this.jwtUtil = jwtUtil;
    }

    @Transactional
    public void addRefresh(String username, String refreshToken) {
        RefreshEntity refreshEntity = RefreshEntity
                .builder()
                .username(username)
                .refresh(refreshToken)
                .build();

        refreshRepository.save(refreshEntity);
    }

    @Transactional(readOnly = true)
    public Boolean existsRefresh(String refreshToken) {
        return refreshRepository.existsByRefresh(refreshToken);
    }

    @Transactional
    public void removeRefresh(String refreshToken) {
        refreshRepository.deleteByRefresh(refreshToken);
    }

    // 소셜 로그인 성공 -> 쿠키의 담긴 RefreshToken 추출 -> 검증 및 정보 추출 -> 새 토큰 생성 -> DB에 저장된 기존 Refresh 토큰 삭제 후 새 토큰을 저장 -> 기존 쿠키 제거
    @Transactional
    public JWTResponseDTO cookie2Header(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            throw new RuntimeException("Request contains no cookie");
        }

        String refreshToken = null;
        for (Cookie cookie : cookies) {
            if ("refreshToken".equals(cookie.getName())) {
                refreshToken = cookie.getValue();
                break;
            }
        }

        if (refreshToken == null) {
            throw new RuntimeException("Missing refresh token cookies");
        }

        Boolean isValid = jwtUtil.isValid(refreshToken, false);
        if (!isValid) {
            throw new RuntimeException("Not valid refresh token");
        }

        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        String newAccessToken = jwtUtil.createJWT(username, role, true);
        String newRefreshToken = jwtUtil.createJWT(username, role, false);

        RefreshEntity refreshEntity = RefreshEntity.builder()
                .username(username)
                .refresh(newRefreshToken)
                .build();

        removeRefresh(refreshToken);
        refreshRepository.flush();
        refreshRepository.save(refreshEntity);

        Cookie refreshCookie = new Cookie("refreshToken", null);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(0);
        refreshCookie.setAttribute("SameSite", "None");

        response.addCookie(refreshCookie);

        return new JWTResponseDTO(newAccessToken, newRefreshToken);
    }

    // refreshToken 재발급
    @Transactional
    public JWTResponseDTO refreshRotate(RefreshRequestDTO dto) {
        String refreshToken = dto.getRefreshToken();

        Boolean isValid = jwtUtil.isValid(refreshToken, false);
        if (!isValid) {
            throw new RuntimeException("Not valid refresh token");
        }

        if (!existsRefresh(refreshToken)) {
            throw new RuntimeException("Not valid refresh token");
        }

        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        String newAccessToken = jwtUtil.createJWT(username, role, true);
        String newRefreshToken = jwtUtil.createJWT(username, role, false);

        RefreshEntity refreshEntity = RefreshEntity.builder()
                .username(username)
                .refresh(newRefreshToken)
                .build();

        removeRefresh(refreshToken);
        refreshRepository.save(refreshEntity);

        return new JWTResponseDTO(newAccessToken, newRefreshToken);
    }
}
