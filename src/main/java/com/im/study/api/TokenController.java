package com.im.study.api;

import com.im.study.domain.jwt.dto.JWTResponseDTO;
import com.im.study.global.config.security.jwt.JwtProvider;
import com.im.study.global.config.security.token.RefreshTokenService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class TokenController {

    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;

    public TokenController(JwtProvider jwtProvider, RefreshTokenService refreshTokenService) {
        this.jwtProvider = jwtProvider;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping(value = "/refresh", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JWTResponseDTO reissueTokenApi(@RequestHeader("Refresh-Token") String refreshToken) {
        if (!jwtProvider.validateToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        Long userId = jwtProvider.getUserId(refreshToken);
        if (!refreshTokenService.isValid(userId, refreshToken)) {
            throw new RuntimeException("Refresh token mismatch");
        }

        String newAccessToken = jwtProvider.createAccessToken(userId);
        String newRefreshToken = jwtProvider.createRefreshToken(userId);
        refreshTokenService.saveRefreshToken(userId, newRefreshToken);

        return new JWTResponseDTO(newAccessToken, newRefreshToken);
    }
}
