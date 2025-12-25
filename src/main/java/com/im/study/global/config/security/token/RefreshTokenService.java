package com.im.study.global.config.security.token;

import org.springframework.stereotype.Service;

@Service
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    // OAuth2 로그인 성공시 refreshToken 저장
    public void saveRefreshToken(Long userId, String refreshToken) {
        refreshTokenRepository.save(new RefreshToken(userId.toString(), refreshToken));
    }

    // refreshToken 획득
    public String getRefreshToken(Long userId) {
        return refreshTokenRepository.findById(userId.toString())
                .map(RefreshToken::getToken)
                .orElse(null);
    }

    // refreshToken 재발급시 검증
    public boolean isValid(Long userId, String refreshToken) {
        return refreshTokenRepository.findById(userId.toString())
                .map(token -> token
                        .getToken()
                        .equals(refreshToken))
                .orElse(false);
    }

    // 재로그인 또는 로그아웃시 refreshToken 제거
    public void delete(Long userId) {
        refreshTokenRepository.deleteById(userId.toString());
    }
}
