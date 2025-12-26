package com.im.study.global.config.security.token;

import org.springframework.stereotype.Service;

@Service
public class RefreshTokenBlacklistService {

    private final RefreshTokenBlacklistRepository blacklistRepository;

    public RefreshTokenBlacklistService(RefreshTokenBlacklistRepository blacklistRepository) {
        this.blacklistRepository = blacklistRepository;
    }

    public void blacklist(String refreshToken) {
        blacklistRepository.save(new RefreshTokenBlacklist(refreshToken));
    }

    public boolean isBlacklist(String refreshToken) {
        return blacklistRepository.existsById(refreshToken);
    }
}
