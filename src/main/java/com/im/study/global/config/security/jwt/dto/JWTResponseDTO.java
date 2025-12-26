package com.im.study.global.config.security.jwt.dto;

import lombok.Getter;

@Getter
public class JWTResponseDTO {
    String accessToken;
    String refreshToken;

    public JWTResponseDTO(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
