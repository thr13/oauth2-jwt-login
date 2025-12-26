package com.im.study.global.config.security.jwt.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class RefreshRequestDTO {

    @NotBlank
    private String refreshToken;
}
