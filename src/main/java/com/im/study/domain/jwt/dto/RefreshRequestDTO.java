package com.im.study.domain.jwt.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class RefreshRequestDTO {

    @NotBlank
    private String refreshToken;
}
