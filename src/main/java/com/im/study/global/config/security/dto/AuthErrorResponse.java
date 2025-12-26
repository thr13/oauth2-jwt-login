package com.im.study.global.config.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthErrorResponse {
    private final String code;
    private final String message;
}
