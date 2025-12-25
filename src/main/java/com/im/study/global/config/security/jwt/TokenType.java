package com.im.study.global.config.security.jwt;

import lombok.Getter;

@Getter
public enum TokenType {
    ACCESS, // 액세스 토큰
    REFRESH // 리프레쉬 토큰
}
