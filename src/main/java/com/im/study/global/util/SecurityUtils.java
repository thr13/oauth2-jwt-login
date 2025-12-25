package com.im.study.global.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


public class SecurityUtils {

    public SecurityUtils() {
    }

    // SecurityContextHolder 내부에 저장된 Authentication 객체를 찾고 인증 객체 속 userId 반환(JWT 설정에서 넣은 userId 반환)
    public static Long getUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw new IllegalStateException("인증 정보가 존재하지 않습니다");
        }

        return Long.valueOf(authentication.getName());
    }

    // 위와 비슷하게 이 메소드는 role 반환
    public static String getRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw new IllegalStateException("인증 정보가 존재하지 않습니다");
        }

        return authentication.getAuthorities()
                .iterator()
                .next()
                .getAuthority();
    }
}
