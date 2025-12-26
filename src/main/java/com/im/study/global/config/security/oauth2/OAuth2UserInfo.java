package com.im.study.global.config.security.oauth2;

import java.util.Map;

public interface OAuth2UserInfo {
    String getProvider(); // OAuth2 서비스명

    String getProviderId(); // 고유 식별값 (id, sub 등)

    String getEmail();

    String getNickname();

    Map<String, Object> getAttributes();
}
