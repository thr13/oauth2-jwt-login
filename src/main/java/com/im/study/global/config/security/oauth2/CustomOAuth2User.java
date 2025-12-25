package com.im.study.global.config.security.oauth2;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    @Getter
    private final Long userId;

    @Getter
    private final String role;

    private final Map<String, Object> attributes;
    private final Collection<? extends GrantedAuthority> authorities;


    public CustomOAuth2User(Long userId, String role, Map<String, Object> attributes, Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.role = role;
        this.attributes = attributes;
        this.authorities = authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return userId.toString();
    }
}
