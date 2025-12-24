package com.im.study.domain.user.dto;

import lombok.Getter;

@Getter
public class UserResponseDTO {
    private final String username;
    private final Boolean social;
    private final String nickname;
    private final String email;

    public UserResponseDTO(String username, Boolean social, String nickname, String email) {
        this.username = username;
        this.social = social;
        this.nickname = nickname;
        this.email = email;
    }
}
