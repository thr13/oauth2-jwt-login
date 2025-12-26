package com.im.study.global.config.security.token;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@RedisHash(value = "refreshTokenBlacklist", timeToLive = 60 * 60 * 24 * 7) // 유효기간 7일
public class RefreshTokenBlacklist {
    @Id
    private String token;
}
