package com.im.study.global.config.security.token;

import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenBlacklistRepository extends CrudRepository<RefreshTokenBlacklist, String> {
}
