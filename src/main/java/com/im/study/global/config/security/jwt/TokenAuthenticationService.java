package com.im.study.global.config.security.jwt;

import org.springframework.security.core.Authentication;

public interface TokenAuthenticationService {

    Authentication authenticate(String token);

}
