package com.im.study.api;

import com.im.study.global.config.security.jwt.dto.JWTResponseDTO;
import com.im.study.global.config.security.token.TokenReissueService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class TokenController {

    private final TokenReissueService tokenReissueService;

    public TokenController(TokenReissueService tokenReissueService) {
        this.tokenReissueService = tokenReissueService;
    }

    // refreshToken 재발급
    @PostMapping(value = "/refresh", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JWTResponseDTO> reissueTokenApi(@RequestHeader("Refresh-Token") String refreshToken) {
        JWTResponseDTO response = tokenReissueService.reissue(refreshToken);

        return ResponseEntity.ok(response);
    }
}
