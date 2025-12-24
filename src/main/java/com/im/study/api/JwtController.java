package com.im.study.api;

import com.im.study.domain.jwt.dto.JWTResponseDTO;
import com.im.study.domain.jwt.dto.RefreshRequestDTO;
import com.im.study.domain.jwt.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {
    private final JwtService jwtService;

    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping(value = "/jwt/exchange", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JWTResponseDTO jwtExchangeApi(HttpServletRequest request, HttpServletResponse response) {
        return jwtService.cookie2Header(request, response);
    }

    @PostMapping(value = "/jwt/refresh", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JWTResponseDTO jwtRefreshApi(@Validated @RequestBody RefreshRequestDTO dto) {
        return jwtService.refreshRotate(dto);
    }
}
