package com.im.study.global.config.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.im.study.global.config.security.dto.AuthErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Qualifier("SocialFailureHandler")
@Component
public class SocialFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;

    public SocialFailureHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");

        AuthErrorResponse body = new AuthErrorResponse(
                "OAUTH2_LOGIN_FAILED",
                exception.getMessage() != null ? exception.getMessage() : "Social login failed"
        );

        objectMapper.writeValue(response.getWriter(), body);
    }
}
