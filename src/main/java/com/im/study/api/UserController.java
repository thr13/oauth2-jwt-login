package com.im.study.api;

import com.im.study.domain.user.dto.UserRequestDTO;
import com.im.study.domain.user.dto.UserResponseDTO;
import com.im.study.domain.user.service.UserService;
import com.im.study.global.util.SecurityUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // 회원가입
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Long>> createUserApi(@Validated(UserRequestDTO.addGroup.class) @RequestBody UserRequestDTO dto) {
        Long id = userService.registerLocal(dto);

        return ResponseEntity.status(HttpStatus.CREATED).body(Collections.singletonMap("userId", id));
    }

    // 회원 중복 확인
    @PostMapping(value = "/exist", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Boolean> existUserApi(@Validated(UserRequestDTO.existGroup.class) @RequestBody UserRequestDTO dto) {
        return ResponseEntity.ok(userService.existUser(dto));
    }

    // 내 정보 조회
    @GetMapping(value = "/me")
    public ResponseEntity<UserResponseDTO> readMeApi() {
        Long userId = SecurityUtils.getUserId();

        return ResponseEntity.ok(userService.readUser(userId));
    }

    // 회원 정보 수정
    @PatchMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Long> updateUserApi(@Validated(UserRequestDTO.updateGroup.class) @RequestBody UserRequestDTO dto) throws AccessDeniedException {
        return ResponseEntity.ok(userService.updateUser(dto));
    }

    // 회원 탈퇴
    @DeleteMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Boolean> deleteUserApi(@Validated(UserRequestDTO.deleteGroup.class) @RequestBody UserRequestDTO dto) throws AccessDeniedException {
        userService.deleteUser(dto);

        return ResponseEntity.noContent().build();
    }
}
