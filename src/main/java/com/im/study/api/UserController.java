package com.im.study.api;

import com.im.study.domain.user.dto.UserRequestDTO;
import com.im.study.domain.user.dto.UserResponseDTO;
import com.im.study.domain.user.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping(value = "/user", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Long>> createUserApi(@Validated(UserRequestDTO.addGroup.class) @RequestBody UserRequestDTO dto) {
        Long id = userService.addUser(dto);
        Map<String, Long> responseBody = Collections.singletonMap("userEntityId", id);

        return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
    }

    @PostMapping(value = "/user/exist", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Boolean> existUserApi(@Validated(UserRequestDTO.existGroup.class) @RequestBody UserRequestDTO dto) {
        return ResponseEntity.ok(userService.existUser(dto));
    }

    @GetMapping(value = "/user", consumes = MediaType.APPLICATION_JSON_VALUE)
    public UserResponseDTO userCheckAPI() {
        return userService.readUser();
    }

    @PatchMapping(value = "/user", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Long> updateUserApi(@Validated(UserRequestDTO.updateGroup.class) @RequestBody UserRequestDTO dto) throws AccessDeniedException {
        return ResponseEntity.status(HttpStatus.OK).body(userService.updateUser(dto));
    }

    @DeleteMapping(value = "/user", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Boolean> deleteUserApi(@Validated(UserRequestDTO.deleteGroup.class) @RequestBody UserRequestDTO dto) throws AccessDeniedException {
        userService.deleteUser(dto);

        return ResponseEntity.status(HttpStatus.OK).body(true);
    }
}
