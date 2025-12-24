package com.im.study.domain.user.repository;

import com.im.study.domain.user.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Boolean existsByUsername(String username);

    Optional<UserEntity> findByUsernameAndIsSocial(String username, Boolean isSocial); // 인증용

    Optional<UserEntity> findByUsernameAndIsLock(String username, Boolean isLock);

    Optional<UserEntity> findByUsernameAndIsLockAndIsSocial(String username, Boolean isLock, Boolean isSocial);

    void deleteByUsername(String username);
}
