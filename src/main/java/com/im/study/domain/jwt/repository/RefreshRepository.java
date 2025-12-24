package com.im.study.domain.jwt.repository;

import com.im.study.domain.jwt.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {

    Boolean existsByRefresh(String refresh);

    void deleteByRefresh(String refresh);

    void deleteByCreatedDateBefore(Instant createdDateBefore);
}
