package com.im.study.global.config;

import com.im.study.domain.jwt.repository.RefreshRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
public class ScheduleConfig {
    private final RefreshRepository refreshRepository;

    public ScheduleConfig(RefreshRepository refreshRepository) {
        this.refreshRepository = refreshRepository;
    }

    @Scheduled(cron = "0 0 6 * * *") // 매일 새벽 6시
    public void refreshEntityTtlSchedule() {
        Instant cutoff = Instant.now().minus(8, ChronoUnit.DAYS); // 저장소에 있는 refreshToken 은 8일이 지나면 삭제
        refreshRepository.deleteByCreatedDateBefore(cutoff);
    }
}
