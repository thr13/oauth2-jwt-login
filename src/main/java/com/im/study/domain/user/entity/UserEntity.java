package com.im.study.domain.user.entity;

import com.im.study.domain.user.dto.UserRequestDTO;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

@Getter
@Table(name = "user_user_entity")
@Entity
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(access = AccessLevel.PRIVATE)
public class UserEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", unique = true, nullable = false, updatable = false)
    private String username;

    @Column(name= "password", nullable = false)
    private String password;

    @Column(name= "is_lock", nullable = false)
    private Boolean isLock; // 활성화 여부

    @Column(name = "is_social", nullable = false)
    private Boolean isSocial; // 소셜 계정 여부

    @Enumerated(EnumType.STRING)
    @Column(name = "social_provider_type")
    private SocialProviderType socialProviderType; // 소셜 제공자(예: 구글, 네이버, 카카오 등)

    @Enumerated(EnumType.STRING)
    @Column(name = "role_type", nullable = false)
    private UserRoleType roleType;

    @Column(name = "nickname")
    private String nickname;

    @Column(name = "email")
    private String email;

    @CreatedDate
    @Column(name = "created_date", updatable = false)
    private Instant createdDate; // 계정 생성일

    @LastModifiedDate
    @Column(name = "updated_date")
    private Instant updateDate; // 계정 수정일

    public static UserEntity loginUser(String username, String password, UserRoleType roleType, Boolean isSocial) {
        return UserEntity.builder()
                .username(username)
                .password(password)
                .roleType(roleType)
                .isSocial(isSocial)
                .build();
    }

    public static UserEntity createLocalUser(String username, String password, UserRoleType roleType, String nickname, String email) {
        return UserEntity.builder()
                .username(username)
                .password(password)
                .roleType(roleType)
                .isLock(false)
                .isSocial(false)
                .nickname(nickname)
                .email(email)
                .build();
    }

    public static UserEntity createSocialUser(String username, String email, SocialProviderType providerType, UserRoleType roleType) {
        return UserEntity.builder()
                .username(username)
                .email(email)
                .roleType(roleType)
                .isLock(false)
                .isSocial(true)
                .socialProviderType(providerType)
                .build();
    }

    public void updateUser(UserRequestDTO dto) {
        this.email = dto.getEmail();
        this.nickname = dto.getNickname();
    }
}
