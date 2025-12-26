package com.im.study.domain.user.service;

import com.im.study.domain.user.dto.UserRequestDTO;
import com.im.study.domain.user.dto.UserResponseDTO;
import com.im.study.domain.user.entity.SocialProviderType;
import com.im.study.domain.user.entity.UserEntity;
import com.im.study.domain.user.entity.UserRoleType;
import com.im.study.domain.user.exception.UserAlreadyExistsException;
import com.im.study.domain.user.repository.UserRepository;
import com.im.study.global.config.security.oauth2.CustomOAuth2User;
import com.im.study.global.config.security.token.TokenLogoutService;
import com.im.study.global.util.SecurityUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
public class UserService extends DefaultOAuth2UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final TokenLogoutService tokenLogoutService;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, TokenLogoutService tokenLogoutService, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.tokenLogoutService = tokenLogoutService;
        this.passwordEncoder = passwordEncoder;
    }

    // 일반 회원 가입
    @Transactional
    public Long registerLocal(UserRequestDTO dto) {
        if (userRepository.existsByUsername(dto.getUsername())) {
            throw new UserAlreadyExistsException("Already user exists");
        }

        UserEntity newUser = UserEntity.createLocalUser(
                dto.getUsername(),
                passwordEncoder.encode(dto.getPassword()),
                UserRoleType.USER,
                dto.getNickname(),
                dto.getEmail()
        );

        return userRepository.save(newUser).getId();
    }

    // 회원 정보 수정(이메일, 닉네임)
    @Transactional
    public Long updateUser(UserRequestDTO dto) throws AccessDeniedException {
        Long userId = SecurityUtils.getUserId();

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("Not found user: " + userId));

        if (!user.getUsername().equals(dto.getUsername())) {
            throw new AccessDeniedException("You can only modify your own account");
        }

        // todo: db에 즉시 반영할려면 더티 체킹 방식에서 직접 update 문을 사용하도록 변경 필요
        user.updateUser(dto);

        return user.getId();
    }

    // 일반 로그인
    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity user = userRepository.findByUsernameAndIsSocial(username, false)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        return (UserDetails) UserEntity.loginUser(
                user.getUsername(),
                user.getPassword(),
                user.getRoleType(),
                user.getIsSocial()
        );
    }

    // DB 에 회원 존재 여부
    @Transactional(readOnly = true)
    public Boolean existUser(UserRequestDTO dto) {
        return userRepository.existsByUsername(dto.getUsername());
    }

    // oauth2 로그인
    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        Map<String, Object> attributes;
        String username;
        String email;
        String nickname;

        String registrationId = userRequest.getClientRegistration()
                .getRegistrationId()
                .toUpperCase();

        // todo: 서비스별 가져오는 데이터가 다르므로 추상화 필요
        if (registrationId.equals(SocialProviderType.NAVER.name())) {
            attributes = (Map<String, Object>) oAuth2User.getAttributes().get("response");
            username = registrationId + "_" + attributes.get("id");
            email = attributes.get("email").toString();
            nickname = attributes.get("nickname").toString();
        } else if (registrationId.equals(SocialProviderType.GOOGLE.name())) {
            attributes = (Map<String, Object>) oAuth2User.getAttributes();
            username = registrationId + "_" + attributes.get("sub");
            email = attributes.get("email").toString();
            nickname = attributes.get("nickname").toString();
        } else {
            throw new OAuth2AuthenticationException("Unsupported social login");
        }

        UserEntity socialUser = userRepository.findByUsernameAndIsSocial(username, true)
                .map(dbUser -> {
                    UserRequestDTO dto = new UserRequestDTO();
                    dto.setEmail(email);
                    dto.setNickname(nickname);
                    dbUser.updateUser(dto);
                    return dbUser;
                }).orElseGet(() -> userRepository.save(
                        UserEntity.createSocialUser(
                                username,
                                email,
                                SocialProviderType.valueOf(registrationId),
                                UserRoleType.USER
                        )));

        String role = UserRoleType.USER.name();
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        return new CustomOAuth2User(
                socialUser.getId(),
                role,
                attributes,
                authorities
        );
    }

    // 회원 탈퇴
    @Transactional
    public void deleteUser(UserRequestDTO dto) throws AccessDeniedException {

        Long userId = SecurityUtils.getUserId();
        String role = SecurityUtils.getRole();

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + userId));

        boolean isOwner = user.getUsername().equals(dto.getUsername());
        boolean isAdmin = role.equals(UserRoleType.ADMIN.name());

        if (!isOwner && !isAdmin) {
            throw new AccessDeniedException("관리자 또는 계정 소유자만 삭제할 수 있습니다.");
        }

        tokenLogoutService.logoutByUserId(userId);
        userRepository.delete(user);
    }

    // 회원 조회
    @Transactional(readOnly = true)
    public UserResponseDTO readUser(Long userId) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + userId));

        return new UserResponseDTO(
                user.getUsername(),
                user.getIsSocial(),
                user.getNickname(),
                user.getEmail()
        );
    }
}

