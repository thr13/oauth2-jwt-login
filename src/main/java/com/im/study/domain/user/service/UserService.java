package com.im.study.domain.user.service;

import com.im.study.domain.jwt.service.JwtService;
import com.im.study.domain.user.dto.CustomOAuth2User;
import com.im.study.domain.user.dto.UserRequestDTO;
import com.im.study.domain.user.dto.UserResponseDTO;
import com.im.study.domain.user.entity.SocialProviderType;
import com.im.study.domain.user.entity.UserEntity;
import com.im.study.domain.user.entity.UserRoleType;
import com.im.study.domain.user.exception.UserAlreadyExistsException;
import com.im.study.domain.user.repository.UserRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
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
import java.util.Optional;

@Service
public class UserService extends DefaultOAuth2UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    // 일반 로그인 유저 생성
    @Transactional
    public Long addUser(UserRequestDTO dto) {
        if (userRepository.existsByUsername(dto.getUsername())) {
            throw new UserAlreadyExistsException("이미 유저가 존재합니다.");
        }

        UserEntity localUser = UserEntity.createLocalUser(
                dto.getUsername(),
                passwordEncoder.encode(dto.getPassword()),
                UserRoleType.USER,
                dto.getNickname(),
                dto.getEmail()
        );

        return userRepository.save(localUser).getId();
    }

    // 회원의 이메일, 닉네임 정보 수정
    @Transactional
    public Long updateUser(UserRequestDTO dto) throws AccessDeniedException {

        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        if (!username.equals(dto.getUsername())) {
            throw new AccessDeniedException("자신의 계정 정보만 수정할 수 있습니다.");
        }

        UserEntity user = userRepository.findByUsernameAndIsLockAndIsSocial(dto.getUsername(), false, false)
                .orElseThrow(() -> new UsernameNotFoundException(dto.getUsername()));

        user.updateUser(dto);

        return userRepository.save(user).getId();
    }

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

    @Transactional(readOnly = true)
    public Boolean existUser(UserRequestDTO dto) {
        return userRepository.existsByUsername(dto.getUsername());
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest); // 부모 메소드 호출

        Map<String, Object> attributes;
        List<GrantedAuthority> authorities;
        String username;
        String role = UserRoleType.USER.name();
        String email;
        String nickname;

        String registrationId = userRequest.getClientRegistration()
                .getRegistrationId()
                .toUpperCase();

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

        Optional<UserEntity> user = userRepository.findByUsernameAndIsSocial(username, true);
        if (user.isPresent()) { // 기존 유저
            role = user.get().getRoleType().name();

            UserRequestDTO dto = new UserRequestDTO();
            dto.setNickname(nickname);
            dto.setEmail(email);
            user.get().updateUser(dto);

            userRepository.save(user.get());
        } else { // 신규 유저
            UserEntity newUser = UserEntity.createSocialUser(
                    username,
                    email,
                    SocialProviderType.valueOf(registrationId),
                    UserRoleType.USER);

            userRepository.save(newUser);
        }

        authorities = List.of(new SimpleGrantedAuthority(role));

        return new CustomOAuth2User(attributes, authorities, username);
    }

    @Transactional
    public void deleteUser(UserRequestDTO dto) throws AccessDeniedException {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        String username = securityContext.getAuthentication().getName();
        String role = securityContext.getAuthentication().getAuthorities().iterator().next().getAuthority();

        boolean isOwner = username.equals(dto.getUsername());
        boolean isAdmin = role.equals("ROLE_" + UserRoleType.ADMIN.name());

        if (!isOwner && !isAdmin) {
            throw new AccessDeniedException("관리자 또는 계정 소유자만 삭제할 수 있습니다.");
        }

        userRepository.deleteByUsername(dto.getUsername());
        jwtService.removeRefresh(dto.getUsername());
    }

    @Transactional(readOnly = true)
    public UserResponseDTO readUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        UserEntity entity = userRepository.findByUsernameAndIsLock(username, false)
                .orElseThrow(() -> new UsernameNotFoundException(username + "을(를) 찾을 수 없습니다."));

        return new UserResponseDTO(username, entity.getIsSocial(), entity.getNickname(), entity.getEmail());
    }
}

