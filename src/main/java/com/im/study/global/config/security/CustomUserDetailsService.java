package com.im.study.global.config.security;

import com.im.study.domain.user.entity.UserEntity;
import com.im.study.domain.user.repository.UserRepository;
import com.im.study.global.config.CustomUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // formLogin 에서 사용할 유저 서비스
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsernameAndIsSocial(username, false)
                .orElseThrow(() -> new UsernameNotFoundException("찾을 수 없는 사용자 입니다: " + username));

        return new CustomUser(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getRoleType()
        );
    }
}
