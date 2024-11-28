package com.example.springSecurity.config.auth;

import com.example.springSecurity.model.User;
import com.example.springSecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    // 함수 종료 시 @AuthenticationPrincipal 생성
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // 로그인 시도 시 자동으로 호출
        User user = userRepository.findByUsername(username);
        if(!(user == null)) return new PrincipalDetails(user);
        return null;
    }
}
