package com.example.springSecurity.config.login.handler;

import com.example.springSecurity.config.auth.PrincipalDetails;
import com.example.springSecurity.config.jwt.JwtTokenProvider;
import com.example.springSecurity.model.User;
import com.example.springSecurity.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;
import java.time.Duration;

@RequiredArgsConstructor
@Slf4j
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private static final Duration ACCESS_DURATION = Duration.ofMinutes(30);
    private static final Duration REFRESH_DURATION = Duration.ofDays(7);
    private final JwtTokenProvider jwtTokenProvider;

    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException{
        User user = userRepository.findByUsername(getUsername(authentication));
        String accessToken = jwtTokenProvider.createToken(user, ACCESS_DURATION);
        String refreshToken = jwtTokenProvider.createToken(user, REFRESH_DURATION);

        jwtTokenProvider.sendAccessAndRefreshToken(response, accessToken, refreshToken);

        user.updateRefreshToken(refreshToken);
        userRepository.saveAndFlush(user);

        log.info("로그인 성공한 유저: " + user.getUsername());
        log.info("AccessToken: " + accessToken);
        log.info("refreshToken: " + refreshToken);
    }

    public String getUsername(Authentication authentication){
        PrincipalDetails  principalDetails = (PrincipalDetails) authentication.getPrincipal();
        return principalDetails.getUsername();
    }
}
