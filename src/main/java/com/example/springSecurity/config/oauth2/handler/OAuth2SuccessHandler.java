package com.example.springSecurity.config.oauth2.handler;

import com.example.springSecurity.config.auth.PrincipalDetails;
import com.example.springSecurity.config.jwt.JwtTokenProvider;
import com.example.springSecurity.model.User;
import com.example.springSecurity.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;

@RequiredArgsConstructor
@Component
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private static final Duration ACCESS_DURATION = Duration.ofMinutes(30);

    private static final Duration REFRESH_DURATION = Duration.ofDays(7);

    private final JwtTokenProvider jwtTokenProvider;

    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        User user = userRepository.findByUsername(getUsername(authentication));
        String accessToken = jwtTokenProvider.createToken(user, ACCESS_DURATION);
        String refreshToken = jwtTokenProvider.createToken(user, REFRESH_DURATION);

        jwtTokenProvider.sendAccessAndRefreshToken(response, accessToken, refreshToken);

        user.updateRefreshToken(refreshToken);
        userRepository.saveAndFlush(user);

        response.sendRedirect("/"); // 인덱스 페이지로 리다이렉트

        log.info("로그인 성공한 유저: " + user.getUsername());
        log.info("AccessToken: " + accessToken);
        log.info("refreshToken: " + refreshToken);
    }

    public String getUsername(Authentication authentication){
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        return principalDetails.getUsername();
    }
}
