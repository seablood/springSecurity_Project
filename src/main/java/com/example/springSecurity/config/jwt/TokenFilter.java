package com.example.springSecurity.config.jwt;

import com.example.springSecurity.config.auth.PrincipalDetailsService;
import com.example.springSecurity.model.User;
import com.example.springSecurity.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

@RequiredArgsConstructor
@Slf4j
public class TokenFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    private final UserRepository userRepository;

    private final PrincipalDetailsService principalDetailsService;

    private static final String NOT_CHECK_URL = "/login"; // /login으로 들어오는 요청은 필터링 예외

    // 인증이나 권한이 필요한 주소 요청을 받음
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getRequestURI().equals(NOT_CHECK_URL)){
            log.info("일반 로그인 요청");
            filterChain.doFilter(request, response);
            return; // 이후 현재 필터의 진행을 튕김
        }

        String refreshToken = jwtTokenProvider.resolveRefreshToken(request);

        if(refreshToken != null && jwtTokenProvider.validateToken(refreshToken)){
            log.info("Access 토큰 재발급");
            checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            return; // 이후 현재 필터의 진행을 튕김
        }

        if(refreshToken == null){
            log.info("유저 인증 절차 진행");
            checkAccessTokenAndAuthentication(request, response, filterChain);
        }
    }

    // AccessToken을 이용해 인증 절차 수행
    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{
        String accessToken = jwtTokenProvider.resolveAccessToken(request);

        if(accessToken != null && jwtTokenProvider.validateToken(accessToken)){
            User user = userRepository.findByUsername(jwtTokenProvider.getUsername(accessToken));
            saveAuthentication(user, accessToken); // ContextHolder에 인증 객체 저장
        }

        filterChain.doFilter(request, response); // 다음 필터로 진행
    }

    public void saveAuthentication(User user, String token){
        UserDetails userDetails = principalDetailsService.loadUserByUsername(user.getUsername());
        // Authentication 객체 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());

        // 시큐리티 세션에 접근 후 ContextHolder에 인증 객체 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    // AccessToken 및 RefreshToken 재발급
    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken){
        userRepository.findByRefreshToken(refreshToken)
                .ifPresent(user -> {
                    String reIssueRefreshToken = reIssueRefreshToken(user);
                    jwtTokenProvider.sendAccessAndRefreshToken(response,
                            jwtTokenProvider.createToken(user, Duration.ofMinutes(30)), reIssueRefreshToken);
                });
    }

    // RefreshToken 재발급 및 저장
    public String reIssueRefreshToken(User user){
        String refreshToken = jwtTokenProvider.createToken(user, Duration.ofDays(7));
        user.updateRefreshToken(refreshToken);
        userRepository.saveAndFlush(user);

        return refreshToken;
    }
}
