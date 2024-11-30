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

@RequiredArgsConstructor
@Slf4j
public class TokenFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    private final UserRepository userRepository;

    private final PrincipalDetailsService principalDetailsService;

    private static final String NOT_CHECK_URL = "/login"; // /login으로 들어오는 요청은 필터링 예외

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getRequestURI().equals(NOT_CHECK_URL)){
            filterChain.doFilter(request, response);
            return; // 이후 현재 필터의 진행을 튕김
        }

        String refreshToken = jwtTokenProvider.resolveRefreshToken(request);

        if(refreshToken == null){
            checkAccessTokenAndAuthentication(request, response, filterChain);
        }
    }

    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{
        String accessToken = jwtTokenProvider.resolveAccessToken(request);

        if(accessToken != null && jwtTokenProvider.validateToken(accessToken)){
            User user = userRepository.findByUsername(jwtTokenProvider.getUsername(accessToken));
            saveAuthentication(user, accessToken);
        }

        filterChain.doFilter(request, response);
    }

    public void saveAuthentication(User user, String token){
        UserDetails userDetails = principalDetailsService.loadUserByUsername(user.getUsername());
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}