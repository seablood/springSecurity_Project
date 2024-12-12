package com.example.springSecurity.config.jwt;

import com.example.springSecurity.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Date;

@Service
@RequiredArgsConstructor
@Getter
@Slf4j
public class JwtTokenProvider {
    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    private final static String TOKEN_PREFIX = "Bearer ";

    // AccessToken 및 RefreshToken 생성
    public String createToken(User user, Duration tokenValidTerm) {
        Date now = new Date();

        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setSubject(user.getUsername())
                .setIssuer(issuer)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + tokenValidTerm.toMillis()))
                .claim("id", user.getId())
                .claim("email", user.getEmail())
                .claim("username", user.getUsername())
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }


    // Token을 response 해더에 추가
    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken){
        response.setStatus(HttpServletResponse.SC_OK);

        response.setHeader(accessHeader, accessToken);
        response.setHeader(refreshHeader, refreshToken);
        log.info("Access Token, Refresh Token 헤더 설정 완료");
    }

    // AccessToken 추출
    public String resolveAccessToken(HttpServletRequest request){
        String authorizationToken = request.getHeader(accessHeader);
        if(authorizationToken != null && authorizationToken.startsWith(TOKEN_PREFIX)){
            return authorizationToken.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

    // RefreshToken 추출
    public String resolveRefreshToken(HttpServletRequest request){
        String authorizationToken = request.getHeader(refreshHeader);
        if(authorizationToken != null && authorizationToken.startsWith(TOKEN_PREFIX)){
            return authorizationToken.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

    // 해당 토큰의 정보(Claim) 추출
    public Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    public String getUsername(String token) {
        return getClaims(token).get("username", String.class);
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            return !getClaims(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}
