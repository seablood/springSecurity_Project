package com.example.springSecurity.config.oauth2.provider;

// Provider에 따라 다른 형태의 유저 데이터를 추출하기 위한 인터페이스
public interface OAuth2UserInfo {
    String getProviderId();
    String getName();
    String getEmail();
    String getProvider();
}
