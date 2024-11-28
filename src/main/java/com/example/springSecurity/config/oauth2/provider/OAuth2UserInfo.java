package com.example.springSecurity.config.oauth2.provider;

public interface OAuth2UserInfo {
    String getProviderId();
    String getName();
    String getEmail();
    String getProvider();
}
