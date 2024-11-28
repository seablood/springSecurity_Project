package com.example.springSecurity.config.oauth2.provider;

import lombok.AllArgsConstructor;

import java.util.Map;

@AllArgsConstructor
public class FacebookUserInfo implements OAuth2UserInfo{
    private Map<String, Object> attributes;

    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getProvider() {
        return "facebook";
    }
}
