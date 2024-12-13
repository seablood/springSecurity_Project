package com.example.springSecurity.dto;

import com.example.springSecurity.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ResponseUserDTO {
    private String username;
    private String email;

    public static ResponseUserDTO toDto(User user){
        return new ResponseUserDTO(user.getUsername(), user.getEmail());
    }
}
