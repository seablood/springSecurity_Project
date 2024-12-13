package com.example.springSecurity.controller;

import com.example.springSecurity.config.auth.PrincipalDetails;
import com.example.springSecurity.dto.ResponseUserDTO;
import com.example.springSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1")
public class RestApiController {
    private final UserService userService;

    @GetMapping("/user")
    public ResponseEntity<ResponseUserDTO> findById(@AuthenticationPrincipal PrincipalDetails principal){
        ResponseUserDTO dto = userService.findById(principal.getUser().getId());
        return ResponseEntity.status(HttpStatus.OK).body(dto);
    }
}
