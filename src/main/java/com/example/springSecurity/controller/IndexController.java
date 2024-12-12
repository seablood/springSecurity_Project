package com.example.springSecurity.controller;

import com.example.springSecurity.config.auth.PrincipalDetails;
import com.example.springSecurity.dto.CreateUserDTO;
import com.example.springSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@Controller
@RequiredArgsConstructor
@Slf4j
public class IndexController {
    private final UserService userService;

    @GetMapping({"", "/"})
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(Authentication authentication, @AuthenticationPrincipal PrincipalDetails principal){
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info(principal.getUser().toString());
        log.info(principalDetails.getUser().toString());
        return "user";
    }

    @GetMapping("/userPage")
    public @ResponseBody String userPage(@AuthenticationPrincipal PrincipalDetails principal){
        log.info(principal.getUser().toString());
        return "userPage";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(CreateUserDTO dto){
        userService.save(dto);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }
}
