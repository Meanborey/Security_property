package com.example.security_property.user.web;

import com.example.security_property.user.TokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user")
public class UserController {
    private final TokenService tokenService;
    public UserController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/home")
    public String homepage(){


        return "Welcome to the homepage";
    }

    @PostMapping("/token")
    public String getToken(Authentication authentication){

        return tokenService.generateToken(authentication);
    }

}
