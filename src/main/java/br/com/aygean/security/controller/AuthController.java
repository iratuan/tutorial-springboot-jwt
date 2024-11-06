package br.com.aygean.security.controller;


import br.com.aygean.security.dto.AuthRequest;
import br.com.aygean.security.repository.UserRepository;
import br.com.aygean.security.service.AuthService;
import org.springframework.security.core.Authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AuthController {
    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("authenticate")
    public String authenticate(
            @RequestBody AuthRequest authRequest) {
        System.out.println(authRequest);
        return authService.authenticate(authRequest);
    }
}