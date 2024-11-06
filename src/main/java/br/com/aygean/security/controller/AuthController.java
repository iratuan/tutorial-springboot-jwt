package br.com.aygean.security.controller;


import br.com.aygean.security.dto.AuthRequest;
import br.com.aygean.security.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }


    @PostMapping("authenticate")
    public String authenticate(
            @RequestBody AuthRequest authRequest) {
        return authService.authenticate(authRequest);
    }
}