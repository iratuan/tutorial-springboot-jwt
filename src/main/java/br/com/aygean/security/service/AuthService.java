package br.com.aygean.security.service;

import br.com.aygean.security.dto.AuthRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthService(JwtService jwtService, AuthenticationManager authenticationManager) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public String authenticate(AuthRequest authRequest) {
        // Cria um objeto Authentication a partir do AuthRequest
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authRequest.username(),
                authRequest.password()
        );

        // Autentica o usuário
        Authentication authenticatedUser = authenticationManager.authenticate(authentication);

        // Gera o token para o usuário autenticado
        return jwtService.generateToken(authenticatedUser);
    }
}
