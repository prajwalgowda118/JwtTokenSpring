package com.scaler.springsecurity.jwtspring.Service;


import com.scaler.springsecurity.jwtspring.Config.JwtService;
import com.scaler.springsecurity.jwtspring.Controller.AuthenticationRequest;
import com.scaler.springsecurity.jwtspring.Controller.AuthenticationResponse;
import com.scaler.springsecurity.jwtspring.Controller.RegisterRequest;
import com.scaler.springsecurity.jwtspring.Model.Role;
import com.scaler.springsecurity.jwtspring.Model.Token;
import com.scaler.springsecurity.jwtspring.Model.TokenType;
import com.scaler.springsecurity.jwtspring.Model.User;
import com.scaler.springsecurity.jwtspring.Repository.TokenRepository;
import com.scaler.springsecurity.jwtspring.Repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    private final TokenRepository tokenRepository;

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager, TokenRepository tokenRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.tokenRepository = tokenRepository;
    }

    public AuthenticationResponse registerUser(RegisterRequest req) {

        var user = User.builder()
                .firstName(req.getFirstName())
                .lastName(req.getLastName())
                .email(req.getEmail())
                .password(passwordEncoder.encode(req.getPassword()))
                .role(Role.ROLE_USER)
                .build();
       userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);

        extractedToken(jwtToken, user);

        return new AuthenticationResponse(jwtToken);

    }

    private void extractedToken(String jwtToken, User user) {
        var token = Token.builder()
                .token(jwtToken)
                .user(user)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();

        tokenRepository.save(token);
    }

    public AuthenticationResponse authenticateUser(AuthenticationRequest req) {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword()));


        var user =userRepository.findByEmail(req.getEmail()).orElseThrow(null);

        var jwtToken = jwtService.generateToken(user);
        revokeToken(user);
        extractedToken(jwtToken, user);
        return new AuthenticationResponse(jwtToken);

        //return new AuthenticationResponse(jwtService.generateToken(user));

    }
    private void revokeToken(User user) {

        var validUserTokens=  tokenRepository.findAllValidTokensByUserId(user.getId());

        if(validUserTokens.isEmpty()){
            return;
        }
        if(validUserTokens.size()>0){
            validUserTokens.forEach(token -> {
                token.setRevoked(true);
                token.setExpired(true);
            });
        }
        tokenRepository.saveAll(validUserTokens);
    }

}
