package com.scaler.springsecurity.jwtspring.Service;


import com.scaler.springsecurity.jwtspring.Config.JwtService;
import com.scaler.springsecurity.jwtspring.Controller.AuthenticationRequest;
import com.scaler.springsecurity.jwtspring.Controller.AuthenticationResponse;
import com.scaler.springsecurity.jwtspring.Controller.RegisterRequest;
import com.scaler.springsecurity.jwtspring.Model.Role;
import com.scaler.springsecurity.jwtspring.Model.User;
import com.scaler.springsecurity.jwtspring.Repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
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

        return new AuthenticationResponse(jwtToken);

    }

    public AuthenticationResponse authenticateUser(AuthenticationRequest req) {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword()));


        var user =userRepository.findByEmail(req.getEmail()).orElseThrow(null);

        return new AuthenticationResponse(jwtService.generateToken(user));

    }
}
