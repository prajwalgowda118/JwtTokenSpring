package com.scaler.springsecurity.jwtspring;

import com.scaler.springsecurity.jwtspring.Controller.RegisterRequest;
import com.scaler.springsecurity.jwtspring.Model.Role;
import com.scaler.springsecurity.jwtspring.Service.AuthenticationService;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class JwtSpringApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtSpringApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(AuthenticationService authenticationService) {


        return args -> {
            var admin = RegisterRequest.builder()
                    .firstName("Admin")
                    .lastName("Admin")
                    .email("admin@admin.com")
                    .password("password")
                    .role(Role.ADMIN)
                    .build();
            System.out.println("Admin tokem "+ authenticationService.registerUser(admin).getAccessToken());

            var admin1 = RegisterRequest.builder()
                    .firstName("Admin")
                    .lastName("Admin")
                    .email("manager@admin.com")
                    .password("password")
                    .role(Role.MANAGER)
                    .build();
            System.out.println("Admin tokem "+ authenticationService.registerUser(admin1).getAccessToken());

        };

    }

}
