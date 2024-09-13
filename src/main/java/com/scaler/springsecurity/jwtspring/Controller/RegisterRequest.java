package com.scaler.springsecurity.jwtspring.Controller;


import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class RegisterRequest {

    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
