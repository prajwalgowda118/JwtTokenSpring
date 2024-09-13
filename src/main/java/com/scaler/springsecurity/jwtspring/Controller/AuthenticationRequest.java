package com.scaler.springsecurity.jwtspring.Controller;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {


    private String email;
    private String password;

}
