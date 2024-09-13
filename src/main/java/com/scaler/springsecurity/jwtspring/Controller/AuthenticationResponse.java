package com.scaler.springsecurity.jwtspring.Controller;


import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class AuthenticationResponse {

    private String token;

}
