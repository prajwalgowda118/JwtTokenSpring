package com.scaler.springsecurity.jwtspring.Config;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service

public class JwtService {

    private static final String secret = "8xVkr8tq9uKl6vq1ESuMAL//vdQ16iOZIaN8LbA4eM1JxPLHtX5NP6+XhN1pZm8z";
    @Value(("${application.security.jwt.expiration}"))
    private long jwtExpiration;

    @Value(("${application.security.jwt.refresh-token.expiration}"))
    private long refreshExpiration;

    public String extractUserName(String token) {

        return extractClaims(token, Claims::getSubject);

    }
    public Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public String generateToken(UserDetails userDetails) {
       return generateToken(new HashMap<>(), userDetails);
    }

    private String buildToken(Map<String, Object> claims, UserDetails userDetails, long jwtExpiration) {

        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+jwtExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public String generateToken(Map<String, Object> claims
                                ,UserDetails userDetails
                                 )
    {
        return buildToken(claims, userDetails,jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails
    )
    {
        return buildToken(new HashMap<>(), userDetails,refreshExpiration);
    }


    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());

    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {

        final Claims claims=extractAllClaims(token);
        return claimsResolver.apply(claims);

    }
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()  // Use parser() for older versions
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {

        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }


}
