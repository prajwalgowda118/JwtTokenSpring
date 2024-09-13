package com.scaler.springsecurity.jwtspring.Repository;

import com.scaler.springsecurity.jwtspring.Model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    Optional<Token> findByToken(String token);

    Optional<Token> findByTokenAndUserId(String token, Long userId);

    @Query("""
    SELECT t FROM Token t WHERE t.user.id = :userId
""")
     List<Token> findAllValidTokensByUserId(@Param("userId") Integer userId);
}
