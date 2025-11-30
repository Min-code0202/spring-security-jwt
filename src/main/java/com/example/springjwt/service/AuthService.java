package com.example.springjwt.service;

import com.example.springjwt.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JWTUtil jwtUtil;

    public String reissueAccessToken(String refreshToken) {

        // refresh 토큰 만료 확인
        try{
            jwtUtil.isExpired(refreshToken);
        }catch(ExpiredJwtException ex){
            throw new IllegalArgumentException("refresh token expired");
        }

        String category = jwtUtil.getCategory(refreshToken);

        if(!category.equals("refresh")){
            throw new IllegalArgumentException("invalid refresh token");
        }

        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        String newAccess = jwtUtil.createJwt("access", username, role, 60 * 10 * 1000L);

        return newAccess;
    }
}
