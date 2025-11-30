package com.example.springjwt.service;

import com.example.springjwt.dto.TokenPair;
import com.example.springjwt.entity.RefreshEntity;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public TokenPair reissueTokens(String refreshToken) {

        try{
            jwtUtil.isExpired(refreshToken);
        }catch(ExpiredJwtException ex){
            throw new IllegalArgumentException("refresh token expired");
        }

        String category = jwtUtil.getCategory(refreshToken);
        if(!category.equals("refresh")){
            throw new IllegalArgumentException("invalid refresh token");
        }

        Boolean isExist = refreshRepository.existsByRefresh(refreshToken);
        if(!isExist){
            throw new IllegalArgumentException("invalid refresh token");
        }

        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        String newAccess  = jwtUtil.createJwt("access",  username, role,  10 * 60 * 1000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400 * 1000L);

        refreshRepository.deleteByUsername(username);
        addRefreshEntity(username, newRefresh, 86400000L);

        return new TokenPair(newAccess, newRefresh);
    }

    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = RefreshEntity.builder()
                .username(username)
                .refresh(refresh)
                .expiration(date.toString())
                .build();

        refreshRepository.save(refreshEntity);
    }

}
