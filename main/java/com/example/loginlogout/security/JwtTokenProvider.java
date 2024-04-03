package com.example.loginlogout.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component
public class JwtTokenProvider {
    private Key key;

    private final UserDetailsService userDetailsService;

    @PostConstruct
    protected void init() {
        key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    // JWT Token 생성
    public String createToken(String userPk, Collection<? extends GrantedAuthority> authorities) {
        // JWT payload에 저장되는 정보
        Claims claims = Jwts.claims().setSubject(userPk); // 이 경우에는 email
        claims.put("roles", authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())); // 이 유저의 권한을 담고
        Date now = new Date();
        // token 유효 시간 : 60분
        long tokenValidTime = 60 * 60 * 1000L;
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now) // 토큰 발행 시간 정보 : 왜냐하면 토큰이 언제 발행되었는지 알아야 하기 때문
                .setExpiration(new Date(now.getTime() + tokenValidTime)) // 유효 시간 설정
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // JWT Token에서 인증 정보 조회
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // JWT Token에서 사용자 토큰 추출
    private String getUserPk(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // Request의 Header에서 token 파싱 : "Authorization : Token 값"
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    // Token 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(jwtToken);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}