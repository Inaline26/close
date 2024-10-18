package com.closegame.unlucky.configuration;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    // Ключ для подписи JWT
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    // Метод для создания JWT токена
    public String createToken(String username, Set<GrantedAuthority> authorities) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        // Преобразуем список ролей в строку
        String authoritiesString = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject(username) // Устанавливаем имя пользователя как subject токена
                .claim("roles", authoritiesString) // Добавляем роли в токен
                .setIssuedAt(now) // Устанавливаем дату создания токена
                .setExpiration(expiryDate) // Устанавливаем срок действия токена
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Подписываем токен секретным ключом
                .compact();
    }

    // Метод для валидации токена
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey()) // Устанавливаем ключ для проверки подписи
                    .build()
                    .parseClaimsJws(token); // Парсим и проверяем токен
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // Здесь можно логировать ошибку или выбросить кастомное исключение
            return false;
        }
    }

    // Метод для получения имени пользователя из токена
    public String getUsername(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject(); // Возвращаем subject, который мы установили как username
    }

    // Метод для получения ролей (авторизаций) из токена
    public Set<GrantedAuthority> getAuthorities(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        String roles = claims.get("roles", String.class); // Получаем строку с ролями
        return Arrays.stream(roles.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet()); // Преобразуем строку в Set<GrantedAuthority>
    }
}
