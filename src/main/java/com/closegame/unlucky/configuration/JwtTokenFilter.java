package com.closegame.unlucky.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 1. Извлекаем токен из заголовка
        String token = resolveToken(request);

        // 2. Проверяем валидность токена
        if (token != null && jwtTokenProvider.validateToken(token)) {

            // 3. Извлекаем имя пользователя из токена
            String username = jwtTokenProvider.getUsername(token);

            // 4. Проверяем, что пользователь еще не аутентифицирован
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // 5. Загружаем информацию о пользователе из UserDetailsService
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 6. Проверяем, что токен действительно принадлежит пользователю
                if (userDetails != null) {
                    // 7. Создаем объект аутентификации
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    // 8. Устанавливаем дополнительные детали аутентификации
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // 9. Устанавливаем аутентификацию в контексте безопасности
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }

        // Продолжаем выполнение цепочки фильтров
        filterChain.doFilter(request, response);
    }

    // Метод для извлечения токена из заголовка Authorization
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}