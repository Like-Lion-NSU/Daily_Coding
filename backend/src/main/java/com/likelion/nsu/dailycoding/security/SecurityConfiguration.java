package com.likelion.nsu.dailycoding.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration{
    private final JwtTokenProvider jwtTokenProvider;
    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception{
        http.csrf(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .sessionManagement(sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(authorizeRequest ->
                authorizeRequest.requestMatchers("/", "/users", "/users/login").permitAll()
                                .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                                .requestMatchers("/users/exception").permitAll()
                                .requestMatchers("**exception**").permitAll()
                                .anyRequest().authenticated()
            );

            /*
            * 나중에 예외처리 추가
            * .exceptionHandling(handler -> {
            *   handler.accessDeniedHandler(new CustomAccessDeniedHandler());
            *   handler.authenticationEntryPoint(new CustomAuthenticationEntryPoint());
            * });
            * */

        http.addFilter(corsConfig.corsFilter())
            .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}