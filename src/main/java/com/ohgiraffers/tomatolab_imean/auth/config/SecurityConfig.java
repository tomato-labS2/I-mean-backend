package com.ohgiraffers.tomatolab_imean.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.HiddenHttpMethodFilter;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public HiddenHttpMethodFilter hiddenHttpMethodFilter() {
        return new HiddenHttpMethodFilter();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .requestMatchers("/css/**", "/js/**", "/images/**", "/fonts/**", "/webjars/**");
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000")); // Next.js 개발 서버 주소
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain config(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> {
                // 공개 API 엔드포인트
                auth.requestMatchers("/api/members/login", "/api/members/register").permitAll();
                // 다단계 회원가입 경로 허용
                auth.requestMatchers("/api/members/register/step1").permitAll();
                auth.requestMatchers("/api/members/register/step2").permitAll();
                auth.requestMatchers("/api/members/register/step3").permitAll();
                auth.requestMatchers("/api/members/register/step4").permitAll();
                auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll(); // CORS preflight 요청 허용
                
                // 인증이 필요한 API 엔드포인트
                auth.requestMatchers("/api/**").authenticated();
                
                // 기타 모든 요청은 인증 필요
                auth.anyRequest().authenticated();
            })
            .httpBasic(basic -> {
                // HTTP Basic 인증 활성화 (API 인증용)
            })
            .sessionManagement(session -> {
                // 세션 생성 정책 변경: 항상 세션 생성
                session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
            })
            .logout(logout -> {
                logout.logoutRequestMatcher(new AntPathRequestMatcher("/api/logout"));
                logout.deleteCookies("JSESSIONID");
                logout.invalidateHttpSession(true);
                logout.logoutSuccessHandler((request, response, authentication) -> {
                    response.setStatus(200);
                });
            })
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}