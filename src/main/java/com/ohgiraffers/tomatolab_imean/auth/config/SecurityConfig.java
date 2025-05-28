package com.ohgiraffers.tomatolab_imean.auth.config;

import com.ohgiraffers.tomatolab_imean.auth.config.handler.JwtAccessDeniedHandler;
import com.ohgiraffers.tomatolab_imean.auth.config.handler.JwtAuthenticationEntryPoint;
import com.ohgiraffers.tomatolab_imean.auth.jwt.JwtAuthenticationFilter;
import com.ohgiraffers.tomatolab_imean.members.model.common.MemberRole;
import org.springframework.context.annotation.Lazy;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.HiddenHttpMethodFilter;

import java.util.Arrays;

/**
 * JWT 기반 Spring Security 설정
 * 세션을 사용하지 않는 Stateless 인증 방식으로 구성
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    
    // JWT 관련 컴포넌트들 주입 (순환 참조 방지를 위해 @Lazy 사용)
    public SecurityConfig(
            @Lazy JwtAuthenticationFilter jwtAuthenticationFilter,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }
    
    /**
     * HTTP 메서드 오버라이드 필터
     * HTML 폼에서 PUT, DELETE 등의 메서드 사용 가능하게 함
     */
    @Bean
    public HiddenHttpMethodFilter hiddenHttpMethodFilter() {
        return new HiddenHttpMethodFilter();
    }
    
    /**
     * 비밀번호 암호화 인코더
     * BCrypt 알고리즘 사용
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 인증 매니저
     * 로그인 시 사용자 인증 처리
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
    
    /**
     * 정적 자원에 대한 보안 설정 제외
     * CSS, JS, 이미지 등은 인증 없이 접근 가능
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .requestMatchers("/css/**", "/js/**", "/images/**", "/fonts/**", "/webjars/**", "/favicon.ico");
        // 이 경로들은 인증하지 않아도 된다고 표시
    }
    
    /**
     * CORS 설정
     * 프론트엔드(Next.js)와의 통신을 위한 CORS 허용
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // 허용할 Origin (프론트엔드 주소)
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",    // Next.js 개발 서버
                "http://localhost:3001",    // 추가 개발 서버 (필요시)
                "https://your-frontend-domain.com"  // 프로덕션 도메인 (나중에 수정)
        ));
        
        // 허용할 HTTP 메서드
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));
        
        // 허용할 헤더 (JWT 토큰을 위한 Authorization 헤더 포함)
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin"
        ));
        
        // 자격 증명(쿠키, 인증 헤더 등) 허용
        configuration.setAllowCredentials(true);
        
        // 모든 경로에 CORS 설정 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    /**
     * 메인 보안 설정
     * JWT 기반 인증 및 권한 부여 설정
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // CORS 설정 적용
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // 요청 권한 설정
            .authorizeHttpRequests(auth -> {
                // === 공개 접근 허용 경로 ===
                
                // 회원 관련 공개 API
                auth.requestMatchers("/api/member/login").permitAll();           // 로그인
                auth.requestMatchers("/api/member/register").permitAll();        // 원스텝 회원가입
                auth.requestMatchers("/api/member/check-email").permitAll();     // 이메일 중복 체크

                // JWT 토큰 관련 공개 API
                auth.requestMatchers("/api/auth/refresh").permitAll();           // 토큰 갱신
                
                // 공개 API (인증 없이 접근 가능)
                auth.requestMatchers("/api/public/**").permitAll();
                
                // CORS preflight 요청 허용
                auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
                
                // 메인 페이지 등 (필요시)
                auth.requestMatchers("/", "/index.html").permitAll();
                
                // === 인증 필요 - 싱글 사용자도 접근 가능 ===
                
                // 프로필 관련 (로그인한 모든 사용자)
                auth.requestMatchers("/api/member/profile").authenticated();
                auth.requestMatchers("/api/member/verify-password").authenticated();
                auth.requestMatchers(HttpMethod.PUT, "/api/member/profile").authenticated();
                
                // 커플 상태 확인 (로그인한 모든 사용자)
                auth.requestMatchers("/api/couple/status").authenticated();
                
                // 커플 등록 (싱글 사용자만 - 비즈니스 로직에서 추가 검증)
                auth.requestMatchers("/api/couple/register").hasAuthority("COUPLE_SINGLE");
                
                // === 커플 관계 필요 ===
                
                // 커플 정보 조회 (커플인 사용자만)
                auth.requestMatchers("/api/couple/info").hasAuthority("COUPLE_COUPLED");
                
                // 커플 해제 (커플인 사용자만)
                auth.requestMatchers(HttpMethod.DELETE, "/api/couple/break").hasAuthority("COUPLE_COUPLED");
                
                // 향후 채팅 관련 API (파이썬에서 구현하더라도 보안 정책 정의)
                auth.requestMatchers("/api/chat/**").hasAuthority("COUPLE_COUPLED");
                
                // === 관리자 권한 ===
                
                // 일반 관리자 권한
                auth.requestMatchers("/api/admin/members/**").hasAnyAuthority("ROLE_GENERAL_ADMIN", "ROLE_SUPER_ADMIN");
                
                // 최고 관리자 권한
                auth.requestMatchers("/api/admin/system/**").hasAuthority("ROLE_SUPER_ADMIN");
                auth.requestMatchers("/admin/**").hasAuthority("ROLE_SUPER_ADMIN");
                
                // === 기타 모든 요청은 인증 필요 ===
                auth.anyRequest().authenticated();
            })
            
            // === JWT 예외 처리 핸들러 설정 ===
            .exceptionHandling(exception -> {
                exception.authenticationEntryPoint(jwtAuthenticationEntryPoint);  // 401 처리
                exception.accessDeniedHandler(jwtAccessDeniedHandler);           // 403 처리
            })
            
            // === 세션 정책: Stateless ===
            .sessionManagement(session -> {
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            })
            
            // === JWT 인증 필터 추가 ===
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            
            // === 불필요한 인증 방식 비활성화 ===
            .httpBasic(httpBasic -> httpBasic.disable())    // HTTP Basic 인증 비활성화
            .formLogin(formLogin -> formLogin.disable())    // 폼 로그인 비활성화
            .logout(logout -> logout.disable())            // 기본 로그아웃 비활성화 (JWT는 클라이언트에서 토큰 삭제)
            
            // === CSRF 비활성화 ===
            // JWT는 CSRF 공격에 대해 자체적으로 보호되므로 CSRF 토큰 불필요
            .csrf(csrf -> csrf.disable());
        
        return http.build();
    }
}